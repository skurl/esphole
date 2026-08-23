#include "dns_server.h"
#include "blocklist.h"
#include "overrides.h"
#include "stats.h"
#include "secrets.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lwip/ip_addr.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_system.h"

#ifndef UPSTREAM_DNS
#define UPSTREAM_DNS "1.1.1.1"
#endif

static const char *TAG = "dns";

#define DNS_PORT    53
#define MAX_PKT     512     /* plain DNS/UDP ceiling; EDNS0 is stripped anyway */
#define NWORKERS    4
#define QUEUE_LEN   16
#define UPSTREAM_TIMEOUT_S 2

typedef struct {
    struct sockaddr_storage from;
    socklen_t fromlen;
    int len;
    uint8_t buf[MAX_PKT];
} job_t;

static int          s_sock = -1;
static QueueHandle_t s_queue;
static uint32_t     s_captive_ip;       /* non-zero while the setup AP is up */

void dns_server_set_captive(const char *ip) { s_captive_ip = ipaddr_addr(ip); }

/* ---- parsing -------------------------------------------------------------
   Every read is bounds-checked against the datagram length. This is the only
   place a hostile packet touches us, so nothing is assumed about the input. */

static int parse_question(const uint8_t *p, int len, char *name, int namesz,
                          int *qend, uint16_t *qtype, uint16_t *qclass, int *namelen)
{
    if (len < 12) return -1;

    uint16_t flags = (uint16_t)(p[2] << 8 | p[3]);
    if (flags & 0x8000) return -1;              /* QR set: this is a response */
    if (((flags >> 11) & 0xF) != 0) return -1;  /* opcode != QUERY */
    if ((p[4] << 8 | p[5]) != 1) return -1;     /* QDCOUNT != 1 */

    int off = 12, n = 0;
    for (;;) {
        if (off >= len) return -1;
        uint8_t l = p[off++];
        if (l == 0) break;
        /* Top bits set means a compression pointer (0xC0) or a reserved form.
           Both are illegal in the question section, and pointers are the
           classic parser trap. Rejecting here also caps labels at 63. */
        if (l & 0xC0) return -1;
        if (off + l > len) return -1;
        if (n) {
            if (n + 1 >= namesz) return -1;
            name[n++] = '.';
        }
        if (n + l >= namesz) return -1;         /* keeps the 255-byte name cap */
        for (int i = 0; i < l; i++) {
            char c = (char)p[off + i];
            name[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        off += l;
    }
    name[n] = '\0';

    if (off + 4 > len) return -1;
    *qtype   = (uint16_t)(p[off]     << 8 | p[off + 1]);
    *qclass  = (uint16_t)(p[off + 2] << 8 | p[off + 3]);
    if (*qclass != 1) return -1;                /* not IN */
    *qend    = off + 4;
    *namelen = n;
    return 0;
}

/* Header + question copied verbatim from the query; counts rewritten.
   ARCOUNT=0 drops any EDNS0 OPT record rather than echoing it back. */
static int build_reply(const uint8_t *q, int qend, uint8_t *out, bool answer_a,
                       uint8_t rcode, uint32_t ip_be)
{
    memcpy(out, q, qend);
    out[2] = (uint8_t)(0x80 | (q[2] & 0x01));       /* QR=1, opcode 0, RD copied */
    out[3] = (uint8_t)(0x80 | (rcode & 0x0F));      /* RA=1 */
    out[6] = 0; out[7] = answer_a ? 1 : 0;          /* ANCOUNT */
    out[8] = 0; out[9] = 0;                         /* NSCOUNT */
    out[10] = 0; out[11] = 0;                       /* ARCOUNT */
    if (!answer_a) return qend;

    static const uint8_t a_rr[] = {
        0xC0, 0x0C,                 /* name -> offset 12 */
        0x00, 0x01, 0x00, 0x01,     /* type A, class IN */
        0x00, 0x00, 0x00, 0x3C,     /* TTL 60 */
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, /* rdlen 4, address patched below */
    };
    memcpy(out + qend, a_rr, sizeof(a_rr));
    memcpy(out + qend + 12, &ip_be, 4);     /* 0 for the sinkhole, else the rewrite */
    return qend + (int)sizeof(a_rr);
}

static void reply(const job_t *j, const uint8_t *buf, int n)
{
    sendto(s_sock, buf, n, 0, (const struct sockaddr *)&j->from, j->fromlen);
}

/* Fresh socket per query: no transaction-ID rewriting, and no chance of a late
   response from an earlier query landing on the next one. */
static void forward(const job_t *j, uint8_t *out, int qend)
{
    int us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (us >= 0) {
        struct timeval tv = { .tv_sec = UPSTREAM_TIMEOUT_S };
        setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in up = {
            .sin_family = AF_INET,
            .sin_port   = htons(53),
            .sin_addr   = { .s_addr = inet_addr(UPSTREAM_DNS) },
        };
        if (connect(us, (struct sockaddr *)&up, sizeof(up)) == 0 &&
            send(us, j->buf, j->len, 0) == j->len) {
            int n = recv(us, out, MAX_PKT, 0);
            if (n >= 12 && memcmp(out, j->buf, 2) == 0) {  /* ID must match */
                close(us);
                reply(j, out, n);
                stats_note_forwarded();
                return;
            }
        }
        close(us);
    }
    stats_note_upstream_fail();
    reply(j, out, build_reply(j->buf, qend, out, false, 2, 0));  /* SERVFAIL */
}

static void worker_task(void *arg)
{
    job_t j;
    char name[256];
    uint8_t out[MAX_PKT];

    for (;;) {
        xQueueReceive(s_queue, &j, portMAX_DELAY);

        int qend, namelen;
        uint16_t qtype, qclass;
        if (parse_question(j.buf, j.len, name, sizeof(name),
                           &qend, &qtype, &qclass, &namelen) != 0) {
            stats_note_drop();
            continue;
        }

        if (s_captive_ip) {                 /* provisioning: everything is us */
            stats_record(name, VERDICT_REWRITE);
            reply(&j, out, build_reply(j.buf, qend, out, qtype == 1, 0, s_captive_ip));
            continue;
        }

        /* Order matters: a rewrite is an explicit instruction, an allowlist
           entry is an explicit exemption, and only then does the blob apply. */
        uint32_t rw_ip;
        if (overrides_rewrite(name, &rw_ip)) {
            stats_record(name, VERDICT_REWRITE);
            reply(&j, out, build_reply(j.buf, qend, out, qtype == 1, 0, rw_ip));
            continue;
        }
        if (blocklist_blocked(name, namelen)) {
            if (overrides_allowed(name)) {
                stats_record(name, VERDICT_ALLOW);
                forward(&j, out, qend);
                continue;
            }
            stats_record(name, VERDICT_BLOCK);
            /* A -> 0.0.0.0; AAAA and everything else -> NODATA. */
            reply(&j, out, build_reply(j.buf, qend, out, qtype == 1, 0, 0));
            continue;
        }
        stats_record(name, VERDICT_FORWARD);
        forward(&j, out, qend);
    }
}

static void listener_task(void *arg)
{
    job_t j;
    for (;;) {
        j.fromlen = sizeof(j.from);
        int n = recvfrom(s_sock, j.buf, MAX_PKT, 0,
                         (struct sockaddr *)&j.from, &j.fromlen);
        if (n < 0) {                        /* socket error */
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        /* Counted before the zero-length check so the stats line balances:
           queries == blocked + forwarded + upstream_fail + dropped. */
        stats_note_query();
        if (n == 0) { stats_note_drop(); continue; }
        j.len = n;
        if (xQueueSend(s_queue, &j, 0) != pdTRUE) stats_note_drop();
    }
}

static void stats_task(void *arg)
{
    stats_snapshot_t *s = malloc(sizeof(*s));
    if (!s) vTaskDelete(NULL);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60000));
        stats_snapshot(s);
        ESP_LOGI(TAG, "q=%lu blocked=%lu fwd=%lu upfail=%lu dropped=%lu heap=%lu",
                 (unsigned long)s->queries, (unsigned long)s->blocked,
                 (unsigned long)s->forwarded, (unsigned long)s->upstream_fail,
                 (unsigned long)s->dropped, (unsigned long)s->free_heap);
    }
}

void dns_server_start(void)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_sock < 0) { ESP_LOGE(TAG, "socket() failed"); return; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
        .sin_addr   = { .s_addr = htonl(INADDR_ANY) },
    };
    if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "bind :53 failed");
        close(s_sock);
        s_sock = -1;
        return;
    }

    s_queue = xQueueCreate(QUEUE_LEN, sizeof(job_t));
    for (int i = 0; i < NWORKERS; i++) {
        xTaskCreate(worker_task, "dns_worker", 4096, NULL, 5, NULL);
    }
    xTaskCreate(listener_task, "dns_listen", 4096, NULL, 6, NULL);
    xTaskCreate(stats_task, "dns_stats", 3072, NULL, 1, NULL);

    ESP_LOGI(TAG, "listening on :53, upstream %s, %lu blocked hashes",
             UPSTREAM_DNS, (unsigned long)blocklist_count());
}
