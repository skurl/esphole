#include "http_server.h"
#include "stats.h"
#include "blocklist.h"
#include "overrides.h"
#include "wifi.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lwip/inet.h"

static const char *TAG = "http";

extern const uint8_t dashboard_html_start[] asm("_binary_dashboard_html_start");
extern const uint8_t dashboard_html_end[]   asm("_binary_dashboard_html_end");
extern const uint8_t provision_html_start[] asm("_binary_provision_html_start");
extern const uint8_t provision_html_end[]   asm("_binary_provision_html_end");

#define JSON_MAX  16384
#define BODY_MAX  512
#define CHUNK     4096      /* one flash sector per write */

/* snprintf returns the length it wanted, not what it wrote, so a naive
   JSON_MAX - n goes negative once the buffer is full and wraps to a huge
   size_t. This keeps every write bounded; a payload that outgrows the buffer
   is cut, never overrun. */
#define LEFT(n) ((n) < JSON_MAX ? (size_t)(JSON_MAX - (n)) : 0)

/* DNS labels may hold any octet — the fuzzer proved it by putting a BEL in a
   name that then landed in the stats. Escape quote, backslash and anything
   outside printable ASCII so the dashboard can always parse what we send. */
static int json_str(char *out, size_t max, const char *s)
{
    int n = 0;
    for (; *s && n + 7 < (int)max; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')          n += snprintf(out + n, max - n, "\\%c", c);
        else if (c < 0x20 || c > 0x7E)       n += snprintf(out + n, max - n, "\\u%04x", c);
        else                                 out[n++] = (char)c;
    }
    out[n] = '\0';
    return n;
}
#define ESC_MAX (STATS_NAME_MAX * 6 + 1)

/* ---- request body helpers -------------------------------------------------
   Everything is form-encoded in a POST body rather than a query string:
   credentials must not end up in URLs, which get logged and cached. */

static int read_body(httpd_req_t *req, char *buf, size_t max)
{
    if (req->content_len == 0 || req->content_len >= max) return -1;
    int got = httpd_req_recv(req, buf, req->content_len);
    if (got <= 0) return -1;
    buf[got] = '\0';
    return got;
}

static void urldecode(char *s)
{
    char *o = s;
    for (char *i = s; *i; i++) {
        if (*i == '+') {
            *o++ = ' ';
        } else if (*i == '%' && i[1] && i[2]) {
            char h[3] = { i[1], i[2], 0 };
            *o++ = (char)strtol(h, NULL, 16);
            i += 2;
        } else {
            *o++ = *i;
        }
    }
    *o = '\0';
}

/* Extracts `key` from a form-encoded body into out. */
static bool field(const char *body, const char *key, char *out, size_t max)
{
    size_t klen = strlen(key);
    for (const char *p = body; p && *p; ) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *end = strchr(v, '&');
            size_t len = end ? (size_t)(end - v) : strlen(v);
            if (len >= max) return false;
            memcpy(out, v, len);
            out[len] = '\0';
            urldecode(out);
            return out[0] != '\0';
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return false;
}

static esp_err_t reply_err(httpd_req_t *req, esp_err_t e)
{
    if (e == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":true}");
    }
    const char *msg = e == ESP_ERR_NO_MEM        ? "list full"
                    : e == ESP_ERR_INVALID_ARG   ? "invalid input"
                    : e == ESP_ERR_INVALID_SIZE  ? "wrong size for this partition"
                    : e == ESP_ERR_NOT_FOUND     ? "not found"
                                                 : "failed";
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    char b[96];
    snprintf(b, sizeof(b), "{\"ok\":false,\"error\":\"%s\"}", msg);
    return httpd_resp_sendstr(req, b);
}

/* ---- handlers ------------------------------------------------------------ */

static esp_err_t page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    if (wifi_is_provisioning())
        return httpd_resp_send(req, (const char *)provision_html_start,
                               provision_html_end - provision_html_start - 1);
    return httpd_resp_send(req, (const char *)dashboard_html_start,
                           dashboard_html_end - dashboard_html_start - 1);
}

#define SL(n, left) ((n) < (int)(left) ? (left) - (n) : 0)

static int append_top(char *p, size_t left, const stats_entry_t *t)
{
    int n = 0, first = 1;
    char e[ESC_MAX];
    n += snprintf(p + n, SL(n, left), "[");
    for (int i = 0; i < STATS_TOP_N; i++) {
        if (t[i].count == 0) continue;
        json_str(e, sizeof(e), t[i].name);
        n += snprintf(p + n, SL(n, left), "%s{\"n\":\"%s\",\"c\":%lu}",
                      first ? "" : ",", e, (unsigned long)t[i].count);
        first = 0;
    }
    n += snprintf(p + n, SL(n, left), "]");
    return n;
}

static esp_err_t stats_get(httpd_req_t *req)
{
    /* Both are far too big for the httpd task stack. */
    stats_snapshot_t *s = malloc(sizeof(*s));
    char *json = malloc(JSON_MAX);
    if (!s || !json) {
        free(s); free(json);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_FAIL;
    }
    stats_snapshot(s);

    int n = snprintf(json, JSON_MAX,
        "{\"queries\":%lu,\"blocked\":%lu,\"forwarded\":%lu,"
        "\"upstream_fail\":%lu,\"dropped\":%lu,\"uptime_s\":%lu,"
        "\"free_heap\":%lu,\"min_free_heap\":%lu,"
        "\"list_count\":%lu,\"list_ready\":%s,\"upstream\":\"%s\","
        "\"ip\":\"%s\",\"hour_index\":%lu,",
        (unsigned long)s->queries, (unsigned long)s->blocked,
        (unsigned long)s->forwarded, (unsigned long)s->upstream_fail,
        (unsigned long)s->dropped, (unsigned long)s->uptime_s,
        (unsigned long)s->free_heap, (unsigned long)s->min_free_heap,
        (unsigned long)blocklist_count(), blocklist_ready() ? "true" : "false",
        wifi_upstream_dns(), wifi_ip_str(), (unsigned long)s->hour_index);

    n += snprintf(json + n, LEFT(n), "\"hourly_q\":[");
    for (int i = 0; i < STATS_HOURS; i++)
        n += snprintf(json + n, LEFT(n), "%s%lu", i ? "," : "",
                      (unsigned long)s->hourly_q[i]);
    n += snprintf(json + n, LEFT(n), "],\"hourly_b\":[");
    for (int i = 0; i < STATS_HOURS; i++)
        n += snprintf(json + n, LEFT(n), "%s%lu", i ? "," : "",
                      (unsigned long)s->hourly_b[i]);
    n += snprintf(json + n, LEFT(n), "],\"top_blocked\":");
    n += append_top(json + n, LEFT(n), s->top_blocked);
    n += snprintf(json + n, LEFT(n), ",\"top_queried\":");
    n += append_top(json + n, LEFT(n), s->top_queried);

    /* Newest first: walk backwards from the ring head. */
    n += snprintf(json + n, LEFT(n), ",\"recent\":[");
    int first = 1;
    char e[ESC_MAX];
    for (int i = 1; i <= STATS_RECENT; i++) {
        const stats_recent_t *r =
            &s->recent[(s->recent_head + STATS_RECENT - i) % STATS_RECENT];
        if (r->name[0] == '\0') continue;
        json_str(e, sizeof(e), r->name);
        n += snprintf(json + n, LEFT(n), "%s{\"n\":\"%s\",\"v\":%u,\"a\":%lu}",
                      first ? "" : ",", e, r->verdict,
                      (unsigned long)(s->uptime_s - r->at_s));
        first = 0;
    }
    n += snprintf(json + n, LEFT(n), "],");
    n += overrides_json(json + n, LEFT(n));
    n += snprintf(json + n, LEFT(n), "}");
    if (n > JSON_MAX - 1) n = JSON_MAX - 1;   /* truncated, never overrun */

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, n);
    free(s);
    free(json);
    return err;
}

static esp_err_t allow_post(httpd_req_t *req)
{
    char body[BODY_MAX], d[OV_NAME_MAX];
    if (read_body(req, body, sizeof(body)) < 0 || !field(body, "d", d, sizeof(d)))
        return reply_err(req, ESP_ERR_INVALID_ARG);
    bool remove = strstr(req->uri, "/del") != NULL;
    return reply_err(req, remove ? overrides_allow_del(d) : overrides_allow_add(d));
}

static esp_err_t rewrite_post(httpd_req_t *req)
{
    char body[BODY_MAX], d[OV_NAME_MAX], ip[20];
    if (read_body(req, body, sizeof(body)) < 0 || !field(body, "d", d, sizeof(d)))
        return reply_err(req, ESP_ERR_INVALID_ARG);
    if (strstr(req->uri, "/del")) return reply_err(req, overrides_rw_del(d));
    if (!field(body, "ip", ip, sizeof(ip)))
        return reply_err(req, ESP_ERR_INVALID_ARG);
    return reply_err(req, overrides_rw_add(d, ip));
}

/* Raw blocklist.bin as the POST body, streamed to flash a sector at a time.
   curl -X POST --data-binary @blocklist.bin http://<ip>/api/blocklist */
static esp_err_t blocklist_post(httpd_req_t *req)
{
    size_t total = req->content_len;
    if (total < 16) return reply_err(req, ESP_ERR_INVALID_SIZE);

    uint8_t *chunk = malloc(CHUNK);
    if (!chunk) return reply_err(req, ESP_ERR_NO_MEM);

    uint8_t hdr[16];
    uint32_t count = 0;
    esp_err_t err = ESP_OK;
    size_t off = 0;

    while (off < total) {
        int want = (int)((total - off < CHUNK) ? total - off : CHUNK);
        int got = 0;
        while (got < want) {
            int r = httpd_req_recv(req, (char *)chunk + got, want - got);
            if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
            if (r <= 0) { err = ESP_FAIL; goto done; }
            got += r;
        }
        if (off == 0) {
            /* Nothing is erased until the header proves this is a blocklist. */
            if (!blocklist_header_ok(chunk, total, &count)) {
                err = ESP_ERR_INVALID_ARG;
                goto done;
            }
            memcpy(hdr, chunk, 16);
            if ((err = blocklist_update_begin(total)) != ESP_OK) goto done;
            if (got > 16 && (err = blocklist_update_write(16, chunk + 16, got - 16)) != ESP_OK)
                goto done;
        } else if ((err = blocklist_update_write(off, chunk, got)) != ESP_OK) {
            goto done;
        }
        off += got;
    }
    err = blocklist_update_end(hdr);

done:
    free(chunk);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "blocklist update failed at %u/%u: %s",
                 (unsigned)off, (unsigned)total, esp_err_to_name(err));
        return reply_err(req, err);
    }
    ESP_LOGI(TAG, "blocklist updated: %lu hashes", (unsigned long)count);
    char b[64];
    snprintf(b, sizeof(b), "{\"ok\":true,\"count\":%lu}", (unsigned long)count);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, b);
}

static esp_err_t wifi_post(httpd_req_t *req)
{
    char body[BODY_MAX], ssid[33], pass[65];
    if (read_body(req, body, sizeof(body)) < 0 || !field(body, "ssid", ssid, sizeof(ssid)))
        return reply_err(req, ESP_ERR_INVALID_ARG);
    if (!field(body, "pass", pass, sizeof(pass))) pass[0] = '\0';   /* open network */

    esp_err_t err = wifi_save_credentials(ssid, pass);
    /* Wipe the plaintext before it can linger on the httpd stack. */
    memset(body, 0, sizeof(body));
    memset(pass, 0, sizeof(pass));
    if (err != ESP_OK) return reply_err(req, err);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true,\"msg\":\"saved, rebooting\"}");
    ESP_LOGI(TAG, "credentials saved, restarting");
    vTaskDelay(pdMS_TO_TICKS(600));       /* let the response flush */
    esp_restart();
    return ESP_OK;
}

void http_server_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 6144;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 10;
    cfg.recv_wait_timeout = 10;     /* a 400KB upload over marginal WiFi */
    /* Below the DNS tasks on purpose: name resolution must never wait on a
       browser refreshing a chart. */
    cfg.task_priority = 3;

    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed — dashboard unavailable");
        return;
    }

    static const httpd_uri_t routes[] = {
        { .uri = "/",                 .method = HTTP_GET,  .handler = page_get },
        { .uri = "/api/stats",        .method = HTTP_GET,  .handler = stats_get },
        { .uri = "/api/allow",        .method = HTTP_POST, .handler = allow_post },
        { .uri = "/api/allow/del",    .method = HTTP_POST, .handler = allow_post },
        { .uri = "/api/rewrite",      .method = HTTP_POST, .handler = rewrite_post },
        { .uri = "/api/rewrite/del",  .method = HTTP_POST, .handler = rewrite_post },
        { .uri = "/api/wifi",         .method = HTTP_POST, .handler = wifi_post },
        { .uri = "/api/blocklist",    .method = HTTP_POST, .handler = blocklist_post },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(*routes); i++)
        httpd_register_uri_handler(srv, &routes[i]);

    ESP_LOGI(TAG, "%s on :80", wifi_is_provisioning() ? "provisioning portal" : "dashboard");
}
