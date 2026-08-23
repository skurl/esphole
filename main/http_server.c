#include "http_server.h"
#include "stats.h"
#include "blocklist.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "esp_http_server.h"
#include "esp_log.h"

static const char *TAG = "http";

extern const uint8_t dashboard_html_start[] asm("_binary_dashboard_html_start");
extern const uint8_t dashboard_html_end[]   asm("_binary_dashboard_html_end");

#define JSON_MAX 3072

static esp_err_t page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)dashboard_html_start,
                           dashboard_html_end - dashboard_html_start - 1);
}

static int append_top(char *p, size_t left, const stats_entry_t *t)
{
    int n = 0, first = 1;
    n += snprintf(p + n, left - n, "[");
    for (int i = 0; i < STATS_TOP_N; i++) {
        if (t[i].count == 0) continue;
        n += snprintf(p + n, left - n, "%s{\"n\":\"%s\",\"c\":%lu}",
                      first ? "" : ",", t[i].name, (unsigned long)t[i].count);
        first = 0;
    }
    n += snprintf(p + n, left - n, "]");
    return n;
}

static esp_err_t stats_get(httpd_req_t *req)
{
    /* Both of these are too big for the httpd task stack, so they go on the heap. */
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
        "\"list_count\":%lu,\"list_ready\":%s,\"hour_index\":%lu,",
        (unsigned long)s->queries, (unsigned long)s->blocked,
        (unsigned long)s->forwarded, (unsigned long)s->upstream_fail,
        (unsigned long)s->dropped, (unsigned long)s->uptime_s,
        (unsigned long)s->free_heap, (unsigned long)s->min_free_heap,
        (unsigned long)blocklist_count(), blocklist_ready() ? "true" : "false",
        (unsigned long)s->hour_index);

    n += snprintf(json + n, JSON_MAX - n, "\"hourly_q\":[");
    for (int i = 0; i < STATS_HOURS; i++)
        n += snprintf(json + n, JSON_MAX - n, "%s%lu", i ? "," : "",
                      (unsigned long)s->hourly_q[i]);
    n += snprintf(json + n, JSON_MAX - n, "],\"hourly_b\":[");
    for (int i = 0; i < STATS_HOURS; i++)
        n += snprintf(json + n, JSON_MAX - n, "%s%lu", i ? "," : "",
                      (unsigned long)s->hourly_b[i]);
    n += snprintf(json + n, JSON_MAX - n, "],\"top_blocked\":");
    n += append_top(json + n, JSON_MAX - n, s->top_blocked);
    n += snprintf(json + n, JSON_MAX - n, ",\"top_queried\":");
    n += append_top(json + n, JSON_MAX - n, s->top_queried);
    n += snprintf(json + n, JSON_MAX - n, "}");

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, n);
    free(s);
    free(json);
    return err;
}

void http_server_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 5120;
    cfg.lru_purge_enable = true;
    /* Below the DNS tasks on purpose: name resolution must never wait on a
       browser refreshing a chart. */
    cfg.task_priority = 3;

    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed — dashboard unavailable");
        return;
    }
    httpd_uri_t page  = { .uri = "/",           .method = HTTP_GET, .handler = page_get };
    httpd_uri_t stats = { .uri = "/api/stats",  .method = HTTP_GET, .handler = stats_get };
    httpd_register_uri_handler(srv, &page);
    httpd_register_uri_handler(srv, &stats);
    ESP_LOGI(TAG, "dashboard on :80");
}
