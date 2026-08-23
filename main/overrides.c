#include "overrides.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "lwip/inet.h"
#include "esp_log.h"

static const char *TAG = "overrides";
#define NVS_NS "esphole"

typedef struct { char name[OV_NAME_MAX]; uint32_t ip_be; } entry_t;

static entry_t s_allow[OV_MAX];
static entry_t s_rw[OV_MAX];
static uint8_t s_n_allow, s_n_rw;
static SemaphoreHandle_t s_lock;

static void load(const char *key, entry_t *tbl, uint8_t *n)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t len = sizeof(entry_t) * OV_MAX;
    if (nvs_get_blob(h, key, tbl, &len) == ESP_OK) *n = len / sizeof(entry_t);
    nvs_close(h);
}

static esp_err_t save(const char *key, const entry_t *tbl, uint8_t n)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, tbl, sizeof(entry_t) * n);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

void overrides_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    load("allow", s_allow, &s_n_allow);
    load("rw", s_rw, &s_n_rw);
    ESP_LOGI(TAG, "%u allowlist, %u rewrite entries", s_n_allow, s_n_rw);
}

/* True when `name` is `suffix` or ends in ".suffix". */
static bool domain_matches(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);
    if (n == s) return memcmp(name, suffix, n) == 0;
    if (n > s) return name[n - s - 1] == '.' && memcmp(name + n - s, suffix, s) == 0;
    return false;
}

static bool lookup(const entry_t *tbl, uint8_t n, const char *name, uint32_t *ip_be)
{
    for (uint8_t i = 0; i < n; i++) {
        if (domain_matches(name, tbl[i].name)) {
            if (ip_be) *ip_be = tbl[i].ip_be;
            return true;
        }
    }
    return false;
}

bool overrides_allowed(const char *name)
{
    if (!s_n_allow) return false;               /* common case, skip the lock */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool hit = lookup(s_allow, s_n_allow, name, NULL);
    xSemaphoreGive(s_lock);
    return hit;
}

bool overrides_rewrite(const char *name, uint32_t *ip_be)
{
    if (!s_n_rw) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool hit = lookup(s_rw, s_n_rw, name, ip_be);
    xSemaphoreGive(s_lock);
    return hit;
}

/* Normalise as the DNS parser would: lowercase, no trailing dot. */
static bool clean(const char *in, char *out)
{
    size_t n = strlen(in);
    while (n && in[n - 1] == '.') n--;
    if (n == 0 || n >= OV_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'))
            return false;
        out[i] = c;
    }
    out[n] = '\0';
    return true;
}

static esp_err_t add(entry_t *tbl, uint8_t *n, const char *key,
                     const char *domain, uint32_t ip_be)
{
    char d[OV_NAME_MAX];
    if (!clean(domain, d)) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = -1;
    for (uint8_t i = 0; i < *n; i++) if (strcmp(tbl[i].name, d) == 0) { slot = i; break; }
    if (slot < 0) {
        if (*n >= OV_MAX) { xSemaphoreGive(s_lock); return ESP_ERR_NO_MEM; }
        slot = (*n)++;
    }
    strlcpy(tbl[slot].name, d, OV_NAME_MAX);
    tbl[slot].ip_be = ip_be;
    esp_err_t err = save(key, tbl, *n);
    xSemaphoreGive(s_lock);
    return err;
}

static esp_err_t del(entry_t *tbl, uint8_t *n, const char *key, const char *domain)
{
    char d[OV_NAME_MAX];
    if (!clean(domain, d)) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = ESP_ERR_NOT_FOUND;
    for (uint8_t i = 0; i < *n; i++) {
        if (strcmp(tbl[i].name, d) != 0) continue;
        tbl[i] = tbl[--(*n)];                   /* order does not matter here */
        err = save(key, tbl, *n);
        break;
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t overrides_allow_add(const char *d) { return add(s_allow, &s_n_allow, "allow", d, 0); }
esp_err_t overrides_allow_del(const char *d) { return del(s_allow, &s_n_allow, "allow", d); }
esp_err_t overrides_rw_del(const char *d)    { return del(s_rw, &s_n_rw, "rw", d); }

esp_err_t overrides_rw_add(const char *d, const char *ip)
{
    uint32_t be = ipaddr_addr(ip);
    if (be == IPADDR_NONE) return ESP_ERR_INVALID_ARG;
    return add(s_rw, &s_n_rw, "rw", d, be);
}

esp_err_t overrides_clear(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_n_allow = s_n_rw = 0;
    esp_err_t a = save("allow", s_allow, 0), b = save("rw", s_rw, 0);
    xSemaphoreGive(s_lock);
    return a != ESP_OK ? a : b;
}

int overrides_json(char *out, size_t max)
{
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    n += snprintf(out + n, max - n, "\"allow\":[");
    for (uint8_t i = 0; i < s_n_allow; i++)
        n += snprintf(out + n, max - n, "%s\"%s\"", i ? "," : "", s_allow[i].name);
    n += snprintf(out + n, max - n, "],\"rewrite\":[");
    for (uint8_t i = 0; i < s_n_rw; i++) {
        char ip[16];
        struct in_addr a = { .s_addr = s_rw[i].ip_be };
        inet_ntoa_r(a, ip, sizeof(ip));
        n += snprintf(out + n, max - n, "%s{\"n\":\"%s\",\"ip\":\"%s\"}",
                      i ? "," : "", s_rw[i].name, ip);
    }
    n += snprintf(out + n, max - n, "]");
    xSemaphoreGive(s_lock);
    return n;
}
