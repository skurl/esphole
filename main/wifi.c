#include "wifi.h"
#include "secrets.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "lwip/ip_addr.h"

static const char *TAG = "wifi";

#define GOT_IP_BIT      BIT0
#define BACKOFF_MIN_MS  1000
#define BACKOFF_MAX_MS  30000
#define NVS_NS          "esphole"

#ifndef UPSTREAM_DNS
#define UPSTREAM_DNS "94.140.14.14"
#endif
/* secrets.h may omit these entirely — provisioning covers that case. */
#ifndef WIFI_SSID
#define WIFI_SSID ""
#define WIFI_PASS ""
#endif
#ifndef SETUP_AP_SSID
#define SETUP_AP_SSID "esphole-setup"
#endif
#ifndef SETUP_AP_PASS
#define SETUP_AP_PASS "esphole-setup"
#endif

static EventGroupHandle_t s_events;
static esp_timer_handle_t s_retry_timer;
static uint32_t s_backoff_ms = BACKOFF_MIN_MS;
static bool     s_provisioning;
static char     s_ip[16] = "0.0.0.0";

bool        wifi_is_provisioning(void) { return s_provisioning; }
const char *wifi_ip_str(void)          { return s_ip; }
const char *wifi_upstream_dns(void)    { return UPSTREAM_DNS; }

esp_err_t wifi_save_credentials(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, "ssid", ssid);
    if (err == ESP_OK) err = nvs_set_str(h, "pass", pass);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static bool load_credentials(char *ssid, size_t ssid_len, char *pass, size_t pass_len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    bool ok = nvs_get_str(h, "ssid", ssid, &ssid_len) == ESP_OK && ssid[0];
    if (ok && nvs_get_str(h, "pass", pass, &pass_len) != ESP_OK) pass[0] = '\0';
    nvs_close(h);
    return ok;
}

static void retry_cb(void *arg) { esp_wifi_connect(); }

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_events, GOT_IP_BIT);
        ESP_LOGW(TAG, "disconnected, retrying in %lums", (unsigned long)s_backoff_ms);
        esp_timer_start_once(s_retry_timer, (uint64_t)s_backoff_ms * 1000);
        s_backoff_ms *= 2;
        if (s_backoff_ms > BACKOFF_MAX_MS) s_backoff_ms = BACKOFF_MAX_MS;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&e->ip_info.ip));
        ESP_LOGI(TAG, "got ip %s", s_ip);
        s_backoff_ms = BACKOFF_MIN_MS;
        xEventGroupSetBits(s_events, GOT_IP_BIT);
    }
}

/* No credentials anywhere: raise an open-ish setup AP so the user can enter
   them in a browser. dns_server runs in captive mode alongside this. */
static void start_provisioning(void)
{
    s_provisioning = true;
    esp_netif_create_default_wifi_ap();

    wifi_config_t ap = { 0 };
    strlcpy((char *)ap.ap.ssid, SETUP_AP_SSID, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, SETUP_AP_PASS, sizeof(ap.ap.password));
    ap.ap.ssid_len       = strlen(SETUP_AP_SSID);
    ap.ap.max_connection = 4;
    ap.ap.authmode       = strlen(SETUP_AP_PASS) >= 8 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    strlcpy(s_ip, "192.168.4.1", sizeof(s_ip));
    ESP_LOGW(TAG, "no credentials — setup AP '%s' up, open http://192.168.4.1/",
             SETUP_AP_SSID);
}

void wifi_start_and_wait(void)
{
    s_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        on_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        on_event, NULL, NULL));

    char ssid[33] = { 0 }, pass[65] = { 0 };
    if (load_credentials(ssid, sizeof(ssid), pass, sizeof(pass))) {
        ESP_LOGI(TAG, "using credentials from NVS");
    } else if (WIFI_SSID[0]) {
        strlcpy(ssid, WIFI_SSID, sizeof(ssid));
        strlcpy(pass, WIFI_PASS, sizeof(pass));
        ESP_LOGI(TAG, "using credentials from secrets.h");
    } else {
        start_provisioning();
        return;
    }

    /* Reconnect timer. Without this the disconnect handler has nothing to fire
       and the device never comes back from an AP outage. */
    const esp_timer_create_args_t targs = { .callback = retry_cb, .name = "wifi_retry" };
    ESP_ERROR_CHECK(esp_timer_create(&targs, &s_retry_timer));

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();

#ifdef STATIC_IP
    /* The router hands this address out as DNS, so it must not move. */
    ESP_ERROR_CHECK(esp_netif_dhcpc_stop(netif));
    esp_netif_ip_info_t ip = { 0 };
    ip.ip.addr      = ipaddr_addr(STATIC_IP);
    ip.gw.addr      = ipaddr_addr(STATIC_GATEWAY);
    ip.netmask.addr = ipaddr_addr(STATIC_NETMASK);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ip));

    /* Our own resolver points upstream, never at ourselves. */
    esp_netif_dns_info_t dns = { 0 };
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = ipaddr_addr(UPSTREAM_DNS);
    ESP_ERROR_CHECK(esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns));
#else
    (void)netif;
#endif

    wifi_config_t wc = { 0 };
    strlcpy((char *)wc.sta.ssid, ssid, sizeof(wc.sta.ssid));
    strlcpy((char *)wc.sta.password, pass, sizeof(wc.sta.password));
    memset(pass, 0, sizeof(pass));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));   /* latency over power here */
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(s_events, GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}
