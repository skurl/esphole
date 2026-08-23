#include "blocklist.h"
#include "dns_server.h"
#include "http_server.h"
#include "stats.h"
#include "wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

#ifdef SINKHOLE_HASH_SELFTEST
#include "hash_vectors.h"
#include <string.h>
#endif

static const char *TAG = "sinkhole";

#ifdef SINKHOLE_HASH_SELFTEST
/* Proves the on-device hash still matches the one the blob was built with.
   Build with: idf.py -DSINKHOLE_HASH_SELFTEST=1 build */
static void hash_selftest(void)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof(kHashVectors) / sizeof(*kHashVectors); i++) {
        uint32_t got = fnv1a(kHashVectors[i].domain, strlen(kHashVectors[i].domain));
        if (got != kHashVectors[i].hash) {
            ESP_LOGE(TAG, "hash mismatch for '%s': got %08lx want %08lx",
                     kHashVectors[i].domain, (unsigned long)got,
                     (unsigned long)kHashVectors[i].hash);
            bad++;
        }
    }
    ESP_LOGI(TAG, "hash selftest: %d/%d ok", (int)(sizeof(kHashVectors) / sizeof(*kHashVectors)) - bad,
             (int)(sizeof(kHashVectors) / sizeof(*kHashVectors)));
}
#endif

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

#ifdef SINKHOLE_HASH_SELFTEST
    hash_selftest();
#endif

    stats_init();
    blocklist_init();
    if (!blocklist_ready()) {
        ESP_LOGW(TAG, "no usable blocklist — running as a plain forwarder");
    }

    wifi_start_and_wait();
    dns_server_start();
    http_server_start();

    /* Nothing left for app_main to do; the tasks own the device from here. */
    vTaskDelete(NULL);
}
