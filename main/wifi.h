#pragma once
#include <stdbool.h>
#include "esp_err.h"

/* Station mode using credentials from NVS, falling back to secrets.h. If neither
   is available, raises a setup AP instead and returns immediately — check
   wifi_is_provisioning() before assuming there is an uplink. */
void wifi_start_and_wait(void);

bool        wifi_is_provisioning(void);
const char *wifi_ip_str(void);
const char *wifi_upstream_dns(void);

/* Stores credentials in NVS. The caller reboots. */
esp_err_t wifi_save_credentials(const char *ssid, const char *pass);
