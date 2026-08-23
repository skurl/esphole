#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#define OV_MAX       32
#define OV_NAME_MAX  64

/* User overrides held in NVS, editable from the dashboard and consulted on every
   query. The blocklist partition is immutable, so this is the only way to undo a
   bad block without rebuilding and reflashing the blob. */
void overrides_init(void);

/* Both match a domain or any subdomain of it: "example.com" covers
   "a.b.example.com". Checked before the blocklist. */
bool overrides_allowed(const char *name);
bool overrides_rewrite(const char *name, uint32_t *ip_be);

esp_err_t overrides_allow_add(const char *domain);
esp_err_t overrides_allow_del(const char *domain);
esp_err_t overrides_rw_add(const char *domain, const char *ip);
esp_err_t overrides_rw_del(const char *domain);
esp_err_t overrides_clear(void);

/* Appends {"allow":[...],"rewrite":[...]} . Returns bytes written. */
int overrides_json(char *out, size_t max);
