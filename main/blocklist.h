#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "fnv1a.h"

/* Maps the blocklist partition and validates its header.
   Fails open by design: a missing, short or corrupt blob leaves the device
   forwarding every query rather than taking the network down. */
void blocklist_init(void);

bool     blocklist_ready(void);
uint32_t blocklist_count(void);

/* domain: lowercase ASCII, NUL-terminated, no trailing dot; `len` excludes the NUL.
   Walks suffixes longest-first, so a hit on tracker.com blocks a.b.tracker.com. */
bool blocklist_blocked(const char *domain, size_t len);

/* Replacing the blob in place, over WiFi. Lookups fail open between begin and
   end. Validate the first 16 bytes with blocklist_header_ok() before begin —
   it refuses to erase a working list for something that is not a list.
   Write the body from offset 16; end() writes the header last, so an upload
   that dies halfway leaves an invalid magic and the device keeps failing open. */
#include "esp_err.h"
bool      blocklist_header_ok(const void *hdr16, size_t total_len, uint32_t *count);
esp_err_t blocklist_update_begin(size_t total_len);
esp_err_t blocklist_update_write(size_t off, const void *data, size_t len);
esp_err_t blocklist_update_end(const void *hdr16);
