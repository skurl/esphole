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
