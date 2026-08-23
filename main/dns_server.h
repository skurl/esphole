#pragma once

/* Binds 0.0.0.0:53 and starts a listener plus 4 worker tasks.
   Call after the network is up and blocklist_init() has run. */
void dns_server_start(void);

/* Captive mode: answer every A query with `ip` and ignore the blocklist
   entirely. Used only while the setup AP is up, so any domain a phone probes
   lands on the provisioning page. Call before dns_server_start(). */
void dns_server_set_captive(const char *ip);
