#pragma once

/* Binds 0.0.0.0:53 and starts a listener plus 4 worker tasks.
   Call after the network is up and blocklist_init() has run. */
void dns_server_start(void);
