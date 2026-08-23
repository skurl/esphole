#pragma once

/* Brings up station mode and blocks until the first IP is acquired.
   After that, reconnects on its own with exponential backoff (capped 30s). */
void wifi_start_and_wait(void);
