# ESP32 DNS Sinkhole

Network-wide DNS ad-blocking on a bare **ESP32-WROOM-32D** — 4MB flash, 520KB SRAM,
**no PSRAM**.

Projects like `s60sc/ESP32_AdBlocker` keep the blocklist as strings in PSRAM. This
board has none, so the list lives as a **sorted array of 32-bit FNV-1a domain hashes
in its own 2.5MB flash partition**, memory-mapped and binary-searched. A ~250k-domain
list costs 1MB of flash and **zero heap**: ~18 probes per lookup, each a 4-byte read.

Target: **ESP-IDF v5.x**.

---

## Build and flash

```bash
cp main/secrets.h.example main/secrets.h   # then edit it
python3 tools/test_hash_parity.py          # regenerates main/hash_vectors.h
python3 tools/build_blocklist.py           # writes blocklist.bin
idf.py set-target esp32
idf.py build flash monitor
```

Then flash the blocklist blob to its partition (once per list update — the firmware
and the list are flashed independently):

```bash
esptool --chip esp32 --port /dev/cu.usbserial-310 write-flash 0x190000 blocklist.bin
```

`build_blocklist.py` prints that command with the right offset when it finishes.

That is esptool **5.x** syntax. ESP-IDF bundles its own esptool 4.x in its virtualenv,
so inside a shell where you have sourced `export.sh` the subcommand is `write_flash`
with an underscore. Both spellings work on 5.x; only the underscore works on 4.x.

### Blocklist options

```bash
python3 tools/build_blocklist.py --allowlist my-allowlist.txt
python3 tools/build_blocklist.py https://example.com/hosts.txt ./local-hosts
```

Default source is StevenBlack/hosts. The builder reports the hash-collision count and
the implied false-positive rate. At 250k entries a 32-bit hash collides ~7 times —
roughly a 1-in-17,000 chance that a given *non-blocked* domain false-positives into
the list. If a site breaks, add it to the allowlist and rebuild.

## Deploying on your network

**Network-wide, if your router allows it.** Set the ESP32's static IP as **DHCP option 6
(DNS server)**, then renew leases (or reboot clients) — they keep the old resolver until
their lease renews.

**Per device, if it doesn't.** Many ISP routers (Sky Hubs among them) ship with the DHCP
DNS fields removed, and there is no way around it in the stock UI. Set DNS on each device
instead:

```bash
networksetup -setdnsservers Wi-Fi 192.168.0.53
```

Revert with `networksetup -setdnsservers Wi-Fi Empty`. On iOS: Wi-Fi → the network →
Configure DNS → Manual. Don't list the router as a secondary — the OS will use either
resolver, so some queries silently skip the sinkhole and you lose the signal about what
is actually being blocked.

Whichever route you take, keep a way back: this device becomes a single point of failure
for every name lookup that uses it.

## Acceptance tests

```bash
dig @<esp-ip> doubleclick.net        # 0.0.0.0, ANCOUNT=1
dig @<esp-ip> ads.doubleclick.net    # 0.0.0.0  (suffix match)
dig @<esp-ip> example.com            # real address, forwarded
dig @<esp-ip> doubleclick.net AAAA   # NOERROR, ANCOUNT=0
dig @<esp-ip> +short google.com      # real address
```

Host-side tests (no hardware needed — both compile the real firmware sources):

```bash
python3 tools/test_hash_parity.py    # Python hash == main/fnv1a.h
python3 tools/test_matching.py       # suffix walk, read-mode fallback, fail-open
```

Fuzz the live device — 10k mutated packets, then a liveness check:

```bash
python3 tools/fuzz_dns.py <esp-ip>
```

---

## How it works

### Partition layout

4MB flash, no OTA: one factory app, everything else is blocklist.

| Name | Type | Offset | Size |
|---|---|---|---|
| nvs | data/nvs | 0x9000 | 0x5000 |
| phy_init | data/phy | 0xE000 | 0x1000 |
| factory | app | 0x10000 | 0x180000 |
| blocklist | data/0x40 | **0x190000** | 0x270000 (2.5MB, ~650k hashes) |

### Blob format

Little-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `BLK1` |
| 4 | 4 | count (uint32) |
| 8 | 4 | algo_id — `1` = FNV-1a 32 |
| 12 | 4 | reserved, zero |
| 16 | count*4 | sorted ascending, deduplicated uint32 hashes |

**Fail open, never fail closed.** Bad magic, wrong algo_id, a count that overruns the
partition, or an unreadable header all leave the device forwarding every query. A
corrupt blocklist must never take name resolution down for the whole network.

### mmap, with a fallback

The ESP32's DROM mapping window is finite, and a 2.5MB map can fail depending on what
else is mapped. That's expected. If `esp_partition_mmap` fails, lookups fall back to
`esp_partition_read()` for each binary-search probe — ~18 four-byte reads, still
sub-millisecond, and it costs no address space. The boot log says which mode is active:

```
I blocklist: mmap mode, 248113 hashes
W blocklist: mmap failed (ESP_ERR_NO_MEM), using read mode, 248113 hashes
```

### Suffix matching, and its limits

Blocklists mix registrable domains (`doubleclick.net`) with subdomains
(`ads.tracker.com`), and blocking `tracker.com` should also kill `a.b.tracker.com`.
So the walk goes longest suffix to shortest, hashing each candidate independently:

```
a.b.tracker.co.uk  ->  b.tracker.co.uk  ->  tracker.co.uk  ->  stop
```

It stops before probing a bare public suffix, using a **12-entry static list** of
multi-label suffixes (`co.uk org.uk ac.uk gov.uk com.au net.au co.jp co.nz co.za
com.br com.mx co.in`): 3 labels minimum under those, 2 otherwise.

**The heuristic's limits, deliberately accepted:** a full Public Suffix List is
thousands of entries and would need its own flash partition. Under an unlisted
multi-label suffix (say `com.sg`), the walk will probe the bare public suffix. That is
only a problem if someone puts `com.sg` in a blocklist — nobody does, and the fix is
one line in `kMultiSuffix[]` in `main/blocklist.c`.

The walk is capped at **8 probes**, so a domain buried more than 8 labels below its
blocked parent is missed. Real ad hostnames don't get that deep.

### DNS server

UDP on `0.0.0.0:53`. One listener task feeds a FreeRTOS queue serving 4 worker tasks;
each worker opens an **ephemeral upstream socket** and does a blocking `recvfrom` with
a 2s timeout. Worker tasks instead of an async transaction table means no transaction-ID
rewriting and none of the bugs that come with it. Upstream failure or timeout → SERVFAIL.

Blocked responses: `QTYPE=A` gets `0.0.0.0` with TTL 60; `AAAA` and everything else gets
NODATA (`RCODE=0`, `ANCOUNT=0`). `ARCOUNT` is forced to 0, which drops any EDNS0 OPT
record rather than echoing it back. Non-blocked queries are forwarded verbatim to the
upstream (`UPSTREAM_DNS` in `secrets.h`, default `1.1.1.1`) and the response is relayed
unchanged.

The parser rejects `QDCOUNT != 1`, `QCLASS != IN`, any opcode but QUERY, and
**compression pointers in the question section** (illegal there, and the classic parser
trap). Every read is bounds-checked against the actual datagram length.

A summary line goes to the log every 60s:

```
I dns: q=4812 blocked=1633 fwd=3179 upfail=0 dropped=0 heap=142380
```

### Dashboard

`http://<esp-ip>/` serves a single self-contained page (5.7KB, no external assets —
inline CSS and JS, no CDN, since the device can't proxy one) polling `/api/stats`
every 5s. It shows total queries, blocks, block rate, free heap, a 24-hour
bar chart, and top blocked/queried domains.

It also shows the **recent query log** (last 40, newest first, tagged forward / block /
allow / rewrite) and edits the **allowlist** and **rewrites** live.

The page is embedded in the firmware via `EMBED_FILES`, not stored on a filesystem —
there is no SPIFFS partition, because the blocklist owns all the flash the app doesn't.
The HTTP task runs at priority 3, below the DNS listener (6) and workers (5), so a
browser refreshing a chart can never delay name resolution.

Hourly buckets are keyed on **uptime**, not wall clock: there is no RTC and no SNTP, so
"last 24 hours" means the last 24 hours the device has been powered.

Top-domain tables use Space-Saving with `STATS_TOP_N` slots. Heavy hitters are always
present and correctly ranked; the counts are upper bounds, so tail entries read high.
Exact counts would mean retaining every domain seen, which the RAM doesn't allow.

Feature set inspired by [twedds95/ESP_hole](https://github.com/twedds95/ESP_hole)
(MPL-2.0). No code was copied from it — that project is Arduino/PlatformIO with bloom
filters and an async web server, none of which ports to this design.

### Allowlist and rewrites

The blocklist partition is immutable, so without this an over-broad entry means
rebuilding the blob and reflashing. Both lists live in NVS, hold up to 32 entries each,
survive reboots, and are edited from the dashboard or `curl`:

```bash
curl -X POST -d 'd=example.com' http://192.168.0.53/api/allow
```

```bash
curl -X POST -d 'd=nas.home&ip=192.168.0.10' http://192.168.0.53/api/rewrite
```

Add `/del` to either path to remove an entry. Both match the domain **and all its
subdomains**, so allowing `example.com` also allows `a.b.example.com`.

Resolution order per query: rewrite → allowlist → blocklist → forward. A rewrite is an
explicit instruction and a allowlist entry an explicit exemption, so both outrank the
blob.

> **An allowlist entry cannot override the upstream resolver.** The default upstream is
> AdGuard (`94.140.14.14`), which filters ads itself. Allowlist `doubleclick.net` and
> the device will dutifully forward the query — and AdGuard will return `0.0.0.0`
> anyway. If allowlisting appears to do nothing, that is why. Set `UPSTREAM_DNS` to
> `1.1.1.1` in `secrets.h` for an unfiltered upstream where the allowlist is the final
> word. It's a real trade: AdGuard catches what the local list misses, at the cost of a
> second blocklist you can't edit.

### First-run provisioning

With no credentials in NVS and none in `secrets.h`, the device raises a setup AP
(`esphole-setup`, password `esphole-setup`) instead of joining anything. Connect to it
and the captive portal opens at `http://192.168.4.1/` — the DNS server runs in captive
mode, answering every query with its own address, so the setup page appears by itself.
Enter the network name and password; credentials are stored in NVS and the device
reboots into station mode.

NVS credentials always win over `secrets.h`. To force provisioning again:

```bash
idf.py -p /dev/cu.usbserial-310 erase-flash
```

That wipes the blocklist partition too, so reflash `blocklist.bin` afterwards.

Credentials are sent in a POST body, never a query string — URLs end up in logs.

### WiFi

Station mode, credentials and static IP from `secrets.h` (gitignored; copy
`secrets.h.example`). Reconnect uses exponential backoff from 1s, capped at 30s, reset
on a successful IP. Task watchdog is on with a 10s timeout — generous, because workers
legitimately block for up to 2s on upstream.

**Use a static IP.** The router hands this address out as the network's DNS server; if
it moves, name resolution stops for every client.

### Hash parity

The C and Python implementations must agree byte for byte or the blob is worthless.
`tools/test_hash_parity.py` compiles the *actual* firmware header (`main/fnv1a.h`) with
the host compiler and diffs it against the Python version over a fixed vector set
(including the empty string, a 253-char name, and a name with digits and hyphens). It
also emits `main/hash_vectors.h` for an on-device boot self-test:

```bash
idf.py -DSINKHOLE_HASH_SELFTEST=1 build
```

---

## Not implemented — on purpose

**YouTube video ads.** Ads and video come from the same `googlevideo.com` hosts and are
increasingly stitched into the stream server-side. No DNS-layer blocker can separate
them — not this one, not Pi-hole. This is not a limitation of the design; it's the
ceiling of the whole approach.

**Browsers with Secure DNS (DoH) enabled bypass this entirely.** Chrome, Firefox and
Edge ship it on or one toggle away. Those queries go straight to Cloudflare or Google
over HTTPS and never reach port 53. Turn it off per browser, or block the known DoH
endpoints at the router.

**This becomes a single point of failure for all name resolution.** When the ESP32
reboots, drops off WiFi, or you re-flash it, every client on the network loses DNS.
Configure a secondary DNS server on the router during testing.

Also out of scope: DoH/DoT upstream, DNSSEC validation, IPv6/AAAA sinkholing, TCP DNS
on port 53, and a DHCP server.

A web UI *was* on this list and has since been built — see **Dashboard** above. Nothing
else on the list has moved.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Everything resolves, nothing blocked | Check the boot log for `no blocklist partition` or `bad header`. The blob wasn't flashed, or was flashed to the wrong offset. It fails open by design. |
| `mmap failed` in the log | Normal. Read-mode fallback is active and correct, just slower. |
| A site broke | Hash collision (~1 in 17,000) or an over-broad list entry. Add it to `--allowlist` and rebuild. |
| Blocking works, forwarding times out | `UPSTREAM_DNS` in `secrets.h` points at this device, or the upstream is unreachable. |
| dig times out entirely | Static IP collides with the DHCP pool, or the device is stuck reconnecting — check the serial console. |
| Allowlisting a domain changes nothing | The upstream is filtering it too. Check with `dig @94.140.14.14 <domain>`; if that returns `0.0.0.0`, switch `UPSTREAM_DNS` to `1.1.1.1`. |
| Dashboard unreachable but DNS works | `httpd_start` failed at boot (check the log). DNS is unaffected — the HTTP server is deliberately isolated from it. |
| Slow first lookups after boot | Flash cache is cold in read mode. It settles. |

## Layout

```
main/fnv1a.h        hash, shared with Python via the parity test
main/blocklist.c    partition mmap + read fallback, binary search, suffix walk
main/dns_server.c   :53 listener, parser, sinkhole responder, upstream forwarder
main/overrides.c    NVS allowlist + rewrites, consulted before the blob
main/stats.c        counters, 24h rings, top-N tables, recent query log
main/http_server.c  :80 dashboard and JSON API
main/dashboard.html embedded via EMBED_FILES, no external assets
main/provision.html first-run setup portal
main/wifi.c         NVS/secrets.h credentials, static IP, backoff reconnect, setup AP
tools/              blob builder, parity test, matching test, fuzzer
```

**Phase 2 (`main/cache.c`, a 32-entry LRU response cache) is not built.** The spec
scopes it to "only after the core works", and ~16KB of fixed 512-byte buffers buys
little on a home network where the upstream resolver is a few milliseconds away and
clients cache aggressively themselves. Add it if the 60s stats line shows a forward
rate high enough to matter.
