# esphole

A network-wide DNS ad-blocker on a single ESP32.

Point a device's DNS at it and requests for ad and tracker domains resolve to
nothing, while everything else is forwarded to a real resolver and answered
normally. Same idea as Pi-hole, on hardware that costs a few pounds and draws
about half a watt.

## What it does

- **Blocks ~93,000 ad and tracker domains** from the usual public blocklists,
  including subdomains — blocking `tracker.com` also blocks `a.b.tracker.com`.
- **Forwards everything else** to an upstream resolver and relays the answer back.
- **Serves a web dashboard** showing queries, blocks, block rate, a 24-hour
  activity chart, top blocked and queried domains, and a live query log.
- **Lets you allowlist domains** when a blocklist entry breaks a site, and add
  local DNS rewrites — both editable from the dashboard, no rebuild or reflash.
- **Sets itself up over WiFi** on first boot: it raises a setup network and asks
  for your credentials in a browser.

## Why it exists

Similar projects need an ESP32 with extra memory, because they keep the
blocklist as text. This one doesn't. It stores the list as sorted hashes in
flash and searches them in place, so a plain ESP32-WROOM-32D with no PSRAM can
hold a full-sized blocklist and still use essentially no RAM to do it.

It's also built to fail safe. If the blocklist is missing or damaged the device
forwards everything rather than blocking everything, because a broken ad-blocker
should be invisible, not take the network down.

## Getting started

```bash
python3 tools/build_blocklist.py     # downloads and builds the blocklist
idf.py build flash monitor           # ESP-IDF v5.x
```

Flash the generated `blocklist.bin` to the blocklist partition, then set the
device's IP as the DNS server on your router or on individual devices. The boot
log prints its address; the dashboard is on port 80.

## What it won't do

- **YouTube ads.** They come from the same servers as the video itself, so no
  DNS-based blocker can separate them. Not a shortcoming of this one.
- **Anything for browsers using Secure DNS.** Chrome and Firefox can send
  lookups over HTTPS directly to their own resolver, bypassing this entirely.
- **Survive being switched off.** Any device pointed at it loses all name
  resolution while it's down. Keep a second DNS server configured, and think
  twice before pointing a laptop that roams between networks at it.

## Status

Working and running on hardware. Verified against malformed traffic, sustained
query load, and WiFi dropouts.

Full design notes, wire formats and troubleshooting live in this file's earlier
revisions (`git log -p README.md`) and in the source comments.
