#!/usr/bin/env python3
"""Build blocklist.bin: a sorted, deduplicated array of FNV-1a 32 domain hashes.

Blob layout (little-endian):
    0  4  magic "BLK1"
    4  4  count
    8  4  algo_id (1 = FNV-1a 32)
   12  4  reserved (zero)
   16  count*4  sorted ascending, deduplicated uint32 hashes
"""
import argparse
import re
import struct
import sys
import urllib.request

MAGIC = b"BLK1"
ALGO_FNV1A32 = 1
PARTITION_SIZE = 0x270000
FLASH_OFFSET = 0x190000
DEFAULT_SOURCE = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)")
JUNK = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


def fnv1a(s: str) -> int:
    """Byte-identical to fnv1a() in main/fnv1a.h. See tools/test_hash_parity.py."""
    h = 2166136261
    for b in s.encode("ascii", "ignore"):
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def read_source(src: str) -> str:
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=60) as r:
            return r.read().decode("utf-8", "replace")
    with open(src, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_hosts(text: str) -> set:
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0]           # strip inline comments
        m = HOSTS_RE.match(line)
        if not m:
            continue
        d = m.group(1).strip().rstrip(".").lower()
        if d in JUNK or "." not in d or len(d) > 253:
            continue
        out.add(d)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", default=[DEFAULT_SOURCE],
                    help=f"hosts-format URLs or files (default: {DEFAULT_SOURCE})")
    ap.add_argument("--allowlist", help="file of domains to drop, one per line")
    ap.add_argument("-o", "--out", default="blocklist.bin")
    args = ap.parse_args()

    domains = set()
    for src in args.sources or [DEFAULT_SOURCE]:
        text = read_source(src)
        found = parse_hosts(text)
        print(f"{src}: {len(found)} domains")
        domains |= found

    if args.allowlist:
        with open(args.allowlist, encoding="utf-8") as f:
            allow = {l.split("#", 1)[0].strip().rstrip(".").lower()
                     for l in f if l.split("#", 1)[0].strip()}
        before = len(domains)
        domains -= allow
        print(f"allowlist: removed {before - len(domains)}")

    hashes = sorted({fnv1a(d) for d in domains})

    collisions = len(domains) - len(hashes)
    fp_rate = len(hashes) / 2**32
    print(f"\n{len(domains)} unique domains -> {len(hashes)} unique hashes")
    print(f"collisions: {collisions} "
          f"({collisions} domains share a hash with another and are redundant)")
    print(f"false-positive rate: {fp_rate:.2e} "
          f"(~1 in {int(1/fp_rate):,} lookups of a NON-blocked domain)")

    size = 16 + len(hashes) * 4
    if size > PARTITION_SIZE:
        print(f"\n*** WARNING: {size} bytes exceeds the {PARTITION_SIZE}-byte "
              f"blocklist partition by {size - PARTITION_SIZE} bytes. "
              f"Trim sources or grow the partition. ***", file=sys.stderr)
        return 1

    with open(args.out, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<III", len(hashes), ALGO_FNV1A32, 0))
        f.write(struct.pack(f"<{len(hashes)}I", *hashes))

    pct = 100 * size / PARTITION_SIZE
    print(f"\nwrote {args.out}: {size} bytes ({pct:.1f}% of partition)")
    print(f"\nOver WiFi, no cable (device stays up, fails open for a few seconds):\n"
          f"  curl -X POST --data-binary @{args.out} http://<esp-ip>/api/blocklist\n"
          f"\nOr over USB:\n"
          f"  esptool --chip esp32 write-flash {FLASH_OFFSET:#x} {args.out}\n"
          "  (esptool 4.x, e.g. the one bundled in an IDF shell: write_flash)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
