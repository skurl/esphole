#!/usr/bin/env python3
"""Fire 10k mutated DNS packets at the sinkhole, then prove it still answers.

Usage: tools/fuzz_dns.py <esp-ip> [count]

The device must drop every one of these without rebooting. A crash shows up as
the final liveness query timing out (and a boot banner on the serial console).
"""
import random
import socket
import struct
import sys

SEEDS = []


def query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def build_seeds():
    SEEDS.append(query("example.com"))
    SEEDS.append(query("doubleclick.net"))
    SEEDS.append(query("a.b.c.d.e.f.g.h.i.j.k.example.co.uk", 28))
    # compression pointer in the question section — illegal, must be rejected
    SEEDS.append(struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1))
    # label length runs past the end of the datagram
    SEEDS.append(struct.pack(">HHHHHH", 2, 0x0100, 1, 0, 0, 0) + b"\x3fshort")
    # QDCOUNT lies
    SEEDS.append(struct.pack(">HHHHHH", 3, 0x0100, 9, 0, 0, 0) + b"\x03abc\x00" + struct.pack(">HH", 1, 1))
    SEEDS.append(b"")                                  # zero-length datagram
    SEEDS.append(b"\x00" * 12)                         # header only
    SEEDS.append(query("x" * 63 + "." + "y" * 63 + "." + "z" * 63 + "." + "w" * 60))


def mutate(p: bytes, rng: random.Random) -> bytes:
    b = bytearray(p)
    for _ in range(rng.randint(1, 6)):
        op = rng.randint(0, 3)
        if op == 0 and b:                      # flip a byte
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1 and b:                    # truncate
            del b[rng.randrange(len(b)):]
        elif op == 2:                          # append junk
            b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 32)))
        elif op == 3 and b:                    # splice
            i = rng.randrange(len(b))
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    return bytes(b[:1400])


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10000

    build_seeds()
    rng = random.Random(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.02)

    for i in range(count):
        s.sendto(mutate(rng.choice(SEEDS), rng), (host, 53))
        try:
            s.recvfrom(2048)                   # drain whatever comes back
        except socket.timeout:
            pass
        if (i + 1) % 1000 == 0:
            print(f"  {i + 1}/{count}")

    print("liveness check...")
    s.settimeout(3)
    for attempt in range(3):
        s.sendto(query("doubleclick.net", txid=0xBEEF), (host, 53))
        try:
            r, _ = s.recvfrom(2048)
        except socket.timeout:
            continue
        if r[:2] == b"\xbe\xef" and r[6:8] == b"\x00\x01" and r[-4:] == b"\x00\x00\x00\x00":
            print(f"PASS: survived {count} mutated packets, still sinkholing")
            return 0
        print(f"unexpected reply: {r.hex()}")
        return 1
    print("FAIL: no reply after fuzzing — check the serial console for a reboot")
    return 1


if __name__ == "__main__":
    sys.exit(main())
