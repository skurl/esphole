#!/usr/bin/env python3
"""Compile main/blocklist.c on the host against stub ESP headers and exercise
the suffix walk, the read-mode fallback, and fail-open on a corrupt header.

No firmware #ifdefs: the stubs live here and are written to a temp dir.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.normpath(os.path.join(HERE, "..", "main"))
sys.path.insert(0, HERE)
from build_blocklist import fnv1a  # noqa: E402

BLOCKED = ["doubleclick.net", "ads.tracker.com", "tracker.co.uk"]

STUB_PARTITION_H = r'''
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_MMAP_DATA 1
typedef uint32_t esp_partition_mmap_handle_t;
typedef struct { size_t size; } esp_partition_t;
extern const uint8_t *g_blob;
extern size_t g_blob_size;
extern int g_mmap_fails;
static esp_partition_t g_part;
static inline const esp_partition_t *esp_partition_find_first(int t, int s, const char *l)
{ (void)t; (void)s; (void)l; g_part.size = g_blob_size; return &g_part; }
static inline esp_err_t esp_partition_read(const esp_partition_t *p, size_t off, void *d, size_t n)
{ (void)p; if (off + n > g_blob_size) return ESP_FAIL; memcpy(d, g_blob + off, n); return ESP_OK; }
static inline esp_err_t esp_partition_mmap(const esp_partition_t *p, size_t o, size_t s,
                                           int f, const void **out, esp_partition_mmap_handle_t *h)
{ (void)p; (void)o; (void)s; (void)f; (void)h;
  if (g_mmap_fails) return ESP_FAIL; *out = g_blob; return ESP_OK; }
static inline const char *esp_err_to_name(esp_err_t e) { (void)e; return "STUB_FAIL"; }
'''

STUB_LOG_H = r'''
#pragma once
#include <stdio.h>
#define ESP_LOGE(tag, fmt, ...) fprintf(stderr, "E %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) fprintf(stderr, "W %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) fprintf(stderr, "I %s: " fmt "\n", tag, ##__VA_ARGS__)
'''

HARNESS = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blocklist.h"
const uint8_t *g_blob; size_t g_blob_size; int g_mmap_fails;
extern const uint8_t kBlob[]; extern const size_t kBlobLen;

static int fails;
static void check(const char *d, int want)
{
    int got = blocklist_blocked(d, strlen(d));
    if (got != want) { printf("FAIL %-34s got=%d want=%d\n", d, got, want); fails++; }
}

int main(int argc, char **argv)
{
    g_mmap_fails = (argc > 1 && !strcmp(argv[1], "nommap"));
    g_blob = kBlob; g_blob_size = kBlobLen;

    if (argc > 1 && !strcmp(argv[1], "corrupt")) {
        static uint8_t bad[64]; memcpy(bad, kBlob, sizeof(bad)); bad[0] = 'X';
        g_blob = bad; g_blob_size = sizeof(bad);
        blocklist_init();
        if (blocklist_ready()) { printf("FAIL corrupt blob was accepted\n"); fails++; }
        check("doubleclick.net", 0);          /* fail open: block nothing */
        printf(fails ? "corrupt: FAILED\n" : "corrupt: ok (fails open)\n");
        return fails != 0;
    }

    blocklist_init();
    if (!blocklist_ready()) { printf("FAIL blocklist not ready\n"); return 1; }

    check("doubleclick.net", 1);
    check("ads.doubleclick.net", 1);          /* suffix match */
    check("a.b.doubleclick.net", 1);
    check("ads.tracker.com", 1);
    check("x.ads.tracker.com", 1);
    check("tracker.com", 0);                  /* parent not listed */
    check("a.b.tracker.co.uk", 1);            /* stops above the co.uk suffix */
    check("tracker.co.uk", 1);
    check("example.com", 0);
    check("co.uk", 0);
    check("uk", 0);
    check("", 0);
    check(".", 0);
    /* Documented ceiling: the walk gives up after 8 probes. */
    check("a.b.c.d.e.f.g.h.i.j.doubleclick.net", 0);

    printf("%s: %s\n", g_mmap_fails ? "read-mode" : "mmap-mode",
           fails ? "FAILED" : "ok");
    return fails != 0;
}
'''


def main() -> int:
    hashes = sorted({fnv1a(d) for d in BLOCKED})
    blob = b"BLK1" + struct.pack("<III", len(hashes), 1, 0) + \
        struct.pack(f"<{len(hashes)}I", *hashes)

    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "esp_partition.h"), "w").write(STUB_PARTITION_H)
        open(os.path.join(td, "esp_log.h"), "w").write(STUB_LOG_H)
        open(os.path.join(td, "harness.c"), "w").write(HARNESS)
        with open(os.path.join(td, "blob.c"), "w") as f:
            f.write("#include <stdint.h>\n#include <stddef.h>\n"
                    "const uint8_t kBlob[] = {" +
                    ",".join(str(b) for b in blob) + "};\n"
                    f"const size_t kBlobLen = {len(blob)};\n")

        exe = os.path.join(td, "t")
        subprocess.run(["cc", "-O1", "-Wall", "-I", td, "-I", MAIN,
                        os.path.join(MAIN, "blocklist.c"),
                        os.path.join(td, "harness.c"),
                        os.path.join(td, "blob.c"), "-o", exe], check=True)

        rc = 0
        for mode in ("mmap", "nommap", "corrupt"):
            rc |= subprocess.run([exe, mode]).returncode
    return rc


if __name__ == "__main__":
    sys.exit(main())
