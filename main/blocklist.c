#include "blocklist.h"
#include <string.h>
#include "esp_partition.h"
#include "esp_log.h"

static const char *TAG = "blocklist";

#define BLK_MAGIC     0x314B4C42u   /* "BLK1" little-endian */
#define ALGO_FNV1A32  1u
#define HDR_SIZE      16
#define MAX_LABELS    128           /* 253 chars => at most 127 labels */
#define MAX_PROBES    8

/* Registrable domains sit one label deeper under these. Deliberately a short
   static list, not the Public Suffix List — see README for the limits.
   ponytail: 12 entries, swap in a real PSL only if false negatives show up. */
static const char *const kMultiSuffix[] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
    "co.jp", "co.nz", "co.za", "com.br", "com.mx", "co.in",
};

static const esp_partition_t   *s_part;
static const uint32_t          *s_hashes;   /* non-NULL only when mmapped */
static esp_partition_mmap_handle_t s_map;
static uint32_t                 s_count;
static bool                     s_ready;

void blocklist_init(void)
{
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "blocklist");
    if (!s_part) {
        ESP_LOGE(TAG, "no blocklist partition — forwarding everything");
        return;
    }

    struct { uint32_t magic, count, algo, reserved; } hdr;
    if (esp_partition_read(s_part, 0, &hdr, sizeof(hdr)) != ESP_OK) {
        ESP_LOGE(TAG, "header read failed — forwarding everything");
        return;
    }
    if (hdr.magic != BLK_MAGIC || hdr.algo != ALGO_FNV1A32) {
        ESP_LOGE(TAG, "bad header (magic=%08lx algo=%lu) — forwarding everything",
                 (unsigned long)hdr.magic, (unsigned long)hdr.algo);
        return;
    }
    if ((uint64_t)HDR_SIZE + (uint64_t)hdr.count * 4 > s_part->size) {
        ESP_LOGE(TAG, "count %lu overruns partition — forwarding everything",
                 (unsigned long)hdr.count);
        return;
    }

    s_count = hdr.count;

    /* mmap of 2.5MB can fail depending on what else holds DROM window space.
       That is expected, not fatal: fall back to ~20 four-byte partition reads
       per lookup, which costs no address space and is still sub-millisecond. */
    const void *ptr;
    esp_err_t err = esp_partition_mmap(s_part, 0, s_part->size,
                                       ESP_PARTITION_MMAP_DATA, &ptr, &s_map);
    if (err == ESP_OK) {
        s_hashes = (const uint32_t *)((const uint8_t *)ptr + HDR_SIZE);
        ESP_LOGI(TAG, "mmap mode, %lu hashes", (unsigned long)s_count);
    } else {
        ESP_LOGW(TAG, "mmap failed (%s), using read mode, %lu hashes",
                 esp_err_to_name(err), (unsigned long)s_count);
    }
    s_ready = s_count > 0;
}

bool     blocklist_ready(void) { return s_ready; }
uint32_t blocklist_count(void) { return s_count; }

static bool lookup(uint32_t h)
{
    uint32_t lo = 0, hi = s_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t v;
        if (s_hashes) {
            v = s_hashes[mid];
        } else if (esp_partition_read(s_part, HDR_SIZE + mid * 4, &v, 4) != ESP_OK) {
            return false;               /* fail open */
        }
        if (v == h) return true;
        if (v < h) lo = mid + 1; else hi = mid;
    }
    return false;
}

bool blocklist_blocked(const char *d, size_t len)
{
    if (!s_ready || len == 0 || len > 253) return false;

    uint16_t start[MAX_LABELS];
    int n = 0;
    start[n++] = 0;
    for (size_t i = 0; i < len; i++) {
        if (d[i] != '.') continue;
        if (n >= MAX_LABELS) return false;
        start[n++] = (uint16_t)(i + 1);
    }
    if (n < 2) return false;            /* bare label / TLD: never blocked */

    /* Stop the walk before it reaches a bare public suffix. */
    int min_labels = 2;
    if (n >= 3) {
        const char *tail = d + start[n - 2];
        for (size_t i = 0; i < sizeof(kMultiSuffix) / sizeof(*kMultiSuffix); i++) {
            if (strcmp(tail, kMultiSuffix[i]) == 0) { min_labels = 3; break; }
        }
    }

    for (int i = 0, probes = 0; i + min_labels <= n && probes < MAX_PROBES; i++, probes++) {
        if (lookup(fnv1a(d + start[i], len - start[i]))) return true;
    }
    return false;
}
