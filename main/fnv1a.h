#pragma once
#include <stdint.h>
#include <stddef.h>

/* FNV-1a 32. Must stay byte-identical to tools/build_blocklist.py.
   Input is the lowercased ASCII domain: no trailing dot, no leading dot.
   tools/test_hash_parity.py compiles THIS header and diffs it against Python. */
static inline uint32_t fnv1a(const char *s, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}
