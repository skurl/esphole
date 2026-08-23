#pragma once
#include <stdint.h>
#include <stdbool.h>

#define STATS_HOURS     24
#define STATS_TOP_N     10
#define STATS_NAME_MAX  48

typedef struct {
    char     name[STATS_NAME_MAX];
    uint32_t count;
} stats_entry_t;

typedef struct {
    uint32_t queries, blocked, forwarded, upstream_fail, dropped;
    uint32_t uptime_s;
    uint32_t free_heap, min_free_heap;
    uint32_t hour_index;                    /* newest bucket in the rings below */
    uint32_t hourly_q[STATS_HOURS];
    uint32_t hourly_b[STATS_HOURS];
    stats_entry_t top_blocked[STATS_TOP_N];
    stats_entry_t top_queried[STATS_TOP_N];
} stats_snapshot_t;

void stats_init(void);

/* One answered query. qname is the lowercase domain. */
void stats_record(const char *qname, bool blocked);
void stats_note_forwarded(void);
void stats_note_upstream_fail(void);
void stats_note_drop(void);
void stats_note_query(void);

void stats_snapshot(stats_snapshot_t *out);
