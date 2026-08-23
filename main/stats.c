#include "stats.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

/* ponytail: one global mutex for the whole stats block. At a few hundred
   queries per minute the DNS workers never meaningfully contend for it.
   Split per-table if query rate ever gets into the thousands/sec. */
static SemaphoreHandle_t s_lock;

static uint32_t s_queries, s_blocked, s_forwarded, s_upstream_fail, s_dropped;
static uint32_t s_hourly_q[STATS_HOURS];
static uint32_t s_hourly_b[STATS_HOURS];
static uint32_t s_hour;                     /* current bucket index */
static stats_entry_t s_top_blocked[STATS_TOP_N];
static stats_entry_t s_top_queried[STATS_TOP_N];

static uint32_t uptime_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

void stats_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* Advance the hourly rings, zeroing every bucket we skipped over. Called with
   the lock held. Buckets are keyed on uptime, not wall clock — there is no RTC
   and no SNTP here, so "last 24 hours" means "last 24 hours of uptime". */
static void roll_hours(void)
{
    uint32_t now = (uptime_s() / 3600) % STATS_HOURS;
    while (s_hour != now) {
        s_hour = (s_hour + 1) % STATS_HOURS;
        s_hourly_q[s_hour] = 0;
        s_hourly_b[s_hour] = 0;
    }
}

/* Space-Saving: on a miss, evict the smallest counter and inherit its count.
   Genuine heavy hitters are always present and correctly ranked, but the counts
   are UPPER bounds — an evicted domain's total is passed to whatever replaces
   it. With STATS_TOP_N slots against a household's domain churn, expect the
   tail entries to read high. Raise STATS_TOP_N if you want tighter numbers.
   ponytail: exact counts would mean storing every domain seen; not worth the RAM. */
static void top_bump(stats_entry_t *tbl, const char *name)
{
    int min_i = 0;
    for (int i = 0; i < STATS_TOP_N; i++) {
        if (tbl[i].count == 0) { min_i = i; break; }
        if (strcmp(tbl[i].name, name) == 0) { tbl[i].count++; return; }
        if (tbl[i].count < tbl[min_i].count) min_i = i;
    }
    uint32_t inherited = tbl[min_i].count;
    strlcpy(tbl[min_i].name, name, STATS_NAME_MAX);
    tbl[min_i].count = inherited + 1;
}

void stats_record(const char *qname, bool blocked)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    roll_hours();
    s_hourly_q[s_hour]++;
    top_bump(s_top_queried, qname);
    if (blocked) {
        s_blocked++;
        s_hourly_b[s_hour]++;
        top_bump(s_top_blocked, qname);
    }
    xSemaphoreGive(s_lock);
}

#define COUNTER(fn, var)                              \
    void fn(void)                                     \
    {                                                 \
        xSemaphoreTake(s_lock, portMAX_DELAY);        \
        var++;                                        \
        xSemaphoreGive(s_lock);                       \
    }

COUNTER(stats_note_query,         s_queries)
COUNTER(stats_note_forwarded,     s_forwarded)
COUNTER(stats_note_upstream_fail, s_upstream_fail)
COUNTER(stats_note_drop,          s_dropped)

void stats_snapshot(stats_snapshot_t *out)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    roll_hours();
    out->queries       = s_queries;
    out->blocked       = s_blocked;
    out->forwarded     = s_forwarded;
    out->upstream_fail = s_upstream_fail;
    out->dropped       = s_dropped;
    out->hour_index    = s_hour;
    memcpy(out->hourly_q,    s_hourly_q,    sizeof(s_hourly_q));
    memcpy(out->hourly_b,    s_hourly_b,    sizeof(s_hourly_b));
    memcpy(out->top_blocked, s_top_blocked, sizeof(s_top_blocked));
    memcpy(out->top_queried, s_top_queried, sizeof(s_top_queried));
    xSemaphoreGive(s_lock);

    out->uptime_s      = uptime_s();
    out->free_heap     = esp_get_free_heap_size();
    out->min_free_heap = esp_get_minimum_free_heap_size();
}
