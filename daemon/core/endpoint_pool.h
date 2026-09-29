#ifndef SENKO_ENDPOINT_POOL_H
#define SENKO_ENDPOINT_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* portable endpoint dialer state: which resolved addresses exist, which one
   worked last, and which are in cooldown after a failed attempt. no network
   calls happen here, the dialer in daemon/ owns actual connects and dns */

#define ENDPOINT_POOL_MAX 16
#define ENDPOINT_TTL_MIN_S 30u
#define ENDPOINT_TTL_MAX_S 3600u
#define ENDPOINT_COOLDOWN_BASE_MS 1000u
#define ENDPOINT_COOLDOWN_MAX_MS  60000u

typedef struct {
    uint8_t  address[16];
    uint8_t  address_len; /* 4 or 16 */
    uint64_t failures;
    uint64_t cooldown_until_ms; /* senko_now_ms() scale, 0 = not in cooldown */
    uint64_t last_success_ms;   /* 0 = never succeeded */
    uint64_t last_attempt_ms;   /* 0 = never attempted */
} endpoint_t;

typedef struct {
    endpoint_t entries[ENDPOINT_POOL_MAX];
    size_t     count;
    size_t     last_good; /* index into entries, SIZE_MAX = none known yet */
    uint64_t   resolved_at_ms;
    uint64_t   expires_at_ms;
} endpoint_pool_t;

typedef enum {
    ENDPOINT_POOL_OK    = 0,
    ENDPOINT_POOL_EMPTY = 1,  /* select found no address at all */
    ENDPOINT_POOL_ERR_ARG  = -1,
    ENDPOINT_POOL_ERR_FULL = -2
} endpoint_pool_status_t;

void endpoint_pool_init(endpoint_pool_t *pool);

/* replace the resolved set from a fresh dns answer. an address that appears
   both before and after keeps its failure count and cooldown, so a flapping
   record does not get a clean slate on every re-resolve. ttl_seconds is
   clamped to [ENDPOINT_TTL_MIN_S, ENDPOINT_TTL_MAX_S] */
endpoint_pool_status_t endpoint_pool_set_resolved(endpoint_pool_t *pool,
    const uint8_t addresses[][16], const uint8_t *address_lens, size_t count,
    uint64_t now_ms, uint32_t ttl_seconds);

/* stable selection: the last known good address if it is not in cooldown,
   else the first non-cooldown address in resolved order, else (everything
   in cooldown) the address whose cooldown ends soonest, lowest index breaks
   a tie. ENDPOINT_POOL_EMPTY means the pool has no resolved address at all */
endpoint_pool_status_t endpoint_pool_select(const endpoint_pool_t *pool, uint64_t now_ms,
    uint8_t *out_address, uint8_t *out_address_len, size_t *out_index);

void endpoint_pool_mark_success(endpoint_pool_t *pool, size_t index, uint64_t now_ms);

/* bounded exponential backoff, capped at ENDPOINT_COOLDOWN_MAX_MS. does not
   clear last_good: a transient failure of the known good address should not
   make the dialer forget it once the cooldown passes */
void endpoint_pool_mark_failure(endpoint_pool_t *pool, size_t index, uint64_t now_ms);

int endpoint_pool_expired(const endpoint_pool_t *pool, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
