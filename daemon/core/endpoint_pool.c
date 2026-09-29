#include "endpoint_pool.h"

#include <string.h>

void endpoint_pool_init(endpoint_pool_t *pool) {
    if (!pool) return;
    memset(pool, 0, sizeof *pool);
    pool->last_good = SIZE_MAX;
}

endpoint_pool_status_t endpoint_pool_set_resolved(endpoint_pool_t *pool,
    const uint8_t addresses[][16], const uint8_t *address_lens, size_t count,
    uint64_t now_ms, uint32_t ttl_seconds) {
    if (!pool || (count && (!addresses || !address_lens))) return ENDPOINT_POOL_ERR_ARG;
    if (count > ENDPOINT_POOL_MAX) return ENDPOINT_POOL_ERR_FULL;
    for (size_t i = 0; i < count; ++i)
        if (address_lens[i] != 4 && address_lens[i] != 16) return ENDPOINT_POOL_ERR_ARG;

    uint8_t prev_good_address[16];
    uint8_t prev_good_len = 0;
    int have_prev_good = pool->count > 0 && pool->last_good != SIZE_MAX &&
        pool->last_good < pool->count;
    if (have_prev_good) {
        memcpy(prev_good_address, pool->entries[pool->last_good].address, 16);
        prev_good_len = pool->entries[pool->last_good].address_len;
    }

    endpoint_t next[ENDPOINT_POOL_MAX];
    memset(next, 0, sizeof next);
    size_t next_count = 0;
    for (size_t i = 0; i < count; ++i) {
        int duplicate = 0;
        for (size_t j = 0; j < next_count; ++j) {
            if (next[j].address_len == address_lens[i] &&
                memcmp(next[j].address, addresses[i], address_lens[i]) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;

        endpoint_t *slot = &next[next_count];
        memcpy(slot->address, addresses[i], address_lens[i]);
        slot->address_len = address_lens[i];
        for (size_t j = 0; j < pool->count; ++j) {
            endpoint_t *old = &pool->entries[j];
            if (old->address_len == slot->address_len &&
                memcmp(old->address, slot->address, slot->address_len) == 0) {
                slot->failures = old->failures;
                slot->cooldown_until_ms = old->cooldown_until_ms;
                slot->last_success_ms = old->last_success_ms;
                slot->last_attempt_ms = old->last_attempt_ms;
                break;
            }
        }
        ++next_count;
    }

    memcpy(pool->entries, next, sizeof next);
    pool->count = next_count;
    pool->last_good = SIZE_MAX;
    if (have_prev_good) {
        for (size_t i = 0; i < pool->count; ++i) {
            if (pool->entries[i].address_len == prev_good_len &&
                memcmp(pool->entries[i].address, prev_good_address, prev_good_len) == 0) {
                pool->last_good = i;
                break;
            }
        }
    }

    if (ttl_seconds < ENDPOINT_TTL_MIN_S) ttl_seconds = ENDPOINT_TTL_MIN_S;
    if (ttl_seconds > ENDPOINT_TTL_MAX_S) ttl_seconds = ENDPOINT_TTL_MAX_S;
    pool->resolved_at_ms = now_ms;
    pool->expires_at_ms = now_ms + (uint64_t)ttl_seconds * 1000u;
    return ENDPOINT_POOL_OK;
}

endpoint_pool_status_t endpoint_pool_select(const endpoint_pool_t *pool, uint64_t now_ms,
    uint8_t *out_address, uint8_t *out_address_len, size_t *out_index) {
    if (!pool || !out_address || !out_address_len || !out_index) return ENDPOINT_POOL_ERR_ARG;
    if (pool->count == 0) {
        *out_address_len = 0;
        *out_index = SIZE_MAX;
        return ENDPOINT_POOL_EMPTY;
    }

    size_t chosen = SIZE_MAX;
    if (pool->last_good != SIZE_MAX && pool->last_good < pool->count &&
        pool->entries[pool->last_good].cooldown_until_ms <= now_ms)
        chosen = pool->last_good;

    if (chosen == SIZE_MAX) {
        for (size_t i = 0; i < pool->count; ++i) {
            if (pool->entries[i].cooldown_until_ms <= now_ms) {
                chosen = i;
                break;
            }
        }
    }

    if (chosen == SIZE_MAX) {
        chosen = 0;
        for (size_t i = 1; i < pool->count; ++i)
            if (pool->entries[i].cooldown_until_ms < pool->entries[chosen].cooldown_until_ms)
                chosen = i;
    }

    const endpoint_t *ep = &pool->entries[chosen];
    memcpy(out_address, ep->address, ep->address_len);
    *out_address_len = ep->address_len;
    *out_index = chosen;
    return ENDPOINT_POOL_OK;
}

void endpoint_pool_mark_success(endpoint_pool_t *pool, size_t index, uint64_t now_ms) {
    if (!pool || index >= pool->count) return;
    endpoint_t *ep = &pool->entries[index];
    ep->failures = 0;
    ep->cooldown_until_ms = 0;
    ep->last_success_ms = now_ms;
    ep->last_attempt_ms = now_ms;
    pool->last_good = index;
}

void endpoint_pool_mark_failure(endpoint_pool_t *pool, size_t index, uint64_t now_ms) {
    if (!pool || index >= pool->count) return;
    endpoint_t *ep = &pool->entries[index];
    ep->last_attempt_ms = now_ms;
    ++ep->failures;
    uint64_t shift = ep->failures - 1;
    if (shift > 6) shift = 6; /* base << 6 already clears the max cap, no need to shift further */
    uint64_t cooldown = ENDPOINT_COOLDOWN_BASE_MS << shift;
    if (cooldown > ENDPOINT_COOLDOWN_MAX_MS) cooldown = ENDPOINT_COOLDOWN_MAX_MS;
    ep->cooldown_until_ms = now_ms + cooldown;
}

int endpoint_pool_expired(const endpoint_pool_t *pool, uint64_t now_ms) {
    if (!pool || pool->count == 0) return 1;
    return now_ms >= pool->expires_at_ms;
}
