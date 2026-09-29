#include "endpoint_pool.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

int main(void) {
    endpoint_pool_t pool;
    endpoint_pool_init(&pool);

    uint8_t addrs[3][16] = { { 0 } };
    uint8_t lens[3] = { 4, 4, 4 };
    addrs[0][0] = 203; addrs[0][1] = 0; addrs[0][2] = 113; addrs[0][3] = 1;
    addrs[1][0] = 203; addrs[1][1] = 0; addrs[1][2] = 113; addrs[1][3] = 2;
    addrs[2][0] = 203; addrs[2][1] = 0; addrs[2][2] = 113; addrs[2][3] = 3;

    ok("resolve ok", endpoint_pool_set_resolved(&pool, addrs, lens, 3, 1000, 60) ==
       ENDPOINT_POOL_OK);
    ok("count matches", pool.count == 3);
    ok("ttl clamped low end kept", pool.expires_at_ms == 1000 + 60u * 1000u);
    ok("not expired right after resolve", !endpoint_pool_expired(&pool, 1000));
    ok("expired well past ttl", endpoint_pool_expired(&pool, 1000 + 61u * 1000u));

    uint8_t out_addr[16];
    uint8_t out_len;
    size_t out_index;
    ok("select first when nothing tried",
       endpoint_pool_select(&pool, 1000, out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK &&
       out_index == 0);

    /* first endpoint address dead: failure sends selection to the next one */
    endpoint_pool_mark_failure(&pool, 0, 1000);
    ok("select skips failed first address",
       endpoint_pool_select(&pool, 1000, out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK &&
       out_index == 1);

    endpoint_pool_mark_success(&pool, 1, 1000);
    ok("last good sticks after success",
       endpoint_pool_select(&pool, 1000, out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK &&
       out_index == 1);

    /* a later transient failure of the known good address still yields to
       cooldown, but does not forget it was ever good */
    endpoint_pool_mark_failure(&pool, 1, 2000);
    ok("known good yields during its own cooldown",
       endpoint_pool_select(&pool, 2000, out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK &&
       out_index != 1);
    ok("known good returns once its cooldown passes",
       endpoint_pool_select(&pool, 2000 + ENDPOINT_COOLDOWN_BASE_MS + 1,
                            out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK &&
       out_index == 1);

    /* everything in cooldown: pick whichever recovers soonest, not an error */
    endpoint_pool_mark_failure(&pool, 0, 5000);
    endpoint_pool_mark_failure(&pool, 1, 5000);
    endpoint_pool_mark_failure(&pool, 2, 5000);
    ok("all in cooldown still returns a pick",
       endpoint_pool_select(&pool, 5000, out_addr, &out_len, &out_index) == ENDPOINT_POOL_OK);

    /* cooldown grows with repeated failures, bounded by the max */
    endpoint_pool_t backoff;
    endpoint_pool_init(&backoff);
    endpoint_pool_set_resolved(&backoff, addrs, lens, 1, 0, 60);
    uint64_t prev_cooldown = 0;
    int grew_each_time = 1;
    for (int i = 0; i < 10; ++i) {
        endpoint_pool_mark_failure(&backoff, 0, 0);
        uint64_t cd = backoff.entries[0].cooldown_until_ms;
        if (i > 0 && cd < prev_cooldown) grew_each_time = 0;
        prev_cooldown = cd;
    }
    ok("cooldown grows or holds each failure", grew_each_time);
    ok("cooldown capped", backoff.entries[0].cooldown_until_ms <= ENDPOINT_COOLDOWN_MAX_MS);

    /* re-resolving keeps failure state for an address that reappears */
    endpoint_pool_t reresolve;
    endpoint_pool_init(&reresolve);
    endpoint_pool_set_resolved(&reresolve, addrs, lens, 2, 0, 60);
    endpoint_pool_mark_failure(&reresolve, 0, 0);
    uint64_t cooldown_before = reresolve.entries[0].cooldown_until_ms;
    endpoint_pool_set_resolved(&reresolve, addrs, lens, 2, 100, 60);
    ok("cooldown survives re-resolve for an address that stays",
       reresolve.entries[0].cooldown_until_ms == cooldown_before);

    /* an address dropped by the new dns answer drops its state too, and the
       one that stays keeps its own index-independent identity by address */
    uint8_t two_of_three[2][16];
    uint8_t two_lens[2] = { 4, 4 };
    memcpy(two_of_three[0], addrs[2], 16);
    memcpy(two_of_three[1], addrs[1], 16);
    endpoint_pool_t reordered;
    endpoint_pool_init(&reordered);
    endpoint_pool_set_resolved(&reordered, addrs, lens, 3, 0, 60);
    endpoint_pool_mark_success(&reordered, 1, 0); /* addrs[1] becomes last_good */
    endpoint_pool_set_resolved(&reordered, two_of_three, two_lens, 2, 200, 60);
    ok("last good tracked by address across reorder",
       reordered.entries[reordered.last_good].address[3] == 2);

    /* duplicate addresses in one dns answer collapse into a single entry */
    endpoint_pool_t dup;
    endpoint_pool_init(&dup);
    uint8_t dup_addrs[2][16] = { { 0 } };
    uint8_t dup_lens[2] = { 4, 4 };
    dup_addrs[0][0] = 203; dup_addrs[0][3] = 9;
    memcpy(dup_addrs[1], dup_addrs[0], 16);
    ok("duplicate resolved addresses collapse",
       endpoint_pool_set_resolved(&dup, dup_addrs, dup_lens, 2, 0, 60) == ENDPOINT_POOL_OK &&
       dup.count == 1);

    /* an empty pool selects nothing rather than reading garbage */
    endpoint_pool_t empty;
    endpoint_pool_init(&empty);
    ok("empty pool select reports empty",
       endpoint_pool_select(&empty, 0, out_addr, &out_len, &out_index) == ENDPOINT_POOL_EMPTY);
    ok("empty pool reports expired", endpoint_pool_expired(&empty, 0));

    /* ttl is clamped into the bounded window, not trusted verbatim */
    endpoint_pool_t clamp;
    endpoint_pool_init(&clamp);
    endpoint_pool_set_resolved(&clamp, addrs, lens, 1, 0, 1);
    ok("ttl clamped up to the minimum", clamp.expires_at_ms == ENDPOINT_TTL_MIN_S * 1000u);
    endpoint_pool_set_resolved(&clamp, addrs, lens, 1, 0, 999999);
    ok("ttl clamped down to the maximum", clamp.expires_at_ms == ENDPOINT_TTL_MAX_S * 1000u);

    /* more addresses than the pool can hold is rejected, not truncated silently */
    uint8_t too_many[ENDPOINT_POOL_MAX + 1][16] = { { 0 } };
    uint8_t too_many_lens[ENDPOINT_POOL_MAX + 1];
    for (size_t i = 0; i < ENDPOINT_POOL_MAX + 1; ++i) {
        too_many[i][3] = (uint8_t)(i + 1);
        too_many_lens[i] = 4;
    }
    endpoint_pool_t full;
    endpoint_pool_init(&full);
    ok("over-capacity resolve rejected",
       endpoint_pool_set_resolved(&full, too_many, too_many_lens, ENDPOINT_POOL_MAX + 1, 0, 60) ==
       ENDPOINT_POOL_ERR_FULL);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all endpoint_pool checks passed");
    return 0;
}
