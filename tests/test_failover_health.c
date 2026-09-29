#include "probe_stats.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static void reset(failover_candidate_t *list, size_t count) {
    memset(list, 0, sizeof *list * count);
    for (size_t i = 0; i < count; ++i) {
        list[i].in_group = 1;
        list[i].median_ms = PROBE_LATENCY_UNAVAILABLE;
    }
}

int main(void) {
    failover_candidate_t list[5];

    /* an empty group has nothing to pick */
    ok("an empty list picks nothing", failover_pick(NULL, 0, 0) == SIZE_MAX);
    reset(list, 5);
    for (size_t i = 0; i < 5; ++i) list[i].in_group = 0;
    ok("a group with no members picks nothing",
       failover_pick(list, 5, 0) == SIZE_MAX);

    /* the explicit user choice wins over a faster measured server */
    reset(list, 5);
    list[3].user_selected = 1;
    list[0].median_ms = 10;
    list[1].median_ms = 20;
    ok("the user choice comes first", failover_pick(list, 5, 0) == 3);

    /* with no user choice, the last working server comes before latency */
    reset(list, 5);
    list[2].last_working = 1;
    list[0].median_ms = 10;
    ok("the last working server comes before a faster one",
       failover_pick(list, 5, 0) == 2);

    /* then measured servers, fastest median first */
    reset(list, 5);
    list[0].median_ms = 300;
    list[1].median_ms = 90;
    list[2].median_ms = 150;
    ok("the fastest measured server is picked", failover_pick(list, 5, 0) == 1);

    /* a measured server beats an unmeasured one */
    reset(list, 5);
    list[4].median_ms = 400;
    ok("a measured server beats an unmeasured one",
       failover_pick(list, 5, 0) == 4);

    /* unmeasured servers are tried before servers in cooldown */
    reset(list, 5);
    list[0].median_ms = 50;
    list[0].cooldown_until_ms = 10000;
    ok("an unmeasured server is tried before one in cooldown",
       failover_pick(list, 5, 1000) == 1);

    /* when everything is in cooldown, the one recovering soonest is picked
       rather than failing the attempt outright */
    reset(list, 5);
    for (size_t i = 0; i < 5; ++i) list[i].cooldown_until_ms = 9000 + i * 100;
    list[3].cooldown_until_ms = 5000;
    ok("all in cooldown picks the one recovering soonest",
       failover_pick(list, 5, 1000) == 3);

    /* a cooldown that has passed is no longer a cooldown */
    reset(list, 5);
    list[0].cooldown_until_ms = 500;
    list[0].median_ms = 20;
    list[1].median_ms = 800;
    ok("an expired cooldown returns the server to normal order",
       failover_pick(list, 5, 1000) == 0);

    /* failover never leaves the selected group, even for a faster server */
    reset(list, 5);
    list[0].in_group = 0;
    list[0].median_ms = 5;
    list[0].user_selected = 1;
    list[2].median_ms = 500;
    ok("a faster server outside the group is not picked",
       failover_pick(list, 5, 0) == 2);

    /* a user selected server that is in cooldown does not jump the queue */
    reset(list, 5);
    list[1].user_selected = 1;
    list[1].cooldown_until_ms = 9000;
    list[2].median_ms = 300;
    ok("a user choice in cooldown yields to a usable server",
       failover_pick(list, 5, 1000) == 2);

    /* a new physical network clears the cooldowns the old one produced */
    reset(list, 5);
    for (size_t i = 0; i < 5; ++i) {
        list[i].cooldown_until_ms = 60000;
        list[i].failures = 3;
    }
    list[2].median_ms = 100;
    failover_reset_cooldowns(list, 5);
    ok("a network change clears every cooldown",
       list[0].cooldown_until_ms == 0 && list[4].cooldown_until_ms == 0);
    ok("a network change clears the failure counters", list[0].failures == 0);
    ok("the measured server is usable again right away",
       failover_pick(list, 5, 1000) == 2);

    /* ties resolve to the lowest index so a refresh does not reshuffle the
       order the user sees */
    reset(list, 5);
    list[1].median_ms = 120;
    list[3].median_ms = 120;
    ok("a latency tie resolves to the lowest index",
       failover_pick(list, 5, 0) == 1);

    reset(list, 5);
    list[2].last_working = 1;
    list[4].last_working = 1;
    ok("two last working entries resolve to the lowest index",
       failover_pick(list, 5, 0) == 2);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all failover health checks passed");
    return 0;
}
