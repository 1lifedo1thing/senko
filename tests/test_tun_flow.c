#include "tun_flow.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static tun_flow_key_t key_v4(uint8_t protocol, uint8_t last_source_byte,
                             uint16_t source_port) {
    tun_flow_key_t key;
    memset(&key, 0, sizeof key);
    key.address_len = 4;
    key.protocol = protocol;
    key.source[0] = 192; key.source[1] = 0; key.source[2] = 2;
    key.source[3] = last_source_byte;
    key.destination[0] = 203; key.destination[2] = 113; key.destination[3] = 9;
    key.source_port = source_port;
    key.destination_port = 443;
    return key;
}

int main(void) {
    tun_flow_table_t table;

    /* a runtime limit below the compile cap is what an armv7 device gets */
    tun_flow_table_init(&table, TUN_FLOW_TCP_LIMIT_ARMV7, TUN_FLOW_UDP_LIMIT_ARMV7);
    ok("tcp runtime limit applied", table.tcp_limit == TUN_FLOW_TCP_LIMIT_ARMV7);
    ok("udp runtime limit applied", table.udp_limit == TUN_FLOW_UDP_LIMIT_ARMV7);

    tun_flow_table_init(&table, 0, 0);
    ok("zero limit means the compile cap",
       table.tcp_limit == TUN_FLOW_MAX_TCP && table.udp_limit == TUN_FLOW_MAX_UDP);

    tun_flow_table_init(&table, TUN_FLOW_MAX_TCP + 100, TUN_FLOW_MAX_UDP + 100);
    ok("a limit above the cap is clamped down",
       table.tcp_limit == TUN_FLOW_MAX_TCP && table.udp_limit == TUN_FLOW_MAX_UDP);

    /* open, find, and the identity of a flow key */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t key = key_v4(TUN_FLOW_TCP, 10, 40000);
    tun_flow_t *flow = NULL;
    ok("open ok",
       tun_flow_open(&table, &key, RULE_ACTION_PROXY, 7, 1000, &flow) == TUN_FLOW_OK);
    ok("open returns a flow", flow != NULL);
    ok("flow starts in opening", flow && flow->state == TUN_FLOW_STATE_OPENING);
    ok("flow carries the policy", flow && flow->policy == RULE_ACTION_PROXY);
    ok("flow carries the generation", flow && flow->server_generation == 7);
    ok("tcp counted", tun_flow_count(&table, TUN_FLOW_TCP) == 1);
    ok("udp untouched", tun_flow_count(&table, TUN_FLOW_UDP) == 0);
    ok("find returns the same flow", tun_flow_find(&table, &key) == flow);

    /* reopening the same key is the same flow, not a second one */
    tun_flow_t *again = NULL;
    ok("reopen returns the existing flow",
       tun_flow_open(&table, &key, RULE_ACTION_PROXY, 7, 1100, &again) == TUN_FLOW_OK &&
       again == flow && tun_flow_count(&table, TUN_FLOW_TCP) == 1);
    ok("reopen counts as activity", flow && flow->last_activity_ms == 1100);

    /* a different source port is a different flow */
    tun_flow_key_t other = key_v4(TUN_FLOW_TCP, 10, 40001);
    tun_flow_t *other_flow = NULL;
    ok("a different port opens a second flow",
       tun_flow_open(&table, &other, RULE_ACTION_PROXY, 7, 1100, &other_flow) ==
       TUN_FLOW_OK && other_flow != flow && tun_flow_count(&table, TUN_FLOW_TCP) == 2);

    /* a blocked policy never takes a slot */
    tun_flow_key_t blocked = key_v4(TUN_FLOW_TCP, 11, 40002);
    tun_flow_t *blocked_flow = NULL;
    ok("block refuses the flow",
       tun_flow_open(&table, &blocked, RULE_ACTION_BLOCK, 7, 1100, &blocked_flow) ==
       TUN_FLOW_ERR_BLOCKED && blocked_flow == NULL);
    ok("block is counted", table.blocked == 1);
    ok("block took no slot", tun_flow_count(&table, TUN_FLOW_TCP) == 2);

    /* a full tcp table refuses rather than killing a live stream */
    tun_flow_table_init(&table, 2, 2);
    tun_flow_key_t a = key_v4(TUN_FLOW_TCP, 10, 100);
    tun_flow_key_t b = key_v4(TUN_FLOW_TCP, 10, 101);
    tun_flow_key_t c = key_v4(TUN_FLOW_TCP, 10, 102);
    tun_flow_t *fa = NULL, *fb = NULL, *fc = NULL;
    tun_flow_open(&table, &a, RULE_ACTION_PROXY, 1, 100, &fa);
    tun_flow_open(&table, &b, RULE_ACTION_PROXY, 1, 200, &fb);
    ok("tcp table full refuses",
       tun_flow_open(&table, &c, RULE_ACTION_PROXY, 1, 300, &fc) == TUN_FLOW_ERR_FULL &&
       fc == NULL);
    ok("refusal counted", table.refused == 1);
    ok("the live flows survive a refusal",
       tun_flow_count(&table, TUN_FLOW_TCP) == 2 && tun_flow_find(&table, &a) == fa);

    /* a full udp table evicts the association idle longest, deterministically */
    tun_flow_key_t ua = key_v4(TUN_FLOW_UDP, 10, 200);
    tun_flow_key_t ub = key_v4(TUN_FLOW_UDP, 10, 201);
    tun_flow_key_t uc = key_v4(TUN_FLOW_UDP, 10, 202);
    tun_flow_t *ufa = NULL, *ufb = NULL, *ufc = NULL;
    tun_flow_open(&table, &ua, RULE_ACTION_PROXY, 1, 100, &ufa);
    tun_flow_open(&table, &ub, RULE_ACTION_PROXY, 1, 200, &ufb);
    tun_flow_touch(ufb, 500); /* b is the fresher one */
    ok("udp table full evicts instead of refusing",
       tun_flow_open(&table, &uc, RULE_ACTION_PROXY, 1, 600, &ufc) == TUN_FLOW_OK &&
       ufc != NULL);
    ok("eviction counted", table.evicted == 1);
    ok("the oldest association is the one that went",
       tun_flow_find(&table, &ua) == NULL && tun_flow_find(&table, &ub) != NULL);
    ok("udp count stays at the limit", tun_flow_count(&table, TUN_FLOW_UDP) == 2);

    /* queue accounting and backpressure in both directions */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t qkey = key_v4(TUN_FLOW_TCP, 12, 300);
    tun_flow_t *q = NULL;
    tun_flow_open(&table, &qkey, RULE_ACTION_PROXY, 1, 0, &q);
    ok("a new flow is not backpressured", !tun_flow_backpressured_to_server(q));
    ok("queueing inside the budget is accepted",
       tun_flow_queue_to_server(q, 1024) == TUN_FLOW_OK && q->queued_to_server == 1024);
    ok("queueing past the start budget grows it",
       tun_flow_queue_to_server(q, TUN_FLOW_QUEUE_MIN) == TUN_FLOW_OK &&
       q->queue_limit > TUN_FLOW_QUEUE_MIN);
    ok("queueing past the hard maximum is refused, not dropped",
       tun_flow_queue_to_server(q, TUN_FLOW_QUEUE_MAX) == TUN_FLOW_ERR_QUEUE);
    ok("a refused queue leaves the counter untouched",
       q->queued_to_server == 1024 + TUN_FLOW_QUEUE_MIN);

    tun_flow_drain_to_server(q, 1024);
    ok("draining reduces the queue", q->queued_to_server == TUN_FLOW_QUEUE_MIN);
    tun_flow_drain_to_server(q, 1024 * 1024);
    ok("draining past empty stops at zero", q->queued_to_server == 0);

    ok("the client direction has its own counter",
       tun_flow_queue_to_client(q, 2048) == TUN_FLOW_OK &&
       q->queued_to_client == 2048 && q->queued_to_server == 0);

    /* a stale worker result is rejected by generation */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t gkey = key_v4(TUN_FLOW_TCP, 13, 400);
    tun_flow_t *g = NULL;
    tun_flow_open(&table, &gkey, RULE_ACTION_PROXY, 5, 0, &g);
    ok("a result from the current generation is accepted",
       tun_flow_accept_generation(&table, g, 5) == TUN_FLOW_OK);
    ok("a result from an older generation is rejected",
       tun_flow_accept_generation(&table, g, 4) == TUN_FLOW_ERR_STALE);
    ok("stale results are counted", table.stale_rejected == 1);

    tun_flow_cancel(g);
    ok("a cancelled flow rejects its own generation too",
       tun_flow_accept_generation(&table, g, 5) == TUN_FLOW_ERR_STALE);

    /* closing frees the slot and names the reason */
    tun_flow_close(&table, g, TUN_FLOW_CLOSE_CLIENT);
    ok("close frees the slot", tun_flow_find(&table, &gkey) == NULL);
    ok("close is counted", table.closed == 1);
    ok("close keeps the reason for diagnostics",
       g->close_reason == TUN_FLOW_CLOSE_CLIENT);
    ok("closing an already closed flow does nothing",
       (tun_flow_close(&table, g, TUN_FLOW_CLOSE_REMOTE), table.closed == 1));

    /* idle expiry, with separate tcp and udp timeouts */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t tcp_idle = key_v4(TUN_FLOW_TCP, 14, 500);
    tun_flow_key_t udp_idle = key_v4(TUN_FLOW_UDP, 14, 501);
    tun_flow_key_t tcp_busy = key_v4(TUN_FLOW_TCP, 14, 502);
    tun_flow_t *ti = NULL, *ui = NULL, *tb = NULL;
    tun_flow_open(&table, &tcp_idle, RULE_ACTION_PROXY, 1, 0, &ti);
    tun_flow_open(&table, &udp_idle, RULE_ACTION_PROXY, 1, 0, &ui);
    tun_flow_open(&table, &tcp_busy, RULE_ACTION_PROXY, 1, 0, &tb);
    tun_flow_touch(tb, 50000);
    size_t expired = tun_flow_expire_idle(&table, 60000, 300000, 30000);
    ok("the udp association expired on its shorter timeout", expired == 1 &&
       tun_flow_find(&table, &udp_idle) == NULL);
    ok("the tcp flows survived their longer timeout",
       tun_flow_find(&table, &tcp_idle) != NULL &&
       tun_flow_find(&table, &tcp_busy) != NULL);

    expired = tun_flow_expire_idle(&table, 400000, 300000, 30000);
    ok("both tcp flows expire once past their timeout", expired == 2 &&
       tun_flow_count(&table, TUN_FLOW_TCP) == 0);

    /* a clock that jumped backwards must not expire everything at once */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_t *back = NULL;
    tun_flow_open(&table, &tcp_idle, RULE_ACTION_PROXY, 1, 100000, &back);
    ok("a backwards clock expires nothing",
       tun_flow_expire_idle(&table, 1000, 300000, 30000) == 0 &&
       tun_flow_count(&table, TUN_FLOW_TCP) == 1);

    /* a server switch drops flows from superseded generations only */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t old_gen = key_v4(TUN_FLOW_TCP, 15, 600);
    tun_flow_key_t new_gen = key_v4(TUN_FLOW_TCP, 15, 601);
    tun_flow_key_t old_udp = key_v4(TUN_FLOW_UDP, 15, 602);
    tun_flow_t *og = NULL, *ng = NULL, *ou = NULL;
    tun_flow_open(&table, &old_gen, RULE_ACTION_PROXY, 1, 0, &og);
    tun_flow_open(&table, &new_gen, RULE_ACTION_PROXY, 2, 0, &ng);
    tun_flow_open(&table, &old_udp, RULE_ACTION_PROXY, 1, 0, &ou);
    size_t dropped = tun_flow_close_generation(&table, 2);
    ok("flows from the old generation are dropped", dropped == 2);
    ok("the current generation survives a server switch",
       tun_flow_find(&table, &new_gen) != NULL &&
       tun_flow_find(&table, &old_gen) == NULL &&
       tun_flow_find(&table, &old_udp) == NULL);

    /* malformed keys are refused rather than keyed on garbage */
    tun_flow_table_init(&table, 4, 4);
    tun_flow_key_t bad = key_v4(TUN_FLOW_TCP, 16, 700);
    bad.address_len = 7;
    tun_flow_t *bad_flow = NULL;
    ok("a bad address length is refused",
       tun_flow_open(&table, &bad, RULE_ACTION_PROXY, 1, 0, &bad_flow) ==
       TUN_FLOW_ERR_ARG);
    bad = key_v4(TUN_FLOW_TCP, 16, 700);
    bad.protocol = 9;
    ok("an unknown protocol is refused",
       tun_flow_open(&table, &bad, RULE_ACTION_PROXY, 1, 0, &bad_flow) ==
       TUN_FLOW_ERR_ARG);

    /* the table can be filled to its exact limit and emptied again */
    tun_flow_table_init(&table, TUN_FLOW_TCP_LIMIT_ARMV7, 4);
    int filled_all = 1;
    for (size_t i = 0; i < TUN_FLOW_TCP_LIMIT_ARMV7; ++i) {
        tun_flow_key_t fill = key_v4(TUN_FLOW_TCP, 20, (uint16_t)(1000 + i));
        tun_flow_t *slot = NULL;
        if (tun_flow_open(&table, &fill, RULE_ACTION_PROXY, 1, 0, &slot) != TUN_FLOW_OK)
            filled_all = 0;
    }
    ok("the table fills to exactly its limit", filled_all &&
       tun_flow_count(&table, TUN_FLOW_TCP) == TUN_FLOW_TCP_LIMIT_ARMV7);
    tun_flow_expire_idle(&table, 1000000, 1, 1);
    ok("the table empties completely", tun_flow_count(&table, TUN_FLOW_TCP) == 0);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_flow checks passed");
    return 0;
}
