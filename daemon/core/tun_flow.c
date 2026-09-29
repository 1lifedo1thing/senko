#include "tun_flow.h"

#include <string.h>

static size_t clamp_limit(size_t requested, size_t cap) {
    if (requested == 0 || requested > cap) return cap;
    return requested;
}

void tun_flow_table_init(tun_flow_table_t *table, size_t tcp_limit, size_t udp_limit) {
    if (!table) return;
    memset(table, 0, sizeof *table);
    table->tcp_limit = clamp_limit(tcp_limit, TUN_FLOW_MAX_TCP);
    table->udp_limit = clamp_limit(udp_limit, TUN_FLOW_MAX_UDP);
}

const char *tun_flow_close_name(tun_flow_close_t reason) {
    switch (reason) {
    case TUN_FLOW_CLOSE_NONE:      return "none";
    case TUN_FLOW_CLOSE_CLIENT:    return "client";
    case TUN_FLOW_CLOSE_REMOTE:    return "remote";
    case TUN_FLOW_CLOSE_BLOCKED:   return "blocked";
    case TUN_FLOW_CLOSE_IDLE:      return "idle";
    case TUN_FLOW_CLOSE_EVICTED:   return "evicted";
    case TUN_FLOW_CLOSE_CANCELLED: return "cancelled";
    case TUN_FLOW_CLOSE_STALE_GENERATION: return "stale-generation";
    case TUN_FLOW_CLOSE_ERROR:     return "error";
    }
    return "unknown";
}

static int key_equal(const tun_flow_key_t *a, const tun_flow_key_t *b) {
    return a->protocol == b->protocol && a->address_len == b->address_len &&
        a->source_port == b->source_port &&
        a->destination_port == b->destination_port &&
        memcmp(a->source, b->source, a->address_len) == 0 &&
        memcmp(a->destination, b->destination, a->address_len) == 0;
}

static tun_flow_t *slots_for(tun_flow_table_t *table, uint8_t protocol, size_t *cap) {
    if (protocol == TUN_FLOW_UDP) {
        *cap = table->udp_limit;
        return table->udp;
    }
    *cap = table->tcp_limit;
    return table->tcp;
}

size_t tun_flow_count(const tun_flow_table_t *table, tun_flow_proto_t protocol) {
    if (!table) return 0;
    return protocol == TUN_FLOW_UDP ? table->udp_count : table->tcp_count;
}

tun_flow_t *tun_flow_find(tun_flow_table_t *table, const tun_flow_key_t *key) {
    if (!table || !key) return NULL;
    if (key->address_len != 4 && key->address_len != 16) return NULL;
    size_t cap = 0;
    tun_flow_t *slots = slots_for(table, key->protocol, &cap);
    for (size_t i = 0; i < cap; ++i) {
        if (slots[i].state == TUN_FLOW_STATE_FREE) continue;
        if (key_equal(&slots[i].key, key)) return &slots[i];
    }
    return NULL;
}

/* the association that has gone without traffic the longest, lowest slot
   breaking a tie so the choice is repeatable in a test */
static tun_flow_t *oldest_used(tun_flow_t *slots, size_t cap) {
    tun_flow_t *oldest = NULL;
    for (size_t i = 0; i < cap; ++i) {
        if (slots[i].state == TUN_FLOW_STATE_FREE) continue;
        if (!oldest || slots[i].last_activity_ms < oldest->last_activity_ms)
            oldest = &slots[i];
    }
    return oldest;
}

static void release(tun_flow_table_t *table, tun_flow_t *flow, tun_flow_close_t reason) {
    uint8_t protocol = flow->key.protocol;
    memset(flow, 0, sizeof *flow);
    flow->state = TUN_FLOW_STATE_FREE;
    flow->close_reason = reason;
    if (protocol == TUN_FLOW_UDP) {
        if (table->udp_count) --table->udp_count;
    } else if (table->tcp_count) {
        --table->tcp_count;
    }
    ++table->closed;
}

tun_flow_status_t tun_flow_open(tun_flow_table_t *table, const tun_flow_key_t *key,
                                rule_action_t policy, uint64_t server_generation,
                                uint64_t now_ms, tun_flow_t **out_flow) {
    if (out_flow) *out_flow = NULL;
    if (!table || !key || !out_flow) return TUN_FLOW_ERR_ARG;
    if (key->address_len != 4 && key->address_len != 16) return TUN_FLOW_ERR_ARG;
    if (key->protocol != TUN_FLOW_TCP && key->protocol != TUN_FLOW_UDP)
        return TUN_FLOW_ERR_ARG;

    if (policy == RULE_ACTION_BLOCK) {
        ++table->blocked;
        return TUN_FLOW_ERR_BLOCKED;
    }

    tun_flow_t *existing = tun_flow_find(table, key);
    if (existing) {
        tun_flow_touch(existing, now_ms);
        *out_flow = existing;
        return TUN_FLOW_OK;
    }

    size_t cap = 0;
    tun_flow_t *slots = slots_for(table, key->protocol, &cap);
    tun_flow_t *slot = NULL;
    for (size_t i = 0; i < cap; ++i) {
        if (slots[i].state == TUN_FLOW_STATE_FREE) {
            slot = &slots[i];
            break;
        }
    }

    if (!slot) {
        /* a full tcp table refuses, because tearing down a live stream to
           admit a new one loses data the peer believes was delivered. a full
           udp table evicts its oldest binding instead, which at worst costs a
           reply to a datagram nobody is waiting on any more */
        if (key->protocol != TUN_FLOW_UDP) {
            ++table->refused;
            return TUN_FLOW_ERR_FULL;
        }
        slot = oldest_used(slots, cap);
        if (!slot) {
            ++table->refused;
            return TUN_FLOW_ERR_FULL;
        }
        release(table, slot, TUN_FLOW_CLOSE_EVICTED);
        ++table->evicted;
    }

    memset(slot, 0, sizeof *slot);
    slot->key = *key;
    slot->state = TUN_FLOW_STATE_OPENING;
    slot->policy = policy;
    slot->server_generation = server_generation;
    slot->opened_at_ms = now_ms;
    slot->last_activity_ms = now_ms;
    slot->queue_limit = TUN_FLOW_QUEUE_MIN;
    slot->close_reason = TUN_FLOW_CLOSE_NONE;

    if (key->protocol == TUN_FLOW_UDP) ++table->udp_count;
    else ++table->tcp_count;
    ++table->opened;

    *out_flow = slot;
    return TUN_FLOW_OK;
}

void tun_flow_touch(tun_flow_t *flow, uint64_t now_ms) {
    if (!flow || flow->state == TUN_FLOW_STATE_FREE) return;
    flow->last_activity_ms = now_ms;
}

/* the queue grows on demand up to the maximum before it reports back
   pressure, so a fast flow is not held to the small starting budget while an
   idle one keeps it */
static tun_flow_status_t queue_bytes(size_t *queued, size_t *limit, size_t bytes) {
    if (*limit == 0) *limit = TUN_FLOW_QUEUE_MIN;
    size_t next = *queued + bytes;
    if (next < *queued) return TUN_FLOW_ERR_QUEUE; /* size_t wrap */
    if (next > *limit) {
        if (next > TUN_FLOW_QUEUE_MAX) return TUN_FLOW_ERR_QUEUE;
        size_t grown = *limit;
        while (grown < next) grown *= 2u;
        if (grown > TUN_FLOW_QUEUE_MAX) grown = TUN_FLOW_QUEUE_MAX;
        *limit = grown;
    }
    *queued = next;
    return TUN_FLOW_OK;
}

tun_flow_status_t tun_flow_queue_to_server(tun_flow_t *flow, size_t bytes) {
    if (!flow || flow->state == TUN_FLOW_STATE_FREE) return TUN_FLOW_ERR_ARG;
    return queue_bytes(&flow->queued_to_server, &flow->queue_limit, bytes);
}

tun_flow_status_t tun_flow_queue_to_client(tun_flow_t *flow, size_t bytes) {
    if (!flow || flow->state == TUN_FLOW_STATE_FREE) return TUN_FLOW_ERR_ARG;
    return queue_bytes(&flow->queued_to_client, &flow->queue_limit, bytes);
}

void tun_flow_drain_to_server(tun_flow_t *flow, size_t bytes) {
    if (!flow) return;
    flow->queued_to_server = bytes >= flow->queued_to_server
        ? 0 : flow->queued_to_server - bytes;
}

void tun_flow_drain_to_client(tun_flow_t *flow, size_t bytes) {
    if (!flow) return;
    flow->queued_to_client = bytes >= flow->queued_to_client
        ? 0 : flow->queued_to_client - bytes;
}

int tun_flow_backpressured_to_server(const tun_flow_t *flow) {
    if (!flow) return 0;
    return flow->queued_to_server >= flow->queue_limit;
}

int tun_flow_backpressured_to_client(const tun_flow_t *flow) {
    if (!flow) return 0;
    return flow->queued_to_client >= flow->queue_limit;
}

tun_flow_status_t tun_flow_accept_generation(tun_flow_table_t *table, tun_flow_t *flow,
                                             uint64_t server_generation) {
    if (!table || !flow || flow->state == TUN_FLOW_STATE_FREE) return TUN_FLOW_ERR_ARG;
    if (flow->server_generation != server_generation) {
        ++table->stale_rejected;
        return TUN_FLOW_ERR_STALE;
    }
    if (flow->cancelled) return TUN_FLOW_ERR_STALE;
    return TUN_FLOW_OK;
}

void tun_flow_cancel(tun_flow_t *flow) {
    if (!flow || flow->state == TUN_FLOW_STATE_FREE) return;
    flow->cancelled = 1;
}

void tun_flow_close(tun_flow_table_t *table, tun_flow_t *flow, tun_flow_close_t reason) {
    if (!table || !flow || flow->state == TUN_FLOW_STATE_FREE) return;
    release(table, flow, reason);
}

static int idle_for(const tun_flow_t *flow, uint64_t now_ms, uint64_t idle_ms) {
    /* a clock that moved backwards must not expire every flow at once */
    if (now_ms < flow->last_activity_ms) return 0;
    return now_ms - flow->last_activity_ms >= idle_ms;
}

size_t tun_flow_expire_idle(tun_flow_table_t *table, uint64_t now_ms,
                            uint64_t tcp_idle_ms, uint64_t udp_idle_ms) {
    if (!table) return 0;
    size_t closed = 0;
    for (size_t i = 0; i < table->tcp_limit; ++i) {
        tun_flow_t *flow = &table->tcp[i];
        if (flow->state == TUN_FLOW_STATE_FREE) continue;
        if (!idle_for(flow, now_ms, tcp_idle_ms)) continue;
        release(table, flow, TUN_FLOW_CLOSE_IDLE);
        ++closed;
    }
    for (size_t i = 0; i < table->udp_limit; ++i) {
        tun_flow_t *flow = &table->udp[i];
        if (flow->state == TUN_FLOW_STATE_FREE) continue;
        if (!idle_for(flow, now_ms, udp_idle_ms)) continue;
        release(table, flow, TUN_FLOW_CLOSE_IDLE);
        ++closed;
    }
    return closed;
}

size_t tun_flow_close_generation(tun_flow_table_t *table, uint64_t server_generation) {
    if (!table) return 0;
    size_t closed = 0;
    for (size_t i = 0; i < table->tcp_limit; ++i) {
        tun_flow_t *flow = &table->tcp[i];
        if (flow->state == TUN_FLOW_STATE_FREE) continue;
        if (flow->server_generation == server_generation) continue;
        release(table, flow, TUN_FLOW_CLOSE_STALE_GENERATION);
        ++closed;
    }
    for (size_t i = 0; i < table->udp_limit; ++i) {
        tun_flow_t *flow = &table->udp[i];
        if (flow->state == TUN_FLOW_STATE_FREE) continue;
        if (flow->server_generation == server_generation) continue;
        release(table, flow, TUN_FLOW_CLOSE_STALE_GENERATION);
        ++closed;
    }
    return closed;
}
