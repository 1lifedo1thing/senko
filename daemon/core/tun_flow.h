#ifndef SENKO_TUN_FLOW_H
#define SENKO_TUN_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "rules.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the flow table for the utun backend: an immutable key per flow, the policy
   it was opened under, the server generation it belongs to, and how much is
   queued in each direction. no sockets and no packet bytes live here, so the
   limits and the eviction order can be tested on the host */

/* compile-time hard caps hold the worst case the arm64 build may reach, the
   runtime limits passed to init are what an armv7 device actually gets */
#define TUN_FLOW_MAX_TCP 64
#define TUN_FLOW_MAX_UDP 128
#define TUN_FLOW_TCP_LIMIT_ARMV7 32
#define TUN_FLOW_UDP_LIMIT_ARMV7 64
#define TUN_FLOW_QUEUE_MIN 16384u
#define TUN_FLOW_QUEUE_MAX 65536u

typedef enum {
    TUN_FLOW_TCP = 0,
    TUN_FLOW_UDP
} tun_flow_proto_t;

typedef struct {
    uint8_t  source[16];
    uint8_t  destination[16];
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t  address_len; /* 4 or 16 */
    uint8_t  protocol;    /* tun_flow_proto_t */
} tun_flow_key_t;

typedef enum {
    TUN_FLOW_STATE_FREE = 0,
    TUN_FLOW_STATE_OPENING, /* waiting on the server handshake */
    TUN_FLOW_STATE_OPEN,
    TUN_FLOW_STATE_HALF_CLOSED_CLIENT,
    TUN_FLOW_STATE_HALF_CLOSED_REMOTE,
    TUN_FLOW_STATE_CLOSED
} tun_flow_state_t;

/* a flow never just disappears: every removal names why, so a counter in
   diagnostics can separate an idle timeout from an eviction from a reset */
typedef enum {
    TUN_FLOW_CLOSE_NONE = 0,
    TUN_FLOW_CLOSE_CLIENT,
    TUN_FLOW_CLOSE_REMOTE,
    TUN_FLOW_CLOSE_BLOCKED,
    TUN_FLOW_CLOSE_IDLE,
    TUN_FLOW_CLOSE_EVICTED,
    TUN_FLOW_CLOSE_CANCELLED,
    TUN_FLOW_CLOSE_STALE_GENERATION,
    TUN_FLOW_CLOSE_ERROR
} tun_flow_close_t;

typedef struct {
    tun_flow_key_t   key;
    tun_flow_state_t state;
    rule_action_t    policy;
    uint64_t         server_generation;
    uint64_t         opened_at_ms;
    uint64_t         last_activity_ms;
    size_t           queued_to_server;
    size_t           queued_to_client;
    size_t           queue_limit;
    int              cancelled;
    tun_flow_close_t close_reason;
} tun_flow_t;

typedef struct {
    tun_flow_t tcp[TUN_FLOW_MAX_TCP];
    tun_flow_t udp[TUN_FLOW_MAX_UDP];
    size_t     tcp_limit;
    size_t     udp_limit;
    size_t     tcp_count;
    size_t     udp_count;
    uint64_t   opened;
    uint64_t   closed;
    uint64_t   refused;   /* tcp flows the table had no room for */
    uint64_t   evicted;   /* udp associations dropped to make room */
    uint64_t   blocked;   /* flows refused by policy */
    uint64_t   stale_rejected;
} tun_flow_table_t;

typedef enum {
    TUN_FLOW_OK        =  0,
    TUN_FLOW_ERR_ARG   = -1,
    TUN_FLOW_ERR_FULL  = -2, /* tcp table full, the caller must reset the flow */
    TUN_FLOW_ERR_BLOCKED = -3,
    TUN_FLOW_ERR_QUEUE = -4, /* queue limit reached, apply backpressure */
    TUN_FLOW_ERR_STALE = -5  /* result belongs to a superseded server generation */
} tun_flow_status_t;

/* limits above the compile-time caps are clamped down, zero means the cap */
void tun_flow_table_init(tun_flow_table_t *table, size_t tcp_limit, size_t udp_limit);

tun_flow_t *tun_flow_find(tun_flow_table_t *table, const tun_flow_key_t *key);

/* open a flow under an already decided policy. tcp refuses when full, udp
   evicts the association that has been idle longest, because dropping the
   oldest datagram binding beats refusing every new one */
tun_flow_status_t tun_flow_open(tun_flow_table_t *table, const tun_flow_key_t *key,
                                rule_action_t policy, uint64_t server_generation,
                                uint64_t now_ms, tun_flow_t **out_flow);

void tun_flow_touch(tun_flow_t *flow, uint64_t now_ms);

/* queue accounting in both directions. a full queue is reported, never
   silently dropped: tcp turns it into a closed window, udp into an error */
tun_flow_status_t tun_flow_queue_to_server(tun_flow_t *flow, size_t bytes);
tun_flow_status_t tun_flow_queue_to_client(tun_flow_t *flow, size_t bytes);
void tun_flow_drain_to_server(tun_flow_t *flow, size_t bytes);
void tun_flow_drain_to_client(tun_flow_t *flow, size_t bytes);
int  tun_flow_backpressured_to_server(const tun_flow_t *flow);
int  tun_flow_backpressured_to_client(const tun_flow_t *flow);

/* a worker result is only applied when it still belongs to the generation the
   flow was opened under */
tun_flow_status_t tun_flow_accept_generation(tun_flow_table_t *table, tun_flow_t *flow,
                                             uint64_t server_generation);

void tun_flow_cancel(tun_flow_t *flow);
void tun_flow_close(tun_flow_table_t *table, tun_flow_t *flow, tun_flow_close_t reason);

/* close everything idle for longer than idle_ms, oldest first, and return how
   many went. tcp and udp carry their own timeouts */
size_t tun_flow_expire_idle(tun_flow_table_t *table, uint64_t now_ms,
                            uint64_t tcp_idle_ms, uint64_t udp_idle_ms);

/* drop every flow that belongs to a superseded server generation, for a
   server switch that must not leave flows pointing at the old transport */
size_t tun_flow_close_generation(tun_flow_table_t *table, uint64_t server_generation);

size_t tun_flow_count(const tun_flow_table_t *table, tun_flow_proto_t protocol);

const char *tun_flow_close_name(tun_flow_close_t reason);

#ifdef __cplusplus
}
#endif

#endif
