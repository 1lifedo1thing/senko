#ifndef SENKO_PROBE_STATS_H
#define SENKO_PROBE_STATS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* what the server list calls ping: the time a full protocol handshake takes,
   broken down per stage, never the time a tcp port takes to answer and never
   the time the local socks listener takes to reply. samples carry the network
   generation they were measured on, so a handover invalidates them instead of
   leaving a number from the old network on screen */

#define PROBE_SAMPLE_MAX 8
#define PROBE_MIN_SAMPLES 2
#define PROBE_PARALLEL_ARMV7 3
#define PROBE_PARALLEL_ARM64 4
#define PROBE_LATENCY_UNAVAILABLE UINT32_MAX

typedef enum {
    PROBE_STAGE_NONE = 0, /* nothing failed */
    PROBE_STAGE_DNS,
    PROBE_STAGE_CONNECT,
    PROBE_STAGE_TRANSPORT, /* tls, reality, websocket, grpc, xhttp */
    PROBE_STAGE_PROTOCOL,  /* vless, trojan, shadowsocks authentication */
    PROBE_STAGE_CARRY
} probe_stage_t;

typedef struct {
    uint32_t dns_ms;
    uint32_t connect_ms;
    uint32_t transport_ms;
    uint32_t protocol_ms;
    uint32_t carry_ms;
    probe_stage_t failed_stage; /* PROBE_STAGE_NONE when the handshake finished */
    int      success;
    uint64_t at_ms;
    uint64_t network_generation;
} probe_sample_t;

typedef struct {
    probe_sample_t samples[PROBE_SAMPLE_MAX];
    size_t   count;
    size_t   next;
    uint64_t successes;
    uint64_t failures;
    uint64_t last_success_ms;
    probe_stage_t last_failed_stage;
} probe_history_t;

void probe_history_init(probe_history_t *history);
void probe_history_add(probe_history_t *history, const probe_sample_t *sample);

/* everything up to and including the protocol handshake. the carry probe is
   an extra proof, not part of the number the list shows */
uint32_t probe_sample_handshake_ms(const probe_sample_t *sample);

/* the median of the successful samples taken on this network generation, or
   PROBE_LATENCY_UNAVAILABLE when fewer than PROBE_MIN_SAMPLES exist. an even
   count takes the lower of the two middle samples, so the number shown is one
   that was actually measured */
uint32_t probe_history_median_ms(const probe_history_t *history,
                                 uint64_t network_generation);

/* how many probes may run at once on this slice */
size_t probe_parallel_limit(int arm64);

const char *probe_stage_name(probe_stage_t stage);

/* one server as the failover order sees it */
typedef struct {
    int      user_selected;
    int      in_group;        /* failover never leaves the selected group */
    int      last_working;
    uint32_t median_ms;       /* PROBE_LATENCY_UNAVAILABLE when unmeasured */
    uint64_t cooldown_until_ms;
    uint64_t failures;
} failover_candidate_t;

/* the explicit user choice, then the last working server, then measured
   servers by median, then unmeasured ones, and only then a server still in
   cooldown. returns SIZE_MAX when the group is empty */
size_t failover_pick(const failover_candidate_t *candidates, size_t count,
                     uint64_t now_ms);

/* a new physical network clears every cooldown: the addresses that failed on
   the old one say nothing about this one */
void failover_reset_cooldowns(failover_candidate_t *candidates, size_t count);

#ifdef __cplusplus
}
#endif

#endif
