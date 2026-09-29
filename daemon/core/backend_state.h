#ifndef SENKO_BACKEND_STATE_H
#define SENKO_BACKEND_STATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the utun backend state machine. every transition goes through one place so
   an attempt can be followed in diagnostics, and so the two rules that keep
   the ui honest cannot be bypassed: online needs a finished protocol
   handshake and a carry probe, and an open utun without a working server is
   degraded, not connected */

#define UTUN_REASON_MAX 96
#define UTUN_STATE_LOG_MAX 16

typedef enum {
    UTUN_IDLE = 0,
    UTUN_OPENING,
    UTUN_CONFIGURING,
    UTUN_PINNING_ENDPOINT,
    UTUN_INSTALLING_ROUTES,
    UTUN_STACK_READY,
    UTUN_SERVER_CHECKING,
    UTUN_ONLINE,
    UTUN_DEGRADED,
    UTUN_RECONNECTING,
    UTUN_STOPPING,
    UTUN_ERROR
} utun_state_t;

/* which layer a failure belongs to, so "it does not connect" can be answered
   without a packet capture */
typedef enum {
    UTUN_LAYER_NONE = 0,
    UTUN_LAYER_DEVICE,
    UTUN_LAYER_ROUTE,
    UTUN_LAYER_DNS,
    UTUN_LAYER_ENDPOINT,
    UTUN_LAYER_TLS,
    UTUN_LAYER_REALITY,
    UTUN_LAYER_TRANSPORT,
    UTUN_LAYER_PROTOCOL,
    UTUN_LAYER_CARRY,
    UTUN_LAYER_RESOURCE,
    UTUN_LAYER_CANCELLED
} utun_layer_t;

typedef struct {
    utun_state_t from;
    utun_state_t to;
    utun_layer_t layer;
    uint64_t     attempt_id;
    uint64_t     at_ms;
    char         reason[UTUN_REASON_MAX];
} utun_state_entry_t;

typedef struct {
    utun_state_t state;
    uint64_t     attempt_id;
    uint64_t     network_generation;
    uint64_t     server_generation;
    uint64_t     entered_state_ms;

    /* what the user asked for, kept across a network change and cleared only
       by an explicit disconnect */
    int user_wants_connected;

    int handshake_ok;
    int carry_ok;

    utun_layer_t failure_layer;
    char         failure_reason[UTUN_REASON_MAX];

    uint64_t reconnects;
    uint64_t transitions;
    uint64_t rejected_transitions;
    uint64_t stale_results;

    utun_state_entry_t log[UTUN_STATE_LOG_MAX];
    size_t log_count; /* entries written, saturating at the ring size */
    size_t log_next;
} utun_backend_state_t;

typedef enum {
    UTUN_BACKEND_OK         =  0,
    UTUN_BACKEND_ERR_ARG    = -1,
    UTUN_BACKEND_ERR_TRANSITION = -2, /* not reachable from the current state */
    UTUN_BACKEND_ERR_UNPROVEN   = -3  /* online asked for before it was proven */
} utun_backend_status_t;

void utun_backend_init(utun_backend_state_t *state);

/* the user asked to connect: starts a new attempt and clears the proof from
   the previous one */
utun_backend_status_t utun_backend_connect(utun_backend_state_t *state, uint64_t now_ms);

/* move one step along the bring-up. entering UTUN_ONLINE is refused unless
   both the handshake and the carry probe have been marked */
utun_backend_status_t utun_backend_advance(utun_backend_state_t *state,
                                           utun_state_t next, utun_layer_t layer,
                                           const char *reason, uint64_t now_ms);

/* an attempt failed at a named layer. lands in UTUN_ERROR, or in
   UTUN_DEGRADED when the tunnel itself is up and only the server is not */
utun_backend_status_t utun_backend_fail(utun_backend_state_t *state, utun_layer_t layer,
                                        const char *reason, uint64_t now_ms);

/* the user asked to stop: cancels any reconnect intent and ends at IDLE */
utun_backend_status_t utun_backend_disconnect(utun_backend_state_t *state,
                                              uint64_t now_ms);

/* the physical network changed: bumps the generation, keeps the user intent,
   and goes back to rebuilding pins and routes without reopening the device */
utun_backend_status_t utun_backend_network_changed(utun_backend_state_t *state,
                                                   uint64_t now_ms);

/* a different server was selected: bumps the server generation only, the
   device and its routes stay up */
utun_backend_status_t utun_backend_server_changed(utun_backend_state_t *state,
                                                  uint64_t now_ms);

void utun_backend_mark_handshake(utun_backend_state_t *state, int ok);
void utun_backend_mark_carry(utun_backend_state_t *state, int ok);

/* a worker result is stale when it was started for an older network. counted
   so a handover storm is visible in diagnostics */
int utun_backend_accepts_result(utun_backend_state_t *state,
                                uint64_t network_generation);

/* whether traffic may leave outside the tunnel. only a backend that is fully
   idle may, so a degraded or half built tunnel stays fail-closed instead of
   leaking around the proxy */
int utun_backend_allows_direct_traffic(const utun_backend_state_t *state);

/* whether the tunnel device and its routes are currently installed */
int utun_backend_tunnel_up(const utun_backend_state_t *state);

const char *utun_state_name(utun_state_t state);
const char *utun_layer_name(utun_layer_t layer);

#ifdef __cplusplus
}
#endif

#endif
