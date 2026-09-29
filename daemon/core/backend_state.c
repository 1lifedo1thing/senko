#include "backend_state.h"

#include <stdio.h>
#include <string.h>

const char *utun_state_name(utun_state_t state) {
    switch (state) {
    case UTUN_IDLE:              return "idle";
    case UTUN_OPENING:           return "opening";
    case UTUN_CONFIGURING:       return "configuring";
    case UTUN_PINNING_ENDPOINT:  return "pinning-endpoint";
    case UTUN_INSTALLING_ROUTES: return "installing-routes";
    case UTUN_STACK_READY:       return "stack-ready";
    case UTUN_SERVER_CHECKING:   return "server-checking";
    case UTUN_ONLINE:            return "online";
    case UTUN_DEGRADED:          return "degraded";
    case UTUN_RECONNECTING:      return "reconnecting";
    case UTUN_STOPPING:          return "stopping";
    case UTUN_ERROR:             return "error";
    }
    return "unknown";
}

const char *utun_layer_name(utun_layer_t layer) {
    switch (layer) {
    case UTUN_LAYER_NONE:      return "none";
    case UTUN_LAYER_DEVICE:    return "device";
    case UTUN_LAYER_ROUTE:     return "route";
    case UTUN_LAYER_DNS:       return "dns";
    case UTUN_LAYER_ENDPOINT:  return "endpoint";
    case UTUN_LAYER_TLS:       return "tls";
    case UTUN_LAYER_REALITY:   return "reality";
    case UTUN_LAYER_TRANSPORT: return "transport";
    case UTUN_LAYER_PROTOCOL:  return "protocol";
    case UTUN_LAYER_CARRY:     return "carry";
    case UTUN_LAYER_RESOURCE:  return "resource";
    case UTUN_LAYER_CANCELLED: return "cancelled";
    }
    return "unknown";
}

void utun_backend_init(utun_backend_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof *state);
    state->state = UTUN_IDLE;
}

int utun_backend_tunnel_up(const utun_backend_state_t *state) {
    if (!state) return 0;
    switch (state->state) {
    case UTUN_STACK_READY:
    case UTUN_SERVER_CHECKING:
    case UTUN_ONLINE:
    case UTUN_DEGRADED:
    case UTUN_RECONNECTING:
        return 1;
    default:
        return 0;
    }
}

int utun_backend_allows_direct_traffic(const utun_backend_state_t *state) {
    if (!state) return 0;
    /* anything past idle has either installed routes or is about to, and a
       half built or degraded tunnel that let traffic out would be the leak
       the split defaults exist to prevent */
    return state->state == UTUN_IDLE && !state->user_wants_connected;
}

static int transition_allowed(utun_state_t from, utun_state_t to) {
    if (to == UTUN_STOPPING) return from != UTUN_IDLE;
    /* the network can change at any point of a bring-up, not only once the
       tunnel is up. an attempt that is half way through pinning endpoints
       for the old gateway has to be able to restart on the new one */
    if (to == UTUN_RECONNECTING)
        return from != UTUN_IDLE && from != UTUN_STOPPING && from != UTUN_RECONNECTING;
    switch (from) {
    case UTUN_IDLE:
        return to == UTUN_OPENING;
    case UTUN_OPENING:
        return to == UTUN_CONFIGURING || to == UTUN_ERROR;
    case UTUN_CONFIGURING:
        return to == UTUN_PINNING_ENDPOINT || to == UTUN_ERROR;
    case UTUN_PINNING_ENDPOINT:
        return to == UTUN_INSTALLING_ROUTES || to == UTUN_ERROR;
    case UTUN_INSTALLING_ROUTES:
        return to == UTUN_STACK_READY || to == UTUN_ERROR;
    case UTUN_STACK_READY:
        return to == UTUN_SERVER_CHECKING || to == UTUN_ERROR;
    case UTUN_SERVER_CHECKING:
        return to == UTUN_ONLINE || to == UTUN_DEGRADED || to == UTUN_ERROR;
    case UTUN_ONLINE:
        return to == UTUN_DEGRADED || to == UTUN_RECONNECTING ||
               to == UTUN_SERVER_CHECKING || to == UTUN_ERROR;
    case UTUN_DEGRADED:
        return to == UTUN_SERVER_CHECKING || to == UTUN_RECONNECTING ||
               to == UTUN_ERROR;
    /* a reconnect rebuilds pins and routes, or only re-checks the server. it
       never returns to OPENING, because the device stays open across both a
       network change and a server switch */
    case UTUN_RECONNECTING:
        return to == UTUN_PINNING_ENDPOINT || to == UTUN_SERVER_CHECKING ||
               to == UTUN_ERROR;
    case UTUN_ERROR:
        return to == UTUN_RECONNECTING || to == UTUN_IDLE;
    case UTUN_STOPPING:
        return to == UTUN_IDLE;
    }
    return 0;
}

static void record(utun_backend_state_t *state, utun_state_t from, utun_state_t to,
                   utun_layer_t layer, const char *reason, uint64_t now_ms) {
    utun_state_entry_t *entry = &state->log[state->log_next];
    memset(entry, 0, sizeof *entry);
    entry->from = from;
    entry->to = to;
    entry->layer = layer;
    entry->attempt_id = state->attempt_id;
    entry->at_ms = now_ms;
    if (reason) snprintf(entry->reason, sizeof entry->reason, "%s", reason);

    state->log_next = (state->log_next + 1u) % UTUN_STATE_LOG_MAX;
    if (state->log_count < UTUN_STATE_LOG_MAX) ++state->log_count;
    ++state->transitions;
}

static utun_backend_status_t move(utun_backend_state_t *state, utun_state_t next,
                                  utun_layer_t layer, const char *reason,
                                  uint64_t now_ms) {
    utun_state_t from = state->state;
    if (!transition_allowed(from, next)) {
        ++state->rejected_transitions;
        return UTUN_BACKEND_ERR_TRANSITION;
    }
    state->state = next;
    state->entered_state_ms = now_ms;
    record(state, from, next, layer, reason, now_ms);
    return UTUN_BACKEND_OK;
}

utun_backend_status_t utun_backend_connect(utun_backend_state_t *state, uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    if (state->state != UTUN_IDLE) {
        ++state->rejected_transitions;
        return UTUN_BACKEND_ERR_TRANSITION;
    }
    ++state->attempt_id;
    state->user_wants_connected = 1;
    state->handshake_ok = 0;
    state->carry_ok = 0;
    state->failure_layer = UTUN_LAYER_NONE;
    state->failure_reason[0] = '\0';
    return move(state, UTUN_OPENING, UTUN_LAYER_NONE, "user connect", now_ms);
}

utun_backend_status_t utun_backend_advance(utun_backend_state_t *state,
                                           utun_state_t next, utun_layer_t layer,
                                           const char *reason, uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    /* the one claim the ui must never make on its own: an open device and a
       reachable server are not the same thing as a working tunnel */
    if (next == UTUN_ONLINE && !(state->handshake_ok && state->carry_ok)) {
        ++state->rejected_transitions;
        return UTUN_BACKEND_ERR_UNPROVEN;
    }
    return move(state, next, layer, reason, now_ms);
}

utun_backend_status_t utun_backend_fail(utun_backend_state_t *state, utun_layer_t layer,
                                        const char *reason, uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    state->failure_layer = layer;
    snprintf(state->failure_reason, sizeof state->failure_reason, "%s",
             reason ? reason : "");
    /* the tunnel itself surviving a server failure is the whole point of
       keeping utun independent of the selected server, so that case is
       degraded rather than a torn down error */
    utun_state_t next = UTUN_ERROR;
    if (state->state == UTUN_SERVER_CHECKING || state->state == UTUN_ONLINE) {
        switch (layer) {
        case UTUN_LAYER_ENDPOINT:
        case UTUN_LAYER_TLS:
        case UTUN_LAYER_REALITY:
        case UTUN_LAYER_TRANSPORT:
        case UTUN_LAYER_PROTOCOL:
        case UTUN_LAYER_CARRY:
            next = UTUN_DEGRADED;
            break;
        default:
            break;
        }
    }
    if (next == UTUN_DEGRADED) {
        state->handshake_ok = 0;
        state->carry_ok = 0;
    }
    return move(state, next, layer, reason, now_ms);
}

utun_backend_status_t utun_backend_disconnect(utun_backend_state_t *state,
                                              uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    state->user_wants_connected = 0;
    state->handshake_ok = 0;
    state->carry_ok = 0;
    if (state->state == UTUN_IDLE) return UTUN_BACKEND_OK;
    utun_backend_status_t status = move(state, UTUN_STOPPING, UTUN_LAYER_NONE,
                                        "user disconnect", now_ms);
    if (status != UTUN_BACKEND_OK) return status;
    return move(state, UTUN_IDLE, UTUN_LAYER_NONE, "stopped", now_ms);
}

utun_backend_status_t utun_backend_network_changed(utun_backend_state_t *state,
                                                   uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    ++state->network_generation;
    if (!state->user_wants_connected) return UTUN_BACKEND_OK;
    state->handshake_ok = 0;
    state->carry_ok = 0;
    ++state->reconnects;
    /* a network that flaps again mid reconnect only needs the new generation:
       the attempt is already restarting, and a self transition would just add
       noise to the log */
    if (state->state == UTUN_RECONNECTING) return UTUN_BACKEND_OK;
    return move(state, UTUN_RECONNECTING, UTUN_LAYER_ROUTE, "network changed", now_ms);
}

utun_backend_status_t utun_backend_server_changed(utun_backend_state_t *state,
                                                  uint64_t now_ms) {
    if (!state) return UTUN_BACKEND_ERR_ARG;
    ++state->server_generation;
    state->handshake_ok = 0;
    state->carry_ok = 0;
    if (!utun_backend_tunnel_up(state)) return UTUN_BACKEND_OK;
    return move(state, UTUN_SERVER_CHECKING, UTUN_LAYER_NONE, "server changed", now_ms);
}

void utun_backend_mark_handshake(utun_backend_state_t *state, int ok) {
    if (!state) return;
    state->handshake_ok = ok ? 1 : 0;
    if (!ok) state->carry_ok = 0;
}

void utun_backend_mark_carry(utun_backend_state_t *state, int ok) {
    if (!state) return;
    state->carry_ok = ok ? 1 : 0;
}

int utun_backend_accepts_result(utun_backend_state_t *state,
                                uint64_t network_generation) {
    if (!state) return 0;
    if (network_generation != state->network_generation) {
        ++state->stale_results;
        return 0;
    }
    return 1;
}
