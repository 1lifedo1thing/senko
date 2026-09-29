#include "backend_state.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

/* walk the bring-up as far as the caller asks, so each test starts from a
   real sequence instead of a hand set state field */
static void bring_up_to(utun_backend_state_t *state, utun_state_t target) {
    static const utun_state_t path[] = {
        UTUN_OPENING, UTUN_CONFIGURING, UTUN_PINNING_ENDPOINT,
        UTUN_INSTALLING_ROUTES, UTUN_STACK_READY, UTUN_SERVER_CHECKING
    };
    utun_backend_init(state);
    utun_backend_connect(state, 0);
    for (size_t i = 1; i < sizeof path / sizeof path[0]; ++i) {
        if (state->state == target) return;
        utun_backend_advance(state, path[i], UTUN_LAYER_NONE, "step", 0);
    }
}

int main(void) {
    utun_backend_state_t state;

    utun_backend_init(&state);
    ok("starts idle", state.state == UTUN_IDLE);
    ok("no attempt yet", state.attempt_id == 0);
    ok("idle allows traffic outside the tunnel",
       utun_backend_allows_direct_traffic(&state));
    ok("idle has no tunnel", !utun_backend_tunnel_up(&state));

    ok("connect starts an attempt",
       utun_backend_connect(&state, 100) == UTUN_BACKEND_OK &&
       state.state == UTUN_OPENING && state.attempt_id == 1);
    ok("connect records the user intent", state.user_wants_connected == 1);
    ok("a second connect while busy is refused",
       utun_backend_connect(&state, 100) == UTUN_BACKEND_ERR_TRANSITION);

    /* the moment an attempt starts, nothing may leave outside the tunnel */
    ok("opening is fail-closed", !utun_backend_allows_direct_traffic(&state));

    /* the bring-up order is enforced, steps cannot be skipped */
    ok("routes cannot be installed before the endpoint is pinned",
       utun_backend_advance(&state, UTUN_INSTALLING_ROUTES, UTUN_LAYER_ROUTE,
                            "skip", 100) == UTUN_BACKEND_ERR_TRANSITION);
    ok("a rejected transition is counted", state.rejected_transitions == 2);
    ok("a rejected transition does not move the state", state.state == UTUN_OPENING);

    ok("configuring follows opening",
       utun_backend_advance(&state, UTUN_CONFIGURING, UTUN_LAYER_DEVICE, "utun3", 110) ==
       UTUN_BACKEND_OK);
    ok("pinning follows configuring",
       utun_backend_advance(&state, UTUN_PINNING_ENDPOINT, UTUN_LAYER_ENDPOINT,
                            "1 address", 120) == UTUN_BACKEND_OK);
    ok("routes follow pinning",
       utun_backend_advance(&state, UTUN_INSTALLING_ROUTES, UTUN_LAYER_ROUTE,
                            "7 ops", 130) == UTUN_BACKEND_OK);
    ok("stack follows routes",
       utun_backend_advance(&state, UTUN_STACK_READY, UTUN_LAYER_NONE, "up", 140) ==
       UTUN_BACKEND_OK);
    ok("the tunnel counts as up once the stack is ready",
       utun_backend_tunnel_up(&state));
    ok("server checking follows the stack",
       utun_backend_advance(&state, UTUN_SERVER_CHECKING, UTUN_LAYER_NONE, "probe", 150) ==
       UTUN_BACKEND_OK);

    /* the rule that keeps the ui honest */
    ok("online without proof is refused",
       utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "", 160) ==
       UTUN_BACKEND_ERR_UNPROVEN);
    utun_backend_mark_handshake(&state, 1);
    ok("online with a handshake but no carry is still refused",
       utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "", 160) ==
       UTUN_BACKEND_ERR_UNPROVEN);
    utun_backend_mark_carry(&state, 1);
    ok("online with both proofs is accepted",
       utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "carried", 170) ==
       UTUN_BACKEND_OK && state.state == UTUN_ONLINE);
    ok("online is still fail-closed for direct traffic",
       !utun_backend_allows_direct_traffic(&state));

    /* losing the handshake invalidates the carry proof with it */
    utun_backend_mark_handshake(&state, 0);
    ok("a lost handshake drops the carry proof", state.carry_ok == 0);

    /* an open tunnel whose server failed is degraded, never online */
    bring_up_to(&state, UTUN_SERVER_CHECKING);
    ok("a server failure lands in degraded",
       utun_backend_fail(&state, UTUN_LAYER_REALITY, "bad public key", 200) ==
       UTUN_BACKEND_OK && state.state == UTUN_DEGRADED);
    ok("degraded keeps the failing layer", state.failure_layer == UTUN_LAYER_REALITY);
    ok("degraded keeps the reason", strcmp(state.failure_reason, "bad public key") == 0);
    ok("degraded still counts as a live tunnel", utun_backend_tunnel_up(&state));
    ok("degraded does not leak traffic around the proxy",
       !utun_backend_allows_direct_traffic(&state));
    ok("degraded cannot be talked into online",
       utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "", 210) ==
       UTUN_BACKEND_ERR_UNPROVEN);

    /* a device or route failure is not something the tunnel survives */
    bring_up_to(&state, UTUN_INSTALLING_ROUTES);
    ok("a route failure is an error, not a degrade",
       utun_backend_fail(&state, UTUN_LAYER_ROUTE, "add refused", 220) ==
       UTUN_BACKEND_OK && state.state == UTUN_ERROR);
    ok("an errored backend has no tunnel", !utun_backend_tunnel_up(&state));
    ok("an errored backend is still fail-closed",
       !utun_backend_allows_direct_traffic(&state));

    /* a user disconnect cancels the intent and ends idle, from anywhere */
    bring_up_to(&state, UTUN_SERVER_CHECKING);
    ok("disconnect from mid bring-up lands idle",
       utun_backend_disconnect(&state, 300) == UTUN_BACKEND_OK &&
       state.state == UTUN_IDLE);
    ok("disconnect clears the intent so nothing reconnects",
       state.user_wants_connected == 0);
    ok("an idle backend allows direct traffic again",
       utun_backend_allows_direct_traffic(&state));
    ok("disconnecting an idle backend is a no-op",
       utun_backend_disconnect(&state, 310) == UTUN_BACKEND_OK &&
       state.state == UTUN_IDLE);

    /* a network change keeps the user intent and rebuilds routes without
       reopening the device */
    bring_up_to(&state, UTUN_SERVER_CHECKING);
    utun_backend_mark_handshake(&state, 1);
    utun_backend_mark_carry(&state, 1);
    utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "carried", 400);
    uint64_t before = state.network_generation;
    ok("network change moves to reconnecting",
       utun_backend_network_changed(&state, 410) == UTUN_BACKEND_OK &&
       state.state == UTUN_RECONNECTING);
    ok("network change bumps the generation", state.network_generation == before + 1);
    ok("network change keeps the user intent", state.user_wants_connected == 1);
    ok("network change drops the old proof",
       state.handshake_ok == 0 && state.carry_ok == 0);
    ok("network change is counted", state.reconnects == 1);
    ok("a reconnect rebuilds pins rather than reopening the device",
       utun_backend_advance(&state, UTUN_PINNING_ENDPOINT, UTUN_LAYER_ROUTE,
                            "rebuild", 420) == UTUN_BACKEND_OK);
    ok("a reconnect may not go back to opening",
       utun_backend_advance(&state, UTUN_OPENING, UTUN_LAYER_DEVICE, "", 420) ==
       UTUN_BACKEND_ERR_TRANSITION);

    /* results from the superseded network are rejected by generation */
    ok("a result from the current network is accepted",
       utun_backend_accepts_result(&state, state.network_generation));
    ok("a result from the previous network is rejected",
       !utun_backend_accepts_result(&state, state.network_generation - 1));
    ok("stale results are counted", state.stale_results == 1);

    /* a network change during the bring-up must be accepted too: wifi can
       drop while the endpoint pins for the old gateway are going in */
    static const utun_state_t mid_bringup[] = {
        UTUN_OPENING, UTUN_CONFIGURING, UTUN_PINNING_ENDPOINT,
        UTUN_INSTALLING_ROUTES, UTUN_STACK_READY, UTUN_SERVER_CHECKING
    };
    for (size_t i = 0; i < sizeof mid_bringup / sizeof mid_bringup[0]; ++i) {
        utun_backend_state_t mid;
        bring_up_to(&mid, mid_bringup[i]);
        char name[80];
        snprintf(name, sizeof name, "network change accepted while %s",
                 utun_state_name(mid_bringup[i]));
        ok(name, mid.state == mid_bringup[i] &&
           utun_backend_network_changed(&mid, 700) == UTUN_BACKEND_OK &&
           mid.state == UTUN_RECONNECTING);
    }

    /* a second network change while already reconnecting bumps the
       generation without a pointless self transition */
    utun_backend_state_t flapping;
    bring_up_to(&flapping, UTUN_PINNING_ENDPOINT);
    utun_backend_network_changed(&flapping, 700);
    uint64_t flap_generation = flapping.network_generation;
    ok("a second change while reconnecting still bumps the generation",
       utun_backend_network_changed(&flapping, 710) == UTUN_BACKEND_OK &&
       flapping.network_generation == flap_generation + 1 &&
       flapping.state == UTUN_RECONNECTING);

    /* a network change with no user intent only bumps the generation */
    utun_backend_init(&state);
    ok("network change while idle stays idle",
       utun_backend_network_changed(&state, 500) == UTUN_BACKEND_OK &&
       state.state == UTUN_IDLE && state.network_generation == 1);

    /* a server switch does not tear the tunnel down */
    bring_up_to(&state, UTUN_SERVER_CHECKING);
    utun_backend_mark_handshake(&state, 1);
    utun_backend_mark_carry(&state, 1);
    utun_backend_advance(&state, UTUN_ONLINE, UTUN_LAYER_NONE, "carried", 600);
    uint64_t server_before = state.server_generation;
    ok("server change re-checks without reopening",
       utun_backend_server_changed(&state, 610) == UTUN_BACKEND_OK &&
       state.state == UTUN_SERVER_CHECKING);
    ok("server change bumps only the server generation",
       state.server_generation == server_before + 1 && state.network_generation == 0);
    ok("server change leaves the tunnel up", utun_backend_tunnel_up(&state));
    ok("server change drops the proof of the old server",
       state.handshake_ok == 0 && state.carry_ok == 0);

    /* the transition log keeps the attempt id and stays bounded */
    utun_backend_init(&state);
    utun_backend_connect(&state, 0);
    ok("the log records the connect",
       state.log_count == 1 && state.log[0].to == UTUN_OPENING &&
       state.log[0].attempt_id == 1);
    for (int i = 0; i < 40; ++i) {
        utun_backend_advance(&state, UTUN_CONFIGURING, UTUN_LAYER_NONE, "a", 0);
        utun_backend_advance(&state, UTUN_PINNING_ENDPOINT, UTUN_LAYER_NONE, "b", 0);
        utun_backend_advance(&state, UTUN_INSTALLING_ROUTES, UTUN_LAYER_NONE, "c", 0);
        utun_backend_fail(&state, UTUN_LAYER_ROUTE, "again", 0);
        utun_backend_advance(&state, UTUN_RECONNECTING, UTUN_LAYER_NONE, "retry", 0);
        utun_backend_advance(&state, UTUN_PINNING_ENDPOINT, UTUN_LAYER_NONE, "d", 0);
        utun_backend_advance(&state, UTUN_INSTALLING_ROUTES, UTUN_LAYER_NONE, "e", 0);
        utun_backend_fail(&state, UTUN_LAYER_ROUTE, "again", 0);
    }
    ok("the log never grows past its ring", state.log_count == UTUN_STATE_LOG_MAX);
    ok("transitions keep being counted past the ring", state.transitions > UTUN_STATE_LOG_MAX);

    /* a reason longer than the field is truncated, not written past the end */
    char long_reason[512];
    memset(long_reason, 'x', sizeof long_reason - 1);
    long_reason[sizeof long_reason - 1] = '\0';
    utun_backend_init(&state);
    utun_backend_connect(&state, 0);
    utun_backend_fail(&state, UTUN_LAYER_DEVICE, long_reason, 0);
    ok("a long reason is truncated to the field",
       strlen(state.failure_reason) == UTUN_REASON_MAX - 1);

    /* names exist for every state and layer, a diagnostics screen must not
       print a bare number */
    int named = 1;
    for (int i = UTUN_IDLE; i <= UTUN_ERROR; ++i)
        if (strcmp(utun_state_name((utun_state_t)i), "unknown") == 0) named = 0;
    for (int i = UTUN_LAYER_NONE; i <= UTUN_LAYER_CANCELLED; ++i)
        if (strcmp(utun_layer_name((utun_layer_t)i), "unknown") == 0) named = 0;
    ok("every state and layer has a name", named);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all backend state checks passed");
    return 0;
}
