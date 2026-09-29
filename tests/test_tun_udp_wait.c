/* the tunnel loop sleeps until a udp association or a dns lookup runs out
   of time. it used to wake every 50 ms while any association existed, which
   kept an idle ios device waking for 30 s after every lookup */

#include "../daemon/tun_udp.c"

#include <stdio.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static uint32_t prepared_wait(tun_udp_t *udp, uint32_t start) {
    fd_set readable, writable;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    int highest = 0;
    uint32_t wait = start;
    on_prepare(udp, &readable, &writable, &highest, &wait);
    return wait;
}

int main(void) {
    tun_udp_t *udp = calloc(1, tun_udp_size());
    if (!udp) return 1;
    for (size_t i = 0; i < TUN_UDP_ASSOC_MAX; ++i) udp->associations[i].fd = -1;
    int64_t now = senko_now_ms();

    ok("nothing to time out leaves the wait alone",
       prepared_wait(udp, 1000) == 1000);

    association_t *assoc = &udp->associations[0];
    assoc->state = UDP_OPENING;
    assoc->opened_ms = now - (TUN_UDP_OPEN_MS - 3000);
    assoc->touched_ms = now;
    uint32_t wait = prepared_wait(udp, UINT32_MAX);
    ok("an opening association waits for its open deadline",
       wait > 2000 && wait <= 3000);

    assoc->opened_ms = now;
    assoc->touched_ms = now - (TUN_UDP_IDLE_MS - 4000);
    wait = prepared_wait(udp, UINT32_MAX);
    ok("an association waits for its idle deadline, not a 50 ms beat",
       wait > 3000 && wait <= 4000);

    assoc->touched_ms = now - TUN_UDP_IDLE_MS - 1;
    ok("an overdue association is served at once", prepared_wait(udp, UINT32_MAX) == 0);
    assoc->state = UDP_FREE;

    dns_pending_t *pending = &udp->dns[0];
    pending->used = 1;
    pending->sent_ms = now - 500;
    wait = prepared_wait(udp, UINT32_MAX);
    ok("a fresh lookup wakes for its stale answer",
       wait > TUN_UDP_DNS_STALE_MS - 1500 && wait <= TUN_UDP_DNS_STALE_MS - 500);
    pending->sent_ms = now - TUN_UDP_DNS_STALE_MS - 1000;
    wait = prepared_wait(udp, UINT32_MAX);
    ok("past the stale mark a lookup waits for its timeout, not a spin",
       wait > TUN_UDP_DNS_WAIT_MS - TUN_UDP_DNS_STALE_MS - 2000 &&
       wait <= TUN_UDP_DNS_WAIT_MS - TUN_UDP_DNS_STALE_MS - 1000);
    ok("a sooner deadline from another owner stands", prepared_wait(udp, 5) == 5);

    free(udp);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_udp wait checks passed");
    return 0;
}
