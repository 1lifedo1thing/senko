#include "tun_nat.h"

#include <stdint.h>
#include <string.h>

/* every packet an app sends passes the capture parser before anything else
   looks at it, and the stack's own packets pass it on the way out. both
   directions get raw bytes here, and whatever is accepted has to keep its
   length and stay inside the buffer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static tun_nat_t nat;
    static int ready;
    if (!ready) {
        tun_nat_config_t config;
        memset(&config, 0, sizeof config);
        const uint8_t local4[4] = { 198, 18, 0, 2 }, synth4[4] = { 198, 18, 0, 3 };
        memcpy(config.local4, local4, 4);
        memcpy(config.synthetic4, synth4, 4);
        config.local6[0] = 0xfd; config.local6[15] = 2;
        config.synthetic6[0] = 0xfd; config.synthetic6[15] = 3;
        config.have_ipv4 = config.have_ipv6 = 1;
        config.listen_port = 7;
        config.limit = 8;
        if (tun_nat_init(&nat, &config) != TUN_NAT_OK) __builtin_trap();
        ready = 1;
    }
    if (size > 1600) return 0;

    static uint8_t packet[1600];
    size_t slot;
    tun_nat_drop_t why;

    memcpy(packet, data, size);
    tun_nat_verdict_t in = tun_nat_inbound(&nat, packet, size, 1, &slot, &why);
    if (in == TUN_NAT_NEW) {
        static uint8_t out[TUN_NAT_SYN_MAX + 80];
        size_t out_len = 0;
        /* alternate, so both answers are reached whatever the packet looks
           like; the first byte of an ip packet is almost always the same */
        static unsigned turn;
        if (++turn & 1) {
            if (tun_nat_accept(&nat, slot, out, sizeof out, &out_len) != TUN_NAT_OK ||
                out_len > TUN_NAT_SYN_MAX)
                __builtin_trap();
        } else if (tun_nat_reject(&nat, slot, out, sizeof out, &out_len) != TUN_NAT_OK) {
            __builtin_trap();
        }
    }

    memcpy(packet, data, size);
    (void)tun_nat_outbound(&nat, packet, size, 2, &slot, &why);

    /* keep the table from filling for good, so later inputs still reach the
       syn path */
    size_t expired[8];
    (void)tun_nat_expire_pending(&nat, 100000, 1, expired, 8);
    for (size_t i = 0; i < 8; ++i)
        if (tun_nat_entry(&nat, i)->state != TUN_NAT_FREE) tun_nat_release(&nat, i);
    return 0;
}
