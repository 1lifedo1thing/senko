/* the profile parser takes the first part of the input as text, the record
   layer gets the rest as the bytes a hostile server sends back. neither may
   crash, read out of bounds or hand out plaintext that no tag vouched for */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "vlenc_conf.h"
#include "vlenc_conn.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 70000) return 0;
    size_t split = size ? data[0] % (size < 4200 ? size : 4200) : 0;
    char *text = malloc(split + 1);
    if (!text) return 0;
    memcpy(text, data, split);
    text[split] = 0;
    vlenc_cfg_t cfg;
    (void)vlenc_parse(text, &cfg);
    free(text);

    static vlenc_cfg_t good;
    static int ready;
    if (!ready) {
        if (vlenc_parse("mlkem768x25519plus.random.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &good) != VLENC_OK)
            abort();
        ready = 1;
    }
    vlc_conn_t *c = vlc_new(&good, "fuzz", NULL);
    if (!c) return 0;
    const uint8_t *h;
    size_t hl, ns;
    const size_t *segs;
    if (vlc_hello(c, &h, &hl, &segs, &ns) == VLC_OK) {
        const uint8_t *in = data + split;
        size_t left = size - split;
        static uint8_t out[VLC_REC_MAX];
        while (left) {
            uint8_t *p;
            size_t cap;
            if (vlc_rx_space(c, &p, &cap) != VLC_OK) break;
            size_t take = left < cap ? left : cap;
            if (take > 97) take = 97;
            memcpy(p, in, take);
            vlc_rx_commit(c, take);
            in += take;
            left -= take;
            size_t got = 0;
            vlc_status_t st = vlc_pull(c, out, sizeof out, &got);
            /* a random reply never authenticates, so no plaintext may come out */
            if (st == VLC_DATA) abort();
            if (st != VLC_NEED_MORE) break;
        }
    }
    vlc_free(c);
    return 0;
}
