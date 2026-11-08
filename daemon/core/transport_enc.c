/* vless encryption over a stream transport. the layer sits between the vless
   bytes and the chosen transport: plaintext goes in, records go out through
   inner->write after the tcp, tls, reality, websocket or http/2 layer is up.
   the handshake runs inside the first reads and writes, never blocking the
   shared loop, and no vless byte leaves before the protocol allows it */

#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reality_handshake.h"
#include "senko_time.h"
#include "vlenc_conf.h"
#include "vlenc_conn.h"

/* a server that has not answered the handshake by now is not going to */
#define ENC_HANDSHAKE_MS 20000

typedef struct {
    const transport_vt_t *inner;
    void *ih;
    vlc_conn_t *vc;
    net_fail_t *fail;
    int failed;

    uint8_t *out;
    size_t out_cap, out_len, out_off;
    /* the hello leaves in the fragments the profile asks for */
    const size_t *segs;
    size_t nsegs, seg_i, seg_left;
    int hello_built;
    int hello_done;

    uint8_t *plain;     /* a decrypted record the caller had no room for */
    size_t plain_len, plain_off;

    int raw_down;       /* the peer switched to plain bytes (vision direct) */
    int raw_up;         /* we did: writes skip the records from here on */
    int64_t deadline_ms;
    int eof;
} enc_t;

static int fail_with(enc_t *e, vlc_status_t st) {
    if (e->fail) net_fail_note(e->fail, NET_FAIL_ENCRYPTION, (int)st);
    e->failed = 1;
    return TRANSPORT_ERR;
}

static void *enc_open(const transport_vt_t *inner, int fd, const transport_tls_cfg_t *cfg) {
    if (!cfg || !cfg->vless_enc) return NULL;
    const vlenc_cfg_t *vc = vlenc_cfg(cfg->vless_enc);
    if (!vc) return NULL;
    enc_t *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    char scope[320];
    snprintf(scope, sizeof scope, "%.256s:%u#%u", cfg->peer_host ? cfg->peer_host : "",
             (unsigned)cfg->peer_port, (unsigned)cfg->vless_enc);
    e->vc = vlc_new(vc, scope, NULL);
    e->ih = inner->open(fd, cfg);
    if (!e->vc || !e->ih) {
        if (e->ih) inner->close(e->ih);
        vlc_free(e->vc);
        free(e);
        return NULL;
    }
    e->inner = inner;
    e->fail = cfg->fail;
    e->deadline_ms = senko_now_ms() + ENC_HANDSHAKE_MS;
    return e;
}

static int out_reserve(enc_t *e, size_t need) {
    if (e->out_cap >= need) return 0;
    uint8_t *n = realloc(e->out, need);
    if (!n) return -1;
    e->out = n;
    e->out_cap = need;
    return 0;
}

/* send queued ciphertext; 0 when empty, else the inner transport's wait code */
static int pump_out(enc_t *e) {
    while (e->out_off < e->out_len) {
        size_t n = e->out_len - e->out_off;
        if (!e->hello_done && e->seg_left && n > e->seg_left) n = e->seg_left;
        int w = e->inner->write(e->ih, e->out + e->out_off, n);
        if (w > 0) {
            e->out_off += (size_t)w;
            if (!e->hello_done && e->seg_left) {
                e->seg_left -= (size_t)w;
                if (e->seg_left == 0 && e->seg_i < e->nsegs) e->seg_left = e->segs[e->seg_i++];
            }
            continue;
        }
        if (w == TRANSPORT_WANT_WRITE || w == TRANSPORT_WANT_READ) return w;
        return TRANSPORT_ERR;
    }
    e->out_off = e->out_len = 0;
    return 0;
}

static int ensure_hello(enc_t *e) {
    if (e->hello_built) return 0;
    e->hello_built = 1;
    const uint8_t *buf;
    size_t len, ns;
    const size_t *segs;
    vlc_status_t st = vlc_hello(e->vc, &buf, &len, &segs, &ns);
    if (st != VLC_OK) return fail_with(e, st);
    if (len == 0) { /* 0rtt: the preamble waits for the first record */
        e->hello_done = 1;
        return 0;
    }
    if (out_reserve(e, len) != 0) return fail_with(e, VLC_ERR_SYSTEM);
    memcpy(e->out, buf, len);
    e->out_len = len;
    e->out_off = 0;
    e->segs = segs;
    e->nsegs = ns;
    e->seg_i = 0;
    e->seg_left = ns ? segs[e->seg_i++] : 0;
    if (!e->seg_left) e->hello_done = 1;
    return 0;
}

static void hello_progress(enc_t *e) {
    if (!e->hello_done && e->out_off == e->out_len && e->seg_left == 0 && e->seg_i >= e->nsegs)
        e->hello_done = 1;
    /* the padding can make the hello tens of kilobytes; records need 13 */
    if (e->hello_done && e->out_off == e->out_len && e->out_cap > 2 * (VLC_PREAMBLE_MAX + VLC_PLAIN_MAX)) {
        free(e->out);
        e->out = NULL;
        e->out_cap = 0;
    }
}

static int late(enc_t *e) {
    if (vlc_established(e->vc)) return 0;
    if (senko_now_ms() < e->deadline_ms) return 0;
    if (e->fail) net_fail_note(e->fail, NET_FAIL_ENCRYPTION, 100);
    e->failed = 1;
    return 1;
}

/* the fresh-start flush shared by write(), read() and want_write() */
static int start(enc_t *e) {
    if (e->failed || late(e)) return TRANSPORT_ERR;
    if (!e->hello_done && ensure_hello(e) != 0) return TRANSPORT_ERR;
    int p = pump_out(e);
    hello_progress(e);
    if (p == TRANSPORT_ERR) e->failed = 1;
    return p;
}

/* move socket bytes into the record layer; 0 means some arrived */
static int fill(enc_t *e) {
    uint8_t *p;
    size_t cap;
    if (vlc_rx_space(e->vc, &p, &cap) != VLC_OK) return fail_with(e, VLC_ERR_SYSTEM);
    int r = e->inner->read(e->ih, p, cap);
    if (r > 0) {
        vlc_rx_commit(e->vc, (size_t)r);
        return 0;
    }
    if (r == TRANSPORT_EOF) {
        e->eof = 1;
        return TRANSPORT_EOF;
    }
    return r;
}

/* a clean end only on a record boundary of an established stream. before
   that the server hung up on the handshake, which is a diagnosis of its own */
static int eof_result(enc_t *e) {
    if (vlc_at_boundary(e->vc)) return TRANSPORT_EOF;
    if (!vlc_established(e->vc) && e->fail) net_fail_note(e->fail, NET_FAIL_CLOSED, 0);
    e->failed = 1;
    return TRANSPORT_ERR;
}

static int enc_read(void *h, uint8_t *buf, size_t len) {
    enc_t *e = h;
    if (e->failed) return TRANSPORT_ERR;
    if (len == 0) return 0;

    if (e->plain_off < e->plain_len) {
        size_t n = e->plain_len - e->plain_off;
        if (n > len) n = len;
        memcpy(buf, e->plain + e->plain_off, n);
        e->plain_off += n;
        return (int)n;
    }

    int s = start(e);
    if (s == TRANSPORT_ERR) return TRANSPORT_ERR;
    /* a write that has to wait does not stop us from reading the reply */

    if (e->raw_down) {
        size_t n = vlc_take_raw(e->vc, buf, len);
        if (n) return (int)n;
        int r = e->inner->read(e->ih, buf, len);
        if (r > 0) vlc_raw_decode(e->vc, buf, (size_t)r);
        else if (r == TRANSPORT_ERR) e->failed = 1;
        return r;
    }

    for (;;) {
        if (!e->plain) {
            e->plain = malloc(VLC_REC_MAX);
            if (!e->plain) return fail_with(e, VLC_ERR_SYSTEM);
        }
        size_t got = 0;
        vlc_status_t st = vlc_pull(e->vc, e->plain, VLC_REC_MAX, &got);
        if (st == VLC_DATA) {
            size_t n = got < len ? got : len;
            memcpy(buf, e->plain, n);
            e->plain_off = n;
            e->plain_len = got;
            return (int)n;
        }
        if (st != VLC_NEED_MORE) return fail_with(e, st);
        if (late(e)) return TRANSPORT_ERR;
        if (e->eof) return eof_result(e);
        int r = fill(e);
        if (r == TRANSPORT_EOF) continue; /* let the pull above judge what was buffered */
        if (r == TRANSPORT_ERR) e->failed = 1;
        if (r != 0) return r;
    }
}

static int enc_write(void *h, const uint8_t *buf, size_t len) {
    enc_t *e = h;
    if (e->failed) return TRANSPORT_ERR;
    int s = start(e);
    if (s == TRANSPORT_ERR) return TRANSPORT_ERR;
    if (len == 0) return s == 0 ? 0 : s;
    if (s != 0) return s; /* ciphertext still queued: take no more yet */

    /* 1rtt: no record may go before the server's reply is read and checked */
    while (!vlc_can_seal(e->vc)) {
        uint8_t scratch[1];
        size_t got = 0;
        vlc_status_t st = vlc_pull(e->vc, scratch, sizeof scratch, &got);
        if (st != VLC_NEED_MORE) return fail_with(e, st);
        if (vlc_can_seal(e->vc)) break;
        int r = fill(e);
        if (r == TRANSPORT_EOF) return eof_result(e);
        if (r == TRANSPORT_ERR) e->failed = 1;
        if (r != 0) return r;
    }

    size_t take = len > VLC_PLAIN_MAX ? VLC_PLAIN_MAX : len;
    if (out_reserve(e, VLC_PREAMBLE_MAX + VLC_PLAIN_MAX + VLC_SEAL_EXTRA) != 0)
        return fail_with(e, VLC_ERR_SYSTEM);
    size_t wl = 0;
    vlc_status_t st = vlc_seal(e->vc, buf, take, e->out, e->out_cap, &wl);
    if (st != VLC_OK) return fail_with(e, st);
    e->out_off = 0;
    e->out_len = wl;
    int p = pump_out(e);
    if (p == TRANSPORT_ERR) {
        e->failed = 1;
        return TRANSPORT_ERR;
    }
    return (int)take;
}

/* the vision direct switch, our side. xray stops reading records from the
   direct command on and takes the stream as plain bytes of the connection
   below, so from the mark on the writes skip the aead records. the transport
   below stays in use as is: a tls or websocket layer under the profile keeps
   protecting the bytes, which is why this goes through inner->write and never
   inner->raw_write, that one would leave the outer tls */
static int enc_raw_write(void *h, const uint8_t *buf, size_t len) {
    enc_t *e = h;
    if (!buf && len == 0) {
        if (!e->failed) e->raw_up = 1;
        return 0;
    }
    if (!e->raw_up) return enc_write(h, buf, len);
    if (e->failed) return TRANSPORT_ERR;

    int s = start(e);
    if (s == TRANSPORT_ERR) return TRANSPORT_ERR;
    if (len == 0) return s;
    if (s != 0) return s;

    size_t take = len > VLC_PLAIN_MAX ? VLC_PLAIN_MAX : len;
    if (out_reserve(e, take) != 0) return fail_with(e, VLC_ERR_SYSTEM);
    memcpy(e->out, buf, take);
    vlc_raw_encode(e->vc, e->out, take);
    e->out_off = 0;
    e->out_len = take;
    if (pump_out(e) == TRANSPORT_ERR) {
        e->failed = 1;
        return TRANSPORT_ERR;
    }
    return (int)take;
}

static int enc_want_write(void *h) {
    enc_t *e = h;
    if (e->failed) return 0;
    if (e->out_off < e->out_len) return 1;
    return e->inner->want_write ? e->inner->want_write(e->ih) : 0;
}

static void enc_shutdown(void *h) {
    enc_t *e = h;
    if (e->failed) return;
    (void)pump_out(e);
    if (e->inner->shutdown) e->inner->shutdown(e->ih);
}

/* the vision direct switch, the peer's side: what follows the command is the
   inner stream without records. bytes that already sit in the record buffer
   belong to it and are returned first */
static void enc_peer_direct(void *h) {
    enc_t *e = h;
    if (!e->failed) e->raw_down = 1;
}

static void enc_close(void *h) {
    enc_t *e = h;
    if (!e) return;
    if (e->ih) e->inner->close(e->ih);
    vlc_free(e->vc);
    if (e->out) {
        memset(e->out, 0, e->out_cap);
        free(e->out);
    }
    if (e->plain) {
        memset(e->plain, 0, VLC_REC_MAX);
        free(e->plain);
    }
    memset(e, 0, sizeof *e);
    free(e);
}

#define ENC_WRAP(name, inner)                                                       \
    static void *name##_open(int fd, const transport_tls_cfg_t *cfg) {              \
        return enc_open(&(inner), fd, cfg);                                         \
    }                                                                               \
    static const transport_vt_t name = {                                            \
        name##_open, enc_read, enc_write, enc_raw_write, enc_close,                 \
        enc_want_write, enc_shutdown, enc_peer_direct                               \
    };

ENC_WRAP(enc_tcp, transport_tcp)
ENC_WRAP(enc_tls, transport_tls)
ENC_WRAP(enc_reality, transport_reality)
ENC_WRAP(enc_ws_tcp, transport_ws_tcp)
ENC_WRAP(enc_ws_tls, transport_ws_tls)
ENC_WRAP(enc_ws_reality, transport_ws_reality)
ENC_WRAP(enc_xhttp_tcp, transport_xhttp_tcp)
ENC_WRAP(enc_xhttp_tls, transport_xhttp_tls)
ENC_WRAP(enc_xhttp_reality, transport_xhttp_reality)

const transport_vt_t *transport_enc_over(const transport_vt_t *inner) {
    if (inner == &transport_tcp) return &enc_tcp;
    if (inner == &transport_tls) return &enc_tls;
    if (inner == &transport_reality) return &enc_reality;
    if (inner == &transport_ws_tcp) return &enc_ws_tcp;
    if (inner == &transport_ws_tls) return &enc_ws_tls;
    if (inner == &transport_ws_reality) return &enc_ws_reality;
    if (inner == &transport_xhttp_tcp) return &enc_xhttp_tcp;
    if (inner == &transport_xhttp_tls) return &enc_xhttp_tls;
    if (inner == &transport_xhttp_reality) return &enc_xhttp_reality;
    return NULL;
}
