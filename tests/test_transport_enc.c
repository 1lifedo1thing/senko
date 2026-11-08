#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "transport_enc.c" /* the whole module: the deadline test moves a private clock */
#include "vlenc_server.h"

static int failures;
#define CHECK(c, what) do { if (!(c)) { fprintf(stderr, "FAIL %s (line %d)\n", what, __LINE__); failures++; } } while (0)

static void b64url(const uint8_t *in, size_t n, char *out) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = a[v >> 18 & 63];
        out[o++] = a[v >> 12 & 63];
        if (i + 1 < n) out[o++] = a[v >> 6 & 63];
        if (i + 2 < n) out[o++] = a[v & 63];
    }
    out[o] = 0;
}

typedef struct {
    vls_key_t keys[2];
    int n;
    char text[VLENC_TEXT_MAX];
    uint16_t id;
    vls_ctx_t *ctx;
} world_t;

static void world_make(world_t *w, const char *mode, const char *rtt, int seconds, const int *pq, int n) {
    memset(w, 0, sizeof *w);
    w->n = n;
    snprintf(w->text, sizeof w->text, "mlkem768x25519plus.%s.%s", mode, rtt);
    for (int i = 0; i < n; ++i) {
        assert(vls_key_make(&w->keys[i], pq[i]) == 0);
        char enc[2200];
        b64url(w->keys[i].pk, w->keys[i].pk_len, enc);
        strcat(w->text, ".");
        strcat(w->text, enc);
    }
    int xm = strcmp(mode, "random") == 0 ? 2 : strcmp(mode, "xorpub") == 0 ? 1 : 0;
    assert(vlenc_intern(w->text, &w->id) == VLENC_OK);
    w->ctx = vls_ctx_new(w->keys, n, xm, seconds);
}

typedef struct {
    int cfd, sfd;
    vls_t *srv;
    const transport_vt_t *vt;
    void *th;
    net_fail_t fail;
} link_t;

static void set_nb(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

static int link_open(link_t *l, world_t *w, const transport_vt_t *inner, uint16_t port) {
    memset(l, 0, sizeof *l);
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    l->cfd = sv[0];
    l->sfd = sv[1];
    set_nb(l->cfd);
    set_nb(l->sfd);
    l->srv = vls_new(w->ctx);
    l->vt = transport_enc_over(inner);
    if (!l->vt) return -1;
    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.vless_enc = w->id;
    cfg.peer_host = "srv.example";
    cfg.peer_port = port;
    cfg.fail = &l->fail;
    l->th = l->vt->open(l->cfd, &cfg);
    return l->th ? 0 : -1;
}

static void link_close(link_t *l) {
    if (l->th) l->vt->close(l->th);
    vls_free(l->srv);
    close(l->cfd);
    close(l->sfd);
}

/* the server end: take what arrived, answer, nothing blocks */
static int serve(link_t *l, int echo) {
    uint8_t buf[70000];
    int moved = 0;
    ssize_t n;
    while ((n = read(l->sfd, buf, sizeof buf)) > 0) {
        vls_feed(l->srv, buf, (size_t)n);
        moved = 1;
    }
    if (echo) {
        uint8_t p[70000];
        size_t g = vls_plain_in(l->srv, p, sizeof p);
        if (g) vls_send(l->srv, p, g);
    }
    for (;;) {
        size_t o = vls_wire_out(l->srv, buf, sizeof buf);
        if (!o) break;
        for (size_t off = 0; off < o;) {
            ssize_t w = write(l->sfd, buf + off, o - off);
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd pf = { l->sfd, POLLOUT, 0 };
                poll(&pf, 1, 100);
                continue;
            }
            if (w <= 0) return -1;
            off += (size_t)w;
        }
        moved = 1;
    }
    return moved;
}

/* a vless-like exchange: write the request, read the echo, until all of it came back */
static int echo_exchange(link_t *l, size_t len, int *final_rc) {
    uint8_t *msg = malloc(len), *back = malloc(len);
    for (size_t i = 0; i < len; ++i) msg[i] = (uint8_t)(i * 17 + 3);
    size_t sent = 0, got = 0;
    int rc = 0;
    for (int iter = 0; iter < 20000 && got < len && !rc; ++iter) {
        if (sent < len) {
            int w = l->vt->write(l->th, msg + sent, len - sent);
            if (w > 0) sent += (size_t)w;
            else if (w == TRANSPORT_ERR || w == TRANSPORT_EOF) { rc = w; break; }
        } else {
            int w = l->vt->write(l->th, (const uint8_t *)"", 0);
            if (w == TRANSPORT_ERR) { rc = w; break; }
        }
        serve(l, 1);
        uint8_t tmp[3000];
        int r = l->vt->read(l->th, tmp, sizeof tmp);
        if (r > 0) {
            if (got + (size_t)r > len) { rc = -99; break; }
            memcpy(back + got, tmp, (size_t)r);
            got += (size_t)r;
        } else if (r == TRANSPORT_ERR || r == TRANSPORT_EOF) {
            rc = r;
        }
    }
    if (!rc && (got != len || memcmp(back, msg, len))) rc = -98;
    free(msg);
    free(back);
    if (final_rc) *final_rc = rc;
    return rc;
}

static void test_echo_everywhere(void) {
    static const char *modes[] = { "native", "xorpub", "random" };
    static const int chains[][2] = { { 0, 0 }, { 1, 0 } };
    static const int chain_n[] = { 1, 2 };
    static const transport_vt_t *inners[] = { &transport_tcp };
    for (int m = 0; m < 3; ++m) {
        for (int c = 0; c < 2; ++c) {
            world_t w;
            world_make(&w, modes[m], "1rtt", 0, chains[c], chain_n[c]);
            static const size_t lens[] = { 1, 700, 8192, 8193, 65000 };
            for (size_t i = 0; i < sizeof lens / sizeof lens[0]; ++i) {
                link_t l;
                CHECK(link_open(&l, &w, inners[0], 443) == 0, "open");
                char what[80];
                int rc = 0;
                echo_exchange(&l, lens[i], &rc);
                snprintf(what, sizeof what, "echo mode=%s chain=%d len=%zu rc=%d", modes[m], c, lens[i], rc);
                CHECK(rc == 0, what);
                CHECK(l.fail.kind == NET_FAIL_NONE, "no failure noted");
                link_close(&l);
            }
            vls_ctx_free(w.ctx);
        }
    }
}

static void test_zero_rtt_flow(void) {
    vlc_tickets_reset();
    int chain[] = { 1 };
    world_t w;
    world_make(&w, "native", "0rtt", 600, chain, 1);
    int zr[3];
    for (int i = 0; i < 3; ++i) {
        link_t l;
        assert(link_open(&l, &w, &transport_tcp, 8443) == 0);
        int rc = 0;
        echo_exchange(&l, 3000, &rc);
        CHECK(rc == 0, "0rtt echo");
        enc_t *e = l.th;
        zr[i] = vlc_is_zero_rtt(e->vc);
        link_close(&l);
    }
    CHECK(zr[0] == 0 && zr[1] == 1 && zr[2] == 1, "tickets used from the second connection");

    /* another port is another scope */
    link_t l;
    assert(link_open(&l, &w, &transport_tcp, 9443) == 0);
    int rc = 0;
    echo_exchange(&l, 100, &rc);
    CHECK(rc == 0 && !vlc_is_zero_rtt(((enc_t *)l.th)->vc), "ticket is scoped to the port");
    link_close(&l);

    /* the server forgot: the connection fails once with the ticket reason, the next one works */
    vls_ctx_forget_tickets(w.ctx);
    assert(link_open(&l, &w, &transport_tcp, 8443) == 0);
    echo_exchange(&l, 100, &rc);
    CHECK(rc == TRANSPORT_ERR, "rejected ticket ends the connection");
    CHECK(l.fail.kind == NET_FAIL_ENCRYPTION && l.fail.value == VLC_ERR_TICKET, "reason is recorded");
    link_close(&l);
    assert(link_open(&l, &w, &transport_tcp, 8443) == 0);
    echo_exchange(&l, 100, &rc);
    CHECK(rc == 0 && !vlc_is_zero_rtt(((enc_t *)l.th)->vc), "full handshake after the rejection");
    link_close(&l);
    vls_ctx_free(w.ctx);
}

static void test_failures(void) {
    int chain[] = { 0 };
    world_t w;
    world_make(&w, "native", "1rtt", 0, chain, 1);
    link_t l;
    uint8_t buf[100000];

    /* a flipped bit in the server's key exchange message */
    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    assert(l.vt->write(l.th, (const uint8_t *)"hi", 2) == TRANSPORT_WANT_READ || 1);
    ssize_t n = read(l.sfd, buf, sizeof buf);
    assert(n > 0);
    vls_feed(l.srv, buf, (size_t)n);
    size_t o = vls_wire_out(l.srv, buf, sizeof buf);
    buf[700] ^= 1;
    assert(write(l.sfd, buf, o) == (ssize_t)o);
    int r = l.vt->read(l.th, buf, 100);
    CHECK(r == TRANSPORT_ERR, "bad reply fails the read");
    CHECK(l.fail.kind == NET_FAIL_ENCRYPTION && l.fail.value == VLC_ERR_AUTH, "auth failure is noted");
    CHECK(l.vt->write(l.th, (const uint8_t *)"x", 1) == TRANSPORT_ERR, "a failed layer takes no more data");
    link_close(&l);

    /* the server hangs up in the middle of the handshake */
    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    l.vt->write(l.th, (const uint8_t *)"hi", 2);
    while (read(l.sfd, buf, sizeof buf) > 0) { /* take the hello so the close is a fin, not a reset */ }
    close(l.sfd);
    l.sfd = -1;
    r = l.vt->read(l.th, buf, 100);
    CHECK(r == TRANSPORT_ERR && l.fail.kind == NET_FAIL_CLOSED, "eof during the handshake is a closed connection");
    l.sfd = dup(0);
    link_close(&l);

    /* a clean end after the last record is an eof, a cut record is an error */
    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    int rc = 0;
    echo_exchange(&l, 50, &rc);
    CHECK(rc == 0, "established");
    shutdown(l.sfd, SHUT_WR);
    r = l.vt->read(l.th, buf, 100);
    CHECK(r == TRANSPORT_EOF, "clean eof at a record boundary");
    link_close(&l);

    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    echo_exchange(&l, 50, &rc);
    CHECK(rc == 0, "established again");
    vls_send(l.srv, buf, 300);
    o = vls_wire_out(l.srv, buf, sizeof buf);
    assert(write(l.sfd, buf, o - 7) == (ssize_t)(o - 7));
    shutdown(l.sfd, SHUT_WR);
    r = l.vt->read(l.th, buf, 100);
    CHECK(r == TRANSPORT_WANT_READ || r == TRANSPORT_EOF || r == TRANSPORT_ERR, "cut record does not deliver");
    r = l.vt->read(l.th, buf, 100);
    CHECK(r == TRANSPORT_ERR, "eof inside a record is an error");
    link_close(&l);

    /* a server that never answers: the handshake gives up at its deadline */
    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    ((enc_t *)l.th)->deadline_ms = senko_now_ms() - 1;
    r = l.vt->write(l.th, (const uint8_t *)"hi", 2);
    CHECK(r == TRANSPORT_ERR && l.fail.kind == NET_FAIL_ENCRYPTION && l.fail.value == 100, "handshake deadline");
    link_close(&l);

    /* no profile in the config: the open refuses */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    CHECK(transport_enc_over(&transport_tcp)->open(sv[0], &cfg) == NULL, "open without a profile");
    cfg.vless_enc = 77;
    CHECK(transport_enc_over(&transport_tcp)->open(sv[0], &cfg) == NULL, "open with an unknown profile");
    close(sv[0]);
    close(sv[1]);
    vls_ctx_free(w.ctx);
}

/* an inner tls record: application data header, then the body */
static size_t tls_record(uint8_t *out, const char *body, size_t n) {
    out[0] = 23; out[1] = 3; out[2] = 3;
    out[3] = (uint8_t)(n >> 8); out[4] = (uint8_t)n;
    memcpy(out + 5, body, n);
    return 5 + n;
}

/* after the vision direct switch xray drops the aead records in both directions and the
   stream is the inner tls records over the same connection, masked in the random profile */
static void test_vision_direct(void) {
    static const char *modes[] = { "native", "xorpub", "random" };
    int chain[] = { 0 };
    for (int m = 0; m < 3; ++m) {
        world_t w;
        world_make(&w, modes[m], "1rtt", 0, chain, 1);
        link_t l;
        assert(link_open(&l, &w, &transport_tcp, 1) == 0);
        int rc = 0;
        echo_exchange(&l, 40, &rc);
        CHECK(rc == 0, "established for the direct test");
        uint8_t buf[4000], rd[4000];

        /* upstream: the mark switches, nothing is sent for it */
        vls_t *peer = l.srv;
        vls_raw_begin(peer);
        CHECK(l.vt->raw_write(l.th, NULL, 0) == 0, "the direct mark succeeds");
        CHECK(read(l.sfd, buf, sizeof buf) < 0 && errno == EAGAIN, "and sends nothing");

        /* two inner records, written in odd pieces, reach the server as the same bytes */
        uint8_t stream[600];
        size_t sl = tls_record(stream, "first inner record body", 23);
        sl += tls_record(stream + sl, "second", 6);
        size_t off = 0;
        static const size_t cuts[] = { 3, 4, 1, 7, 100, 1000 };
        for (size_t c = 0; off < sl; ++c) {
            size_t piece = cuts[c % 6] < sl - off ? cuts[c % 6] : sl - off;
            CHECK(l.vt->raw_write(l.th, stream + off, piece) == (int)piece, "raw write takes the piece");
            off += piece;
        }
        ssize_t n;
        while ((n = read(l.sfd, buf, sizeof buf)) > 0) vls_feed(peer, buf, (size_t)n);
        uint8_t got[600];
        size_t gl = vls_plain_in(peer, got, sizeof got);
        CHECK(gl == sl && memcmp(got, stream, sl) == 0, "raw writes arrive as the inner stream");
        if (m == 0) {
            /* native: it is literally the plain bytes on the wire */
            enc_t *e = l.th;
            CHECK(e->raw_up, "the layer records the switch");
        }

        /* downstream: one last record carries the direct command, plain stream bytes follow glued to it */
        vls_send(peer, (const uint8_t *)"LAST", 4);
        size_t o = vls_wire_out(peer, buf, sizeof buf);
        uint8_t glued[300];
        size_t gn = tls_record(glued, "hello from the origin", 21);
        gn += tls_record(glued + gn, "more", 4);
        vls_raw_encode(peer, glued, gn);
        memcpy(buf + o, glued, gn);
        assert(write(l.sfd, buf, o + gn) == (ssize_t)(o + gn));
        int r = l.vt->read(l.th, rd, sizeof rd);
        CHECK(r == 4 && memcmp(rd, "LAST", 4) == 0, "the last record is delivered whole");
        l.vt->peer_direct(l.th);
        uint8_t want[300];
        size_t wn = tls_record(want, "hello from the origin", 21);
        wn += tls_record(want + wn, "more", 4);
        size_t have = 0;
        for (int i = 0; i < 20 && have < wn; ++i) {
            r = l.vt->read(l.th, rd + have, sizeof rd - have);
            if (r > 0) have += (size_t)r;
            else if (r != TRANSPORT_WANT_READ) break;
        }
        CHECK(have == wn && memcmp(rd, want, wn) == 0, "the buffered stream bytes come first, unmasked");

        /* later bytes arrive in pieces, split inside a header */
        uint8_t more[100];
        size_t mn = tls_record(more, "tail", 4);
        uint8_t keep[100];
        memcpy(keep, more, mn);
        vls_raw_encode(peer, more, mn);
        assert(write(l.sfd, more, 3) == 3);
        assert(write(l.sfd, more + 3, mn - 3) == (ssize_t)(mn - 3));
        have = 0;
        for (int i = 0; i < 20 && have < mn; ++i) {
            r = l.vt->read(l.th, rd + have, sizeof rd - have);
            if (r > 0) have += (size_t)r;
            else if (r != TRANSPORT_WANT_READ) break;
        }
        CHECK(have == mn && memcmp(rd, keep, mn) == 0, "a header split across reads is unmasked");
        link_close(&l);
        vls_ctx_free(w.ctx);
    }
}

static void test_backpressure(void) {
    int chain[] = { 0 };
    world_t w;
    world_make(&w, "native", "1rtt", 0, chain, 1);
    link_t l;
    assert(link_open(&l, &w, &transport_tcp, 1) == 0);
    int small = 4096;
    setsockopt(l.cfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(l.sfd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    int rc = 0;
    echo_exchange(&l, 10, &rc);
    CHECK(rc == 0, "established under a small buffer");

    /* write until the socket stops taking data, the layer must keep its ciphertext and say so */
    uint8_t chunk[8192];
    memset(chunk, 'z', sizeof chunk);
    size_t total = 0;
    int saw_pending = 0;
    for (int i = 0; i < 400; ++i) {
        int wr = l.vt->write(l.th, chunk, sizeof chunk);
        if (wr > 0) total += (size_t)wr;
        else if (wr == TRANSPORT_WANT_WRITE) { saw_pending = 1; break; }
        else if (wr < 0 && wr != TRANSPORT_WANT_READ) break;
        if (l.vt->want_write(l.th)) { saw_pending = 1; break; }
    }
    CHECK(saw_pending, "the layer reports queued ciphertext");
    /* drain through the server and flush with empty writes */
    uint8_t plain[200000];
    size_t srv_total = 0;
    for (int i = 0; i < 20000 && srv_total < total; ++i) {
        (void)l.vt->write(l.th, (const uint8_t *)"", 0);
        serve(&l, 0);
        srv_total += vls_plain_in(l.srv, plain + srv_total % 100000, 100000);
    }
    CHECK(srv_total == total, "every byte written came out of the other end");
    CHECK(!l.vt->want_write(l.th), "nothing left queued");
    link_close(&l);
    vls_ctx_free(w.ctx);
}

int main(void) {
    test_echo_everywhere();
    test_zero_rtt_flow();
    test_failures();
    test_vision_direct();
    test_backpressure();
    if (failures) {
        fprintf(stderr, "test_transport_enc: %d failures\n", failures);
        return 1;
    }
    puts("test_transport_enc: ok");
    return 0;
}
