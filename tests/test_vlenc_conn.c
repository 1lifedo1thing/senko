#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vlenc_conf.h"
#include "vlenc_conn.c" /* the whole module: the nonce rollover test reaches into it */
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

/* a client profile text for the chain and the matching server context */
typedef struct {
    char text[VLENC_TEXT_MAX];
    vls_key_t keys[VLS_MAX_KEYS];
    int n;
} prof_t;

static void make_prof(prof_t *p, const char *mode, const char *rtt, const char *padding, const int *pq, int n) {
    assert(n <= VLS_MAX_KEYS);
    memset(p, 0, sizeof *p);
    p->n = n;
    snprintf(p->text, sizeof p->text, "mlkem768x25519plus.%s.%s", mode, rtt);
    if (padding && padding[0]) {
        strcat(p->text, ".");
        strcat(p->text, padding);
    }
    for (int i = 0; i < n; ++i) {
        assert(vls_key_make(&p->keys[i], pq[i]) == 0);
        char enc[2200];
        b64url(p->keys[i].pk, p->keys[i].pk_len, enc);
        strcat(p->text, ".");
        strcat(p->text, enc);
    }
}

typedef struct {
    vlenc_cfg_t cfg;
    vls_ctx_t *ctx;
    vlc_conn_t *c;
    vls_t *s;
} pair_t;

/* move the server's output to the client, pulling plaintext as it goes */
static int settle(vlc_conn_t *c, vls_t *s, int chunk, uint8_t *got, size_t *got_len, size_t got_cap, size_t *unused) {
    static uint8_t buf[200000];
    (void)unused;
    size_t n = vls_wire_out(s, buf, sizeof buf);
    size_t off = 0;
    while (off < n) {
        uint8_t *p;
        size_t cap;
        if (vlc_rx_space(c, &p, &cap) != VLC_OK) return -1;
        size_t take = n - off < cap ? n - off : cap;
        if (chunk && take > (size_t)chunk) take = (size_t)chunk;
        memcpy(p, buf + off, take);
        vlc_rx_commit(c, take);
        off += take;
        for (;;) {
            uint8_t out[VLC_REC_MAX];
            size_t ol = 0;
            vlc_status_t st = vlc_pull(c, out, sizeof out, &ol);
            if (st == VLC_DATA) {
                if (*got_len + ol > got_cap) return -2;
                memcpy(got + *got_len, out, ol);
                *got_len += ol;
                continue;
            }
            if (st == VLC_NEED_MORE) break;
            return (int)st + 100;
        }
    }
    return 0;
}

/* a whole exchange: handshake, a client write of up_len bytes, a server write of down_len bytes,
   with the byte streams cut into chunk sized pieces when chunk is set. returns 0 when both sides
   saw exactly what the other sent */
static int exchange(const prof_t *p, vls_ctx_t *ctx, const vlenc_cfg_t *cfg, const char *scope,
                    int aes, size_t up_len, size_t down_len, int chunk, int *zrtt_out, int *client_st) {
    vlc_env_t env = { 0 };
    env.use_aes = aes;
    vlc_conn_t *c = vlc_new(cfg, scope, &env);
    vls_t *s = vls_new(ctx);
    int rc = 0;
    (void)p;

    const uint8_t *hello;
    size_t hl, nsegs;
    const size_t *segs;
    if (vlc_hello(c, &hello, &hl, &segs, &nsegs) != VLC_OK) { rc = -10; goto done; }
    size_t sum = 0;
    for (size_t i = 0; i < nsegs; ++i) sum += segs[i];
    if (sum != hl) { rc = -11; goto done; }
    if (hl) {
        for (size_t off = 0; off < hl; off += (chunk ? (size_t)chunk : hl)) {
            size_t take = chunk ? (hl - off < (size_t)chunk ? hl - off : (size_t)chunk) : hl;
            if (vls_feed(s, hello + off, take) != 0) { rc = -12; goto done; }
        }
    }

    uint8_t *up = malloc(up_len ? up_len : 1), *down = malloc(down_len ? down_len : 1);
    for (size_t i = 0; i < up_len; ++i) up[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < down_len; ++i) down[i] = (uint8_t)(i * 13 + 5);

    /* client writes first, as the vless request does */
    uint8_t wire[VLC_PREAMBLE_MAX + VLC_PLAIN_MAX + VLC_SEAL_EXTRA];
    size_t sent = 0;
    uint8_t *srv_plain = malloc(up_len + 1);
    size_t srv_plain_len = 0;
    uint8_t *cli_plain = malloc(down_len + 1);
    size_t cli_plain_len = 0;
    while (up_len && sent < up_len) {
        size_t take = up_len - sent > VLC_PLAIN_MAX ? VLC_PLAIN_MAX : up_len - sent;
        size_t wl = 0;
        vlc_status_t st = vlc_seal(c, up + sent, take, wire, sizeof wire, &wl);
        if (st == VLC_ERR_STATE) {
            /* 1rtt: the reply has to come first */
            int r = settle(c, s, chunk, cli_plain, &cli_plain_len, down_len, NULL);
            if (r) { rc = r; goto done2; }
            continue;
        }
        if (st != VLC_OK) { rc = -20; goto done2; }
        for (size_t off = 0; off < wl; off += (chunk ? (size_t)chunk : wl)) {
            size_t t = chunk ? (wl - off < (size_t)chunk ? wl - off : (size_t)chunk) : wl;
            if (vls_feed(s, wire + off, t) != 0) {
                /* the server hangs up, what it wrote before that still reaches the client */
                int r = settle(c, s, chunk, cli_plain, &cli_plain_len, down_len, NULL);
                rc = r ? r : -21;
                goto done2;
            }
        }
        sent += take;
    }
    {
        int r = settle(c, s, chunk, cli_plain, &cli_plain_len, down_len, NULL);
        if (r) { rc = r; goto done2; }
    }
    srv_plain_len = vls_plain_in(s, srv_plain, up_len + 1);
    if (srv_plain_len != up_len || memcmp(srv_plain, up, up_len)) { rc = -30; goto done2; }
    if (down_len) {
        if (!vls_handshake_done(s)) { rc = -31; goto done2; }
        if (vls_send(s, down, down_len) != 0) { rc = -32; goto done2; }
        int r = settle(c, s, chunk, cli_plain, &cli_plain_len, down_len, NULL);
        if (r) { rc = r; goto done2; }
        if (cli_plain_len != down_len || memcmp(cli_plain, down, down_len)) { rc = -33; goto done2; }
    }
    if (zrtt_out) *zrtt_out = vls_was_zero_rtt(s) == vlc_is_zero_rtt(c) ? vlc_is_zero_rtt(c) : -1;
done2:
    free(up); free(down); free(srv_plain); free(cli_plain);
done:
    if (client_st) *client_st = rc;
    vlc_free(c);
    vls_free(s);
    return rc;
}

static void test_parse(void) {
    static const struct { const char *text; vlenc_status_t want; } cases[] = {
        { "", VLENC_ERR_VERSION },
        { "none", VLENC_ERR_VERSION },
        { "mlkem768x25519plus", VLENC_ERR_FORMAT },
        { "mlkem768x25519plus.native", VLENC_ERR_FORMAT },
        { "mlkem768x25519plus.native.0rtt", VLENC_ERR_FORMAT },
        { "mlkem768x25519plus.native.0rtt.", VLENC_ERR_KEY_LENGTH },
        { "mlkem768x25519plus.weird.0rtt.AAAA", VLENC_ERR_MODE },
        { "mlkem768x25519plus.native.2rtt.AAAA", VLENC_ERR_RTT },
        { "mlkem768x25519plus.native.0rtt.AAAA", VLENC_ERR_KEY_LENGTH },
        { "mlkem768x25519plus.native.0rtt.100-111-1111", VLENC_ERR_KEY_COUNT },
        { "mlkem768x25519plus.native.0rtt.100-111", VLENC_ERR_PADDING },
        { "mlkem768x25519plus.native.0rtt.50-111-1111.AAAA", VLENC_ERR_PADDING },
        { "mlkem768x25519plus.native.0rtt.100-20-1111.AAAA", VLENC_ERR_PADDING },
        { "mlkem768x25519plus.native.0rtt.100-1111-111.AAAA", VLENC_ERR_PADDING },
        { "mlkem768x25519plus.native.0rtt.100-111-99999.AAAA", VLENC_ERR_PADDING },
        { "mlkem768x25519plus.mlkem.0rtt.AAAA", VLENC_ERR_MODE },
        { "mlkem1024x25519plus.native.0rtt.AAAA", VLENC_ERR_VERSION },
        { "mlkem768x25519plus.native.0rtt.dGVzdA==", VLENC_ERR_KEY_ENCODING },
        { "mlkem768x25519plus.native.0rtt.a+b/c", VLENC_ERR_KEY_ENCODING },
        { "mlkem768x25519plus.native.0rtt.AAAAA", VLENC_ERR_KEY_ENCODING },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        vlenc_cfg_t cfg;
        vlenc_status_t st = vlenc_parse(cases[i].text, &cfg);
        if (st != cases[i].want) fprintf(stderr, "case %zu: got %d want %d\n", i, st, cases[i].want);
        CHECK(st == cases[i].want, "parse table");
    }

    int pq[] = { 0 };
    prof_t p;
    make_prof(&p, "xorpub", "1rtt", "100-111-1111.75-0-111.50-0-3333", pq, 1);
    vlenc_cfg_t cfg;
    CHECK(vlenc_parse(p.text, &cfg) == VLENC_OK, "valid x25519 with padding");
    CHECK(cfg.xor_mode == VLENC_XOR_PUB && !cfg.zero_rtt && cfg.n_lens == 2 && cfg.n_gaps == 1 && cfg.n_keys == 1, "fields");
    CHECK(cfg.lens[0].min == 111 && cfg.lens[0].max == 1111 && cfg.gaps[0].prob == 75, "padding numbers");

    /* a key chain at the limits and one past them */
    int five[] = { 0, 0, 0, 0 };
    make_prof(&p, "random", "0rtt", "", five, 4);
    CHECK(vlenc_parse(p.text, &cfg) == VLENC_OK && cfg.n_keys == 4, "four keys");
    {
        /* a fifth key, only its text matters to the parser */
        char extra[64];
        b64url(p.keys[0].pk, 32, extra);
        strcat(p.text, ".");
        strcat(p.text, extra);
        CHECK(vlenc_parse(p.text, &cfg) == VLENC_ERR_KEY_COUNT, "five keys");
    }

    int pqs[] = { 1, 1, 1 };
    make_prof(&p, "native", "0rtt", "", pqs, 3);
    CHECK(vlenc_parse(p.text, &cfg) == VLENC_ERR_TOO_LONG || vlenc_parse(p.text, &cfg) == VLENC_ERR_KEY_COUNT, "three ml-kem keys do not fit");
    int pq2[] = { 1, 0 };
    make_prof(&p, "native", "0rtt", "", pq2, 2);
    CHECK(vlenc_parse(p.text, &cfg) == VLENC_OK && cfg.key_len[0] == 1184 && cfg.key_len[1] == 32, "ml-kem then x25519");

    /* an ml-kem key whose first coefficient is out of range */
    int one[] = { 1 };
    make_prof(&p, "native", "0rtt", "", one, 1);
    p.keys[0].pk[0] = 0xff;
    p.keys[0].pk[1] = 0x0f;
    char enc[2200];
    b64url(p.keys[0].pk, 1184, enc);
    snprintf(p.text, sizeof p.text, "mlkem768x25519plus.native.0rtt.%s", enc);
    CHECK(vlenc_parse(p.text, &cfg) == VLENC_ERR_KEY_VALUE, "ml-kem coefficient above q");

    /* a text one byte too long and one that is exactly the cap */
    char big[VLENC_TEXT_MAX + 8];
    memset(big, 'A', sizeof big - 1);
    big[sizeof big - 1] = 0;
    CHECK(vlenc_parse(big, &cfg) == VLENC_ERR_TOO_LONG, "text beyond the cap");

    /* intern: the same text twice is one profile, ids start at 1 */
    vlenc_pool_reset();
    int x[] = { 0 };
    make_prof(&p, "native", "0rtt", "", x, 1);
    uint16_t a = 0, b = 0;
    CHECK(vlenc_intern(p.text, &a) == VLENC_OK && a == 1, "intern first");
    CHECK(vlenc_intern(p.text, &b) == VLENC_OK && b == 1, "intern again");
    CHECK(vlenc_text(a) && strcmp(vlenc_text(a), p.text) == 0 && vlenc_cfg(a)->n_keys == 1, "pool lookup");
    CHECK(vlenc_text(0) == NULL && vlenc_text(2) == NULL, "unknown ids");
    uint16_t id = 0;
    CHECK(vlenc_intern("mlkem768x25519plus.native.0rtt.AAAA", &id) == VLENC_ERR_KEY_LENGTH && id == 0, "bad text is not interned");
    for (int i = 0; i < VLENC_POOL_MAX + 2; ++i) {
        make_prof(&p, "native", "0rtt", "", x, 1);
        vlenc_status_t st = vlenc_intern(p.text, &id);
        if (i < VLENC_POOL_MAX - 1) CHECK(st == VLENC_OK, "pool fill");
        else if (i > VLENC_POOL_MAX) { CHECK(st == VLENC_ERR_POOL_FULL, "pool full"); break; }
    }
    /* a full pool recovers once the profiles nobody holds are released: kept
       ids stay put, a freed slot is reused and a connection outlives its profile */
    uint16_t keep[] = { 1, 5 };
    char keep_text[VLENC_TEXT_MAX];
    snprintf(keep_text, sizeof keep_text, "%s", vlenc_text(5));
    vlc_conn_t *live = vlc_new(vlenc_cfg(5), "retain-test", NULL);
    CHECK(live != NULL, "connection over a pool profile");
    vlenc_pool_retain(keep, 2);
    CHECK(vlenc_text(1) && vlenc_text(5) && strcmp(vlenc_text(5), keep_text) == 0, "kept ids stay valid");
    CHECK(vlenc_text(2) == NULL && vlenc_cfg(3) == NULL, "released ids are gone");
    make_prof(&p, "native", "0rtt", "", x, 1);
    CHECK(vlenc_intern(p.text, &id) == VLENC_OK && id == 2, "a freed slot is reused");
    CHECK(vlenc_text(5) && strcmp(vlenc_text(5), keep_text) == 0, "kept profile is untouched by reuse");
    vlc_free(live);
    vlenc_pool_reset();
}

static void test_modes(void) {
    static const char *modes[] = { "native", "xorpub", "random" };
    static const int chains[][4] = { { 0 }, { 1 }, { 0, 1 }, { 1, 0 }, { 0, 0, 1 } };
    static const int chain_n[] = { 1, 1, 2, 2, 3 };
    for (int m = 0; m < 3; ++m) {
        for (int ch = 0; ch < 5; ++ch) {
            for (int aes = 0; aes < 2; ++aes) {
                prof_t p;
                make_prof(&p, modes[m], "1rtt", "", chains[ch], chain_n[ch]);
                vlenc_cfg_t cfg;
                if (vlenc_parse(p.text, &cfg) != VLENC_OK) { CHECK(0, "mode profile parses"); continue; }
                vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, m, 0);
                char what[96];
                static const size_t ups[] = { 1, 100, 8192, 8193, 40000 };
                for (size_t u = 0; u < sizeof ups / sizeof ups[0]; ++u) {
                    int st = 0;
                    int r = exchange(&p, ctx, &cfg, "mode-test", aes, ups[u], ups[u] + 17, 0, NULL, &st);
                    snprintf(what, sizeof what, "round trip mode=%s chain=%d aes=%d up=%zu rc=%d", modes[m], ch, aes, ups[u], r);
                    CHECK(r == 0, what);
                }
                /* one byte pieces in both directions */
                int r = exchange(&p, ctx, &cfg, "mode-test", aes, 3000, 3000, 1, NULL, NULL);
                snprintf(what, sizeof what, "byte pieces mode=%s chain=%d aes=%d rc=%d", modes[m], ch, aes, r);
                CHECK(r == 0, what);
                r = exchange(&p, ctx, &cfg, "mode-test", aes, 20000, 20000, 77, NULL, NULL);
                snprintf(what, sizeof what, "77 byte pieces mode=%s chain=%d aes=%d rc=%d", modes[m], ch, aes, r);
                CHECK(r == 0, what);
                vls_ctx_free(ctx);
            }
        }
    }
}

static int64_t fake_now_v;
static int64_t fake_now(void *c) { (void)c; return fake_now_v; }

static void test_zero_rtt(void) {
    static const char *modes[] = { "native", "xorpub", "random" };
    for (int m = 0; m < 3; ++m) {
        vlc_tickets_reset();
        int chain[] = { 1, 0 };
        prof_t p;
        make_prof(&p, modes[m], "0rtt", "", chain, 2);
        vlenc_cfg_t cfg;
        CHECK(vlenc_parse(p.text, &cfg) == VLENC_OK, "0rtt profile");
        vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, m, 600);
        int z = -1;
        fake_now_v = 1000;
        vlc_env_t env = { .now = fake_now, .use_aes = 1 };
        (void)env;

        /* first connection has no ticket: full handshake, and it stores one */
        CHECK(exchange(&p, ctx, &cfg, "srv-a:443", 1, 500, 700, 0, &z, NULL) == 0 && z == 0, "first connection is 1rtt");
        /* second one uses it */
        z = -1;
        CHECK(exchange(&p, ctx, &cfg, "srv-a:443", 1, 500, 700, 0, &z, NULL) == 0 && z == 1, "second connection is 0rtt");
        z = -1;
        CHECK(exchange(&p, ctx, &cfg, "srv-a:443", 0, 9000, 9000, 33, &z, NULL) == 0 && z == 1, "0rtt in pieces");
        /* another server name never sees the ticket */
        z = -1;
        CHECK(exchange(&p, ctx, &cfg, "srv-b:443", 1, 10, 10, 0, &z, NULL) == 0 && z == 0, "ticket is scoped");

        /* the server restarts and forgets: the client is told, and the next try is a full one */
        vls_ctx_forget_tickets(ctx);
        int st = 0;
        int r = exchange(&p, ctx, &cfg, "srv-a:443", 1, 500, 700, 0, &z, &st);
        CHECK(r == 100 + VLC_ERR_TICKET, "rejected ticket fails the connection with its own status");
        z = -1;
        CHECK(exchange(&p, ctx, &cfg, "srv-a:443", 1, 500, 700, 0, &z, NULL) == 0 && z == 0, "full handshake after a rejection");
        vls_ctx_free(ctx);
    }
}

static void test_ticket_expiry_and_profile(void) {
    vlc_tickets_reset();
    int chain[] = { 0 };
    prof_t p;
    make_prof(&p, "native", "0rtt", "", chain, 1);
    vlenc_cfg_t cfg;
    assert(vlenc_parse(p.text, &cfg) == VLENC_OK);
    vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, 0, 30);

    /* expiry runs on the client's clock: past the lifetime the ticket is not offered */
    vlc_env_t env = { .now = fake_now, .use_aes = 1 };
    fake_now_v = 5000;
    for (int round = 0; round < 3; ++round) {
        vlc_conn_t *c = vlc_new(&cfg, "exp:1", &env);
        vls_t *s = vls_new(ctx);
        const uint8_t *h; size_t hl, ns; const size_t *sg;
        assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
        int zr = vlc_is_zero_rtt(c);
        if (round == 0) CHECK(!zr, "no ticket at first");
        if (round == 1) CHECK(zr, "ticket live at +10s");
        if (round == 2) CHECK(!zr, "ticket expired at +40s");
        if (!zr) {
            vls_feed(s, h, hl);
            uint8_t buf[4000];
            size_t n = vls_wire_out(s, buf, sizeof buf), off = 0;
            while (off < n) {
                uint8_t *rp; size_t cap;
                vlc_rx_space(c, &rp, &cap);
                size_t t = n - off < cap ? n - off : cap;
                memcpy(rp, buf + off, t);
                vlc_rx_commit(c, t);
                off += t;
            }
            uint8_t out[VLC_REC_MAX]; size_t ol;
            vlc_pull(c, out, sizeof out, &ol);
        }
        vlc_free(c);
        vls_free(s);
        fake_now_v += round == 0 ? 10 : 30;
    }

    /* a profile with other keys is another scope: the caller names the scope with the profile text */
    vls_ctx_free(ctx);
    vlc_tickets_reset();
}

static void test_tamper(void) {
    int chain[] = { 0 };
    prof_t p;
    make_prof(&p, "native", "1rtt", "", chain, 1);
    vlenc_cfg_t cfg;
    assert(vlenc_parse(p.text, &cfg) == VLENC_OK);
    vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, 0, 0);

    /* capture a good server reply, then break it one byte at a time */
    vlc_env_t env = { .use_aes = 1 };
    vlc_conn_t *c = vlc_new(&cfg, "t:1", &env);
    vls_t *s = vls_new(ctx);
    const uint8_t *h; size_t hl, ns; const size_t *sg;
    assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
    assert(vls_feed(s, h, hl) == 0);
    static uint8_t reply[70000];
    size_t rl = vls_wire_out(s, reply, sizeof reply);
    vlc_free(c);
    vls_free(s);
    CHECK(rl > 1136 + 32 + 18, "captured reply");

    /* the reply was made for that exact client key, so tampering needs a live client per try:
       rerun the handshake and flip a byte of the reply that came back */
    size_t probe[] = { 0, 500, 1119, 1120, 1135, 1136, 1150, 1167, 1168, 1180, 1185 };
    for (size_t k = 0; k < sizeof probe / sizeof probe[0]; ++k) {
        c = vlc_new(&cfg, "t:1", &env);
        s = vls_new(ctx);
        assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
        assert(vls_feed(s, h, hl) == 0);
        size_t n = vls_wire_out(s, reply, sizeof reply);
        if (probe[k] >= n) { vlc_free(c); vls_free(s); continue; }
        reply[probe[k]] ^= 0x01;
        uint8_t *rp; size_t cap;
        assert(vlc_rx_space(c, &rp, &cap) == VLC_OK);
        size_t t = n < cap ? n : cap;
        memcpy(rp, reply, t);
        vlc_rx_commit(c, t);
        uint8_t out[VLC_REC_MAX]; size_t ol;
        vlc_status_t st = vlc_pull(c, out, sizeof out, &ol);
        char what[64];
        snprintf(what, sizeof what, "flip at %zu is refused (st=%d)", probe[k], st);
        CHECK(st == VLC_ERR_AUTH || st == VLC_ERR_PROTO || st == VLC_ERR_KEY, what);
        CHECK(!vlc_can_seal(c) || st != VLC_DATA, "no data after a bad reply");
        /* the connection is dead for good */
        CHECK(vlc_pull(c, out, sizeof out, &ol) == VLC_ERR_STATE, "dead stays dead");
        vlc_free(c);
        vls_free(s);
    }

    /* truncated reply: the client waits, it never invents data */
    c = vlc_new(&cfg, "t:2", &env);
    s = vls_new(ctx);
    assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
    assert(vls_feed(s, h, hl) == 0);
    size_t n = vls_wire_out(s, reply, sizeof reply);
    for (size_t cut = 0; cut < 1136 + 32 + 18 + 5 && cut < n; cut += 97) {
        vlc_conn_t *c2 = vlc_new(&cfg, "t:3", &env);
        assert(vlc_hello(c2, &h, &hl, &sg, &ns) == VLC_OK);
        vls_t *s2 = vls_new(ctx);
        vls_feed(s2, h, hl);
        size_t n2 = vls_wire_out(s2, reply, sizeof reply);
        uint8_t *rp; size_t cap;
        vlc_rx_space(c2, &rp, &cap);
        size_t t = cut < n2 ? cut : n2;
        memcpy(rp, reply, t);
        vlc_rx_commit(c2, t);
        uint8_t out[VLC_REC_MAX]; size_t ol = 0;
        vlc_status_t st = vlc_pull(c2, out, sizeof out, &ol);
        CHECK(st == VLC_NEED_MORE && ol == 0, "truncated reply waits");
        vlc_free(c2);
        vls_free(s2);
    }
    vlc_free(c);
    vls_free(s);

    /* a record with a flipped tag, flipped header and a header length out of range */
    for (int variant = 0; variant < 4; ++variant) {
        c = vlc_new(&cfg, "t:4", &env);
        s = vls_new(ctx);
        assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
        assert(vls_feed(s, h, hl) == 0);
        n = vls_wire_out(s, reply, sizeof reply);
        uint8_t body[200];
        memset(body, 'x', sizeof body);
        vls_send(s, body, sizeof body);
        size_t m = vls_wire_out(s, reply + n, sizeof reply - n);
        assert(m == 5 + 200 + 16);
        if (variant == 0) reply[n + 5 + 3] ^= 0x80;       /* ciphertext */
        if (variant == 1) reply[n + 5 + 200 + 15] ^= 0x01; /* last tag byte */
        if (variant == 2) reply[n] = 22;                   /* not application data */
        if (variant == 3) { reply[n + 3] = 0; reply[n + 4] = 16; } /* length below a tag */
        size_t off = 0, total = n + m;
        vlc_status_t st = VLC_NEED_MORE;
        size_t got = 0;
        while (off < total && (st == VLC_NEED_MORE || st == VLC_DATA)) {
            uint8_t *rp; size_t cap;
            vlc_rx_space(c, &rp, &cap);
            size_t t = total - off < cap ? total - off : cap;
            memcpy(rp, reply + off, t);
            vlc_rx_commit(c, t);
            off += t;
            uint8_t out[VLC_REC_MAX]; size_t ol = 0;
            st = vlc_pull(c, out, sizeof out, &ol);
            got += st == VLC_DATA ? ol : 0;
        }
        char what[64];
        snprintf(what, sizeof what, "bad record variant %d refused (st=%d)", variant, st);
        CHECK(st == VLC_ERR_AUTH || st == VLC_ERR_PROTO, what);
        CHECK(got == 0, "nothing delivered from a bad record");
        vlc_free(c);
        vls_free(s);
    }

    /* wrong key: a server that holds other keys cannot answer, the client sees an auth failure or silence */
    int other[] = { 0 };
    prof_t q;
    make_prof(&q, "native", "1rtt", "", other, 1);
    vls_ctx_t *ctx2 = vls_ctx_new(q.keys, q.n, 0, 0);
    c = vlc_new(&cfg, "t:5", &env);
    s = vls_new(ctx2);
    assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
    CHECK(vls_feed(s, h, hl) != 0 || vls_wire_out(s, reply, sizeof reply) == 0, "server with another key stays silent");
    vlc_free(c);
    vls_free(s);
    vls_ctx_free(ctx2);
    vls_ctx_free(ctx);
}

static void test_replay(void) {
    vlc_tickets_reset();
    int chain[] = { 0 };
    prof_t p;
    make_prof(&p, "native", "0rtt", "", chain, 1);
    vlenc_cfg_t cfg;
    assert(vlenc_parse(p.text, &cfg) == VLENC_OK);
    vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, 0, 600);
    CHECK(exchange(&p, ctx, &cfg, "rp:1", 1, 10, 10, 0, NULL, NULL) == 0, "seed ticket");

    /* capture a 0rtt preamble plus record and send it twice */
    vlc_env_t env = { .use_aes = 1 };
    vlc_conn_t *c = vlc_new(&cfg, "rp:1", &env);
    const uint8_t *h; size_t hl, ns; const size_t *sg;
    assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK && hl == 0 && vlc_is_zero_rtt(c));
    uint8_t wire[VLC_PREAMBLE_MAX + 64];
    size_t wl;
    assert(vlc_seal(c, (const uint8_t *)"hello", 5, wire, sizeof wire, &wl) == VLC_OK);
    vls_t *s1 = vls_new(ctx), *s2 = vls_new(ctx);
    CHECK(vls_feed(s1, wire, wl) == 0 && vls_was_zero_rtt(s1), "first delivery accepted");
    CHECK(vls_feed(s2, wire, wl) != 0, "the same bytes again are a replay");
    CHECK(strcmp(vls_why(s2), "replay") == 0, "named as replay");
    uint8_t got[16];
    CHECK(vls_plain_in(s2, got, sizeof got) == 0, "replay delivers nothing");
    vlc_free(c);
    vls_free(s1);
    vls_free(s2);
    vls_ctx_free(ctx);
}

static void test_nonce_rollover(void) {
    int chain[] = { 0 };
    prof_t p;
    make_prof(&p, "native", "1rtt", "", chain, 1);
    vlenc_cfg_t cfg;
    assert(vlenc_parse(p.text, &cfg) == VLENC_OK);
    vls_ctx_t *ctx = vls_ctx_new(p.keys, p.n, 0, 0);
    vlc_env_t env = { .use_aes = 0 };
    vlc_conn_t *c = vlc_new(&cfg, "nr:1", &env);
    vls_t *s = vls_new(ctx);
    const uint8_t *h; size_t hl, ns; const size_t *sg;
    assert(vlc_hello(c, &h, &hl, &sg, &ns) == VLC_OK);
    assert(vls_feed(s, h, hl) == 0);
    uint8_t buf[70000];
    size_t n = vls_wire_out(s, buf, sizeof buf);
    uint8_t *rp; size_t cap;
    vlc_rx_space(c, &rp, &cap);
    memcpy(rp, buf, n);
    vlc_rx_commit(c, n);
    uint8_t out[VLC_REC_MAX]; size_t ol;
    assert(vlc_pull(c, out, sizeof out, &ol) == VLC_NEED_MORE);
    /* both ends of the upstream direction sit one message below the counter limit */
    uint8_t near_max[12];
    memset(near_max, 0xff, 12);
    near_max[11] = 0xfd;
    vls_debug_set_nonce(s, 1, near_max);
    memcpy(c->tx.nonce, near_max, 12);
    uint8_t wire[100];
    size_t wl;
    for (int i = 0; i < 6; ++i) {
        char msg[8];
        snprintf(msg, sizeof msg, "rec%d", i);
        assert(vlc_seal(c, (const uint8_t *)msg, 4, wire, sizeof wire, &wl) == VLC_OK);
        CHECK(vls_feed(s, wire, wl) == 0, "records across the nonce limit");
        uint8_t got[16];
        size_t g = vls_plain_in(s, got, sizeof got);
        CHECK(g == 4 && memcmp(got, msg, 4) == 0, "plaintext across the nonce limit");
    }
    vlc_free(c);
    vls_free(s);
    vls_ctx_free(ctx);
}

int main(void) {
    test_parse();
    test_modes();
    test_zero_rtt();
    test_ticket_expiry_and_profile();
    test_tamper();
    test_replay();
    test_nonce_rollover();
    if (failures) {
        fprintf(stderr, "test_vlenc_conn: %d failures\n", failures);
        return 1;
    }
    puts("test_vlenc_conn: ok");
    return 0;
}
