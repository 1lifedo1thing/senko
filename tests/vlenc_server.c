#include "vlenc_server.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"
#include "reality_crypto.h"

typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
    int aes;
} sa_t;

static const uint8_t MAXN[12] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };

static void sa_init(sa_t *a, const uint8_t *ctx, size_t cl, const uint8_t *key, size_t kl, int aes) {
    blake3_derive_key(ctx, cl, key, kl, a->key);
    memset(a->nonce, 0, 12);
    a->aes = aes;
}

static void inc(uint8_t n[12]) {
    for (int i = 11; i >= 0; --i)
        if (++n[i]) break;
}

static int sa_seal(sa_t *a, const uint8_t *nonce, const uint8_t *aad, size_t al,
                   const uint8_t *in, size_t n, uint8_t *out) {
    if (!nonce) { inc(a->nonce); nonce = a->nonce; }
    return (a->aes ? rc_aes256gcm_seal(a->key, nonce, aad, al, in, n, out, out + n)
                   : rc_chacha20poly1305_seal(a->key, nonce, aad, al, in, n, out, out + n)) == RC_OK ? 0 : -1;
}

static int sa_open(sa_t *a, const uint8_t *nonce, const uint8_t *aad, size_t al,
                   const uint8_t *in, size_t n, uint8_t *out) {
    if (!nonce) { inc(a->nonce); nonce = a->nonce; }
    return (a->aes ? rc_aes256gcm_open(a->key, nonce, aad, al, in, n, in + n, out)
                   : rc_chacha20poly1305_open(a->key, nonce, aad, al, in, n, in + n, out)) == RC_OK ? 0 : -1;
}

static EVP_CIPHER_CTX *ctr(const uint8_t *key, size_t kl, const uint8_t *iv) {
    uint8_t k[32];
    blake3_derive_key("VLESS", 5, key, kl, k);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(x, EVP_aes_256_ctr(), NULL, k, iv);
    return x;
}

static void ctrx(EVP_CIPHER_CTX *x, uint8_t *p, size_t n) {
    int o;
    EVP_EncryptUpdate(x, p, &o, p, (int)n);
}

typedef struct {
    int used;
    uint8_t ticket[16];
    uint8_t pfs[64];
    uint8_t seen[8][32];
    int nseen;
} sess_t;

struct vls_ctx {
    vls_key_t keys[VLS_MAX_KEYS];
    int nkeys;
    int xor_mode;
    int seconds;
    sess_t sess[32];
};

vls_ctx_t *vls_ctx_new(const vls_key_t *keys, int nkeys, int xor_mode, int ticket_seconds) {
    vls_ctx_t *x = calloc(1, sizeof *x);
    memcpy(x->keys, keys, (size_t)nkeys * sizeof *keys);
    x->nkeys = nkeys;
    x->xor_mode = xor_mode;
    x->seconds = ticket_seconds;
    return x;
}

void vls_ctx_free(vls_ctx_t *x) { free(x); }
void vls_ctx_forget_tickets(vls_ctx_t *x) { memset(x->sess, 0, sizeof x->sess); }

int vls_key_make(vls_key_t *k, int pq) {
    memset(k, 0, sizeof *k);
    k->pq = pq;
    if (pq) {
        k->pk_len = 1184;
        k->sk_len = 2400;
        return rc_mlkem768_keygen(k->pk, k->sk) == RC_OK ? 0 : -1;
    }
    k->sk_len = 32;
    k->pk_len = 32;
    if (RAND_bytes(k->sk, 32) != 1) return -1;
    return rc_x25519_public(k->sk, k->pk) == RC_OK ? 0 : -1;
}

typedef enum { S_HELLO, S_LEN, S_Z_TICKET, S_PFS, S_CPADLEN, S_CPAD, S_READY, S_DEAD } sst_t;

struct vls {
    vls_ctx_t *x;
    sst_t st;
    const char *why;
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len, out_cap;
    uint8_t *plain;
    size_t plain_len;
    uint8_t iv[16];
    uint8_t nfs[32];
    sa_t nfs_a, tx, rx;
    int aes;
    uint8_t united[96];
    uint8_t pfs[64];
    uint8_t ticket[16];
    EVP_CIPHER_CTX *ctx_tx, *ctx_rx;
    int zrtt;
    int done;
    size_t pending_len;
    uint8_t hdr[5];
    int have_hdr;
    size_t rec;
    size_t cpad;
    uint8_t pre[16];
    size_t pre_len;
    uint8_t client_pfs[1216];
    size_t first_rec_left;
    int raw;
    size_t out_skip, in_skip, out_hl, in_hl;
    uint8_t out_hdr[5], in_hdr[5];
};

vls_t *vls_new(vls_ctx_t *x) {
    vls_t *s = calloc(1, sizeof *s);
    s->x = x;
    s->aes = 1;
    return s;
}

void vls_free(vls_t *s) {
    if (!s) return;
    if (s->ctx_tx) EVP_CIPHER_CTX_free(s->ctx_tx);
    if (s->ctx_rx) EVP_CIPHER_CTX_free(s->ctx_rx);
    free(s->in);
    free(s->out);
    free(s->plain);
    free(s);
}

const char *vls_why(const vls_t *s) { return s->why ? s->why : "none"; }
int vls_handshake_done(const vls_t *s) { return s->st == S_READY; }
int vls_was_zero_rtt(const vls_t *s) { return s->zrtt; }

static int dead(vls_t *s, const char *why) {
    s->st = S_DEAD;
    s->why = why;
    return -1;
}

static void emit(vls_t *s, const uint8_t *p, size_t n) {
    if (s->out_len + n > s->out_cap) {
        s->out_cap = (s->out_len + n) * 2;
        s->out = realloc(s->out, s->out_cap);
    }
    memcpy(s->out + s->out_len, p, n);
    s->out_len += n;
}

static void be16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static size_t relays_total(const vls_ctx_t *x) {
    size_t n = 0;
    for (int j = 0; j < x->nkeys; ++j) n += (x->keys[j].pq ? 1088 : 32) + 32;
    return n - 32;
}

static int do_relays(vls_t *s, uint8_t *relays) {
    EVP_CIPHER_CTX *last = NULL;
    for (int j = 0; j < s->x->nkeys; ++j) {
        const vls_key_t *k = &s->x->keys[j];
        size_t index = k->pq ? 1088 : 32;
        if (last) ctrx(last, relays, 32);
        if (s->x->xor_mode > 0) {
            EVP_CIPHER_CTX *m = ctr(k->pk, k->pk_len, s->iv);
            ctrx(m, relays, index);
            EVP_CIPHER_CTX_free(m);
        }
        if (!k->pq) {
            if (relays[31] > 127) { if (last) EVP_CIPHER_CTX_free(last); return dead(s, "x25519 high bit"); }
            if (rc_x25519_shared(k->sk, relays, s->nfs) != RC_OK) { if (last) EVP_CIPHER_CTX_free(last); return dead(s, "ecdh"); }
        } else if (rc_mlkem768_decap(relays, k->sk, s->nfs) != RC_OK) {
            if (last) EVP_CIPHER_CTX_free(last);
            return dead(s, "decap");
        }
        if (j + 1 == s->x->nkeys) break;
        relays += index;
        if (last) EVP_CIPHER_CTX_free(last);
        last = ctr(s->nfs, 32, s->iv);
        ctrx(last, relays, 32);
        uint8_t h[32];
        blake3_hash(s->x->keys[j + 1].pk, s->x->keys[j + 1].pk_len, h);
        if (memcmp(h, relays, 32) != 0) { EVP_CIPHER_CTX_free(last); return dead(s, "relay hash"); }
        relays += 32;
    }
    if (last) EVP_CIPHER_CTX_free(last);
    return 0;
}

static int step(vls_t *s) {
    uint8_t *p = s->in;
    size_t n = s->in_len, used = 0;
    size_t rl = relays_total(s->x);
    for (;;) {
        p = s->in + used;
        n = s->in_len - used;
        switch (s->st) {
        case S_HELLO: {
            if (n < 16 + rl) goto more;
            memcpy(s->iv, p, 16);
            uint8_t *relays = malloc(rl ? rl : 1);
            memcpy(relays, p + 16, rl);
            int r = do_relays(s, relays);
            free(relays);
            if (r) return -1;
            sa_init(&s->nfs_a, s->iv, 16, s->nfs, 32, s->aes);
            used += 16 + rl;
            s->st = S_LEN;
            break;
        }
        case S_LEN: {
            if (n < 18) goto more;
            uint8_t b[2];
            if (sa_open(&s->nfs_a, NULL, NULL, 0, p, 2, b)) {
                s->aes = !s->aes; /* the client may run the other cipher */
                sa_init(&s->nfs_a, s->iv, 16, s->nfs, 32, s->aes);
                if (sa_open(&s->nfs_a, NULL, NULL, 0, p, 2, b)) return dead(s, "length tag");
            }
            s->pending_len = (size_t)b[0] << 8 | b[1];
            used += 18;
            if (s->pending_len == 32) {
                if (!s->x->seconds) return dead(s, "0rtt refused");
                s->st = S_Z_TICKET;
            } else {
                if (s->pending_len < 1184 + 32 + 16) return dead(s, "short pfs");
                s->st = S_PFS;
            }
            break;
        }
        case S_Z_TICKET: {
            if (n < 32) goto more;
            uint8_t t[16];
            if (sa_open(&s->nfs_a, NULL, NULL, 0, p, 16, t)) return dead(s, "ticket tag");
            sess_t *se = NULL;
            for (int i = 0; i < 32; ++i)
                if (s->x->sess[i].used && memcmp(s->x->sess[i].ticket, t, 16) == 0) se = &s->x->sess[i];
            if (!se) {
                /* noise that cannot parse as a record header */
                uint8_t noise[1300];
                do { RAND_bytes(noise, sizeof noise); } while (noise[0] == 23 && noise[1] == 3 && noise[2] == 3);
                emit(s, noise, sizeof noise);
                return dead(s, "expired ticket");
            }
            for (int i = 0; i < se->nseen; ++i)
                if (memcmp(se->seen[i], s->nfs, 32) == 0) return dead(s, "replay");
            if (se->nseen < 8) memcpy(se->seen[se->nseen++], s->nfs, 32);
            memcpy(s->united, se->pfs, 64);
            memcpy(s->united + 64, s->nfs, 32);
            RAND_bytes(s->pre, 16);
            sa_init(&s->tx, s->pre, 16, s->united, 96, s->aes);
            sa_init(&s->rx, p, 32, s->united, 96, s->aes);
            if (s->x->xor_mode == 2) {
                s->ctx_tx = ctr(s->united, 96, s->pre);
                s->ctx_rx = ctr(s->united, 96, s->iv);
            }
            emit(s, s->pre, 16);
            used += 32;
            s->zrtt = 1;
            s->st = S_READY;
            break;
        }
        case S_PFS: {
            size_t L = s->pending_len;
            if (n < L) goto more;
            uint8_t *pl = malloc(L);
            if (sa_open(&s->nfs_a, NULL, NULL, 0, p, L - 16, pl)) { free(pl); return dead(s, "pfs tag"); }
            uint8_t mlkem[32], sct[1088], x[32], spub[32], spriv[32];
            if (rc_mlkem768_encap(pl, sct, mlkem) != RC_OK) { free(pl); return dead(s, "encap"); }
            RAND_bytes(spriv, 32);
            rc_x25519_public(spriv, spub);
            if (rc_x25519_shared(spriv, pl + 1184, x) != RC_OK) { free(pl); return dead(s, "x25519"); }
            memcpy(s->client_pfs, pl, 1216);
            free(pl);
            memcpy(s->pfs, mlkem, 32);
            memcpy(s->pfs + 32, x, 32);
            memcpy(s->united, s->pfs, 64);
            memcpy(s->united + 64, s->nfs, 32);
            uint8_t srv_pub[1120];
            memcpy(srv_pub, sct, 1088);
            memcpy(srv_pub + 1088, spub, 32);
            sa_init(&s->tx, srv_pub, 1120, s->united, 96, s->aes);
            sa_init(&s->rx, s->client_pfs, 1216, s->united, 96, s->aes);

            uint8_t m1[1136];
            sa_seal(&s->nfs_a, MAXN, NULL, 0, srv_pub, 1120, m1);
            emit(s, m1, sizeof m1);

            RAND_bytes(s->ticket, 16);
            be16(s->ticket, (unsigned)s->x->seconds);
            if (s->x->seconds) {
                for (int i = 0; i < 32; ++i)
                    if (!s->x->sess[i].used) {
                        memset(&s->x->sess[i], 0, sizeof s->x->sess[i]);
                        s->x->sess[i].used = 1;
                        memcpy(s->x->sess[i].ticket, s->ticket, 16);
                        memcpy(s->x->sess[i].pfs, s->pfs, 64);
                        break;
                    }
            }
            uint8_t m2[32];
            sa_seal(&s->tx, NULL, NULL, 0, s->ticket, 16, m2);
            emit(s, m2, 32);
            unsigned padlen = 35 + (unsigned)(rand() % 200);
            uint8_t two[2];
            be16(two, padlen - 18);
            uint8_t m3[18];
            sa_seal(&s->tx, NULL, NULL, 0, two, 2, m3);
            emit(s, m3, 18);
            uint8_t *body = calloc(1, padlen - 18);
            sa_seal(&s->tx, NULL, NULL, 0, body, padlen - 34, body);
            emit(s, body, padlen - 18);
            free(body);
            if (s->x->xor_mode == 2) {
                s->ctx_tx = ctr(s->united, 96, s->ticket);
                s->ctx_rx = ctr(s->united, 96, s->iv);
            }
            used += L;
            s->st = S_CPADLEN;
            break;
        }
        case S_CPADLEN: {
            if (n < 18) goto more;
            uint8_t b[2];
            if (sa_open(&s->nfs_a, NULL, NULL, 0, p, 2, b)) return dead(s, "client padlen");
            s->cpad = (size_t)b[0] << 8 | b[1];
            used += 18;
            s->st = S_CPAD;
            break;
        }
        case S_CPAD: {
            if (n < s->cpad) goto more;
            uint8_t *t = malloc(s->cpad);
            int r = sa_open(&s->nfs_a, NULL, NULL, 0, p, s->cpad - 16, t);
            free(t);
            if (r) return dead(s, "client padding tag");
            used += s->cpad;
            s->st = S_READY;
            break;
        }
        case S_READY: {
            if (!s->have_hdr) {
                if (n < 5) goto more;
                memcpy(s->hdr, p, 5);
                if (s->ctx_rx) ctrx(s->ctx_rx, s->hdr, 5);
                s->rec = (size_t)s->hdr[3] << 8 | s->hdr[4];
                if (s->hdr[0] != 23 || s->hdr[1] != 3 || s->hdr[2] != 3 || s->rec < 17 || s->rec > 16640)
                    return dead(s, "bad header");
                s->have_hdr = 1;
                used += 5;
                break;
            }
            if (n < s->rec) goto more;
            size_t pl = s->rec - 16;
            s->plain = realloc(s->plain, s->plain_len + pl);
            int mx = !memcmp(s->rx.nonce, MAXN, 12);
            sa_t next;
            if (mx) {
                uint8_t *c = malloc(5 + s->rec);
                memcpy(c, s->hdr, 5);
                memcpy(c + 5, p, s->rec);
                sa_init(&next, c, 5 + s->rec, s->united, 96, s->aes);
                free(c);
            }
            if (sa_open(&s->rx, NULL, s->hdr, 5, p, pl, s->plain + s->plain_len)) return dead(s, "record tag");
            if (mx) s->rx = next;
            s->plain_len += pl;
            used += s->rec;
            s->have_hdr = 0;
            break;
        }
        case S_DEAD:
            return -1;
        }
    }
more:
    memmove(s->in, s->in + used, s->in_len - used);
    s->in_len -= used;
    return 0;
}

static size_t hdr_len(const uint8_t h[5]) {
    if (h[0] != 23 || h[1] != 3 || h[2] != 3) return 0;
    return (size_t)h[3] << 8 | h[4];
}

void vls_raw_begin(vls_t *s) {
    /* whatever the record parser still holds is plain stream now */
    s->raw = 1;
    s->out_skip = s->in_skip = s->out_hl = s->in_hl = 0;
}

void vls_raw_encode(vls_t *s, uint8_t *p, size_t n) {
    if (!s->ctx_tx) return;
    for (;;) {
        if (n <= s->out_skip) { s->out_skip -= n; break; }
        p += s->out_skip; n -= s->out_skip; s->out_skip = 0;
        size_t need = 5 - s->out_hl;
        if (n < need) {
            memcpy(s->out_hdr + s->out_hl, p, n);
            s->out_hl += n;
            ctrx(s->ctx_tx, p, n);
            break;
        }
        memcpy(s->out_hdr + s->out_hl, p, need);
        s->out_skip = hdr_len(s->out_hdr);
        s->out_hl = 0;
        ctrx(s->ctx_tx, p, need);
        p += need; n -= need;
    }
}

static void raw_decode(vls_t *s, uint8_t *p, size_t n) {
    if (!s->ctx_rx) return;
    for (;;) {
        if (n <= s->in_skip) { s->in_skip -= n; break; }
        p += s->in_skip; n -= s->in_skip; s->in_skip = 0;
        size_t need = 5 - s->in_hl;
        if (n < need) {
            ctrx(s->ctx_rx, p, n);
            memcpy(s->in_hdr + s->in_hl, p, n);
            s->in_hl += n;
            break;
        }
        ctrx(s->ctx_rx, p, need);
        memcpy(s->in_hdr + s->in_hl, p, need);
        s->in_skip = hdr_len(s->in_hdr);
        s->in_hl = 0;
        p += need; n -= need;
    }
}

int vls_feed(vls_t *s, const uint8_t *in, size_t n) {
    if (s->raw) {
        s->plain = realloc(s->plain, s->plain_len + n + 1);
        memcpy(s->plain + s->plain_len, in, n);
        raw_decode(s, s->plain + s->plain_len, n);
        s->plain_len += n;
        return 0;
    }
    if (s->st == S_DEAD) return -1;
    s->in = realloc(s->in, s->in_len + n + 1);
    memcpy(s->in + s->in_len, in, n);
    s->in_len += n;
    return step(s);
}

size_t vls_wire_out(vls_t *s, uint8_t *buf, size_t cap) {
    size_t n = s->out_len < cap ? s->out_len : cap;
    if (!n) return 0;
    memcpy(buf, s->out, n);
    memmove(s->out, s->out + n, s->out_len - n);
    s->out_len -= n;
    return n;
}

size_t vls_plain_in(vls_t *s, uint8_t *buf, size_t cap) {
    size_t n = s->plain_len < cap ? s->plain_len : cap;
    if (!n) return 0;
    memcpy(buf, s->plain, n);
    memmove(s->plain, s->plain + n, s->plain_len - n);
    s->plain_len -= n;
    return n;
}

int vls_send(vls_t *s, const uint8_t *plain, size_t n) {
    while (n) {
        size_t c = n > 8192 ? 8192 : n;
        uint8_t rec[5 + 8192 + 16];
        rec[0] = 23; rec[1] = 3; rec[2] = 3;
        be16(rec + 3, (unsigned)c + 16);
        int mx = !memcmp(s->tx.nonce, MAXN, 12);
        if (sa_seal(&s->tx, NULL, rec, 5, plain, c, rec + 5)) return -1;
        if (mx) sa_init(&s->tx, rec, 5 + c + 16, s->united, 96, s->aes);
        if (s->ctx_tx) ctrx(s->ctx_tx, rec, 5);
        emit(s, rec, 5 + c + 16);
        plain += c;
        n -= c;
    }
    return 0;
}

void vls_debug_set_nonce(vls_t *s, int which, const uint8_t nonce[12]) {
    memcpy(which ? s->rx.nonce : s->tx.nonce, nonce, 12);
}
