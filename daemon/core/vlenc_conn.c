#include "vlenc_conn.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "blake3.h"
#include "reality_crypto.h"
#include "senko_time.h"

#define IV_LEN            16
#define PFS_PUB_LEN       (RC_MLKEM768_PUBLICKEYLEN + RC_X25519_KEYLEN)       /* 1216 */
#define CLIENT_PFS_LEN    (18 + PFS_PUB_LEN + 16)                             /* 1250 */
#define SERVER_PFS_PLAIN  (RC_MLKEM768_CIPHERTEXTLEN + RC_X25519_KEYLEN)      /* 1120 */
#define SERVER_PFS_LEN    (SERVER_PFS_PLAIN + 16)                             /* 1136 */
#define TICKET_LEN        16
#define SEC_TICKET_LEN    (TICKET_LEN + 16)
#define PFS_KEY_LEN       64
#define UNITED_LEN        (PFS_KEY_LEN + 32)
#define RX_BASE           (5 + VLC_REC_MAX)
#define RX_PAD_MAX        (65535 + 32)
#define TICKET_SLOTS      8
#define DEFAULT_NLENS     2

static void zero(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
    int     aes;
} aead_t;

static const uint8_t MAX_NONCE[12] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };

typedef enum {
    ST_NEW = 0,
    ST_S_PFS,       /* waiting for the server's key exchange message */
    ST_S_TICKET,
    ST_S_PADLEN,
    ST_S_PAD,
    ST_Z_RANDOM,    /* 0rtt: the server's 16 random bytes come first */
    ST_READY,
    ST_RAW,         /* vision direct: the peer sends plain bytes */
    ST_ERR
} state_t;

struct vlc_conn {
    vlenc_cfg_t own; /* a copy: the pool may release the profile mid session */
    const vlenc_cfg_t *cfg;
    vlc_env_t env;
    state_t   state;
    int       use_aes;
    uint8_t   scope[32];

    uint8_t   iv[IV_LEN];
    uint8_t   nfs_key[32];
    uint8_t   united[UNITED_LEN];
    uint8_t   pfs_key[PFS_KEY_LEN];
    aead_t    nfs_aead;     /* opens the reply's key exchange message */
    aead_t    tx;
    aead_t    rx_aead;
    uint8_t   ticket16[TICKET_LEN];
    int       tx_ready;
    int       zero_rtt;

    uint8_t  *hello;
    size_t    hello_len;
    size_t    segs[1 + (VLENC_MAX_PAD + 1) / 2];
    size_t    nsegs;

    /* 0rtt preamble waits for the first sealed record */
    uint8_t   pre[VLC_PREAMBLE_MAX];
    size_t    pre_len;

    /* what the 1rtt reply is checked against */
    uint8_t   pfs_priv[RC_MLKEM768_SECRETKEYLEN];
    uint8_t   x25519_priv[RC_X25519_KEYLEN];
    uint8_t   pfs_pub[PFS_PUB_LEN];

    EVP_CIPHER_CTX *ctr_tx;
    EVP_CIPHER_CTX *ctr_rx;
    uint8_t   ticket_ct[SEC_TICKET_LEN];
    int       first_record;
    size_t    pad_len;

    /* header masking of the plain stream after the vision direct switch: the
       skip counts the record body bytes to leave alone, hdr holds the part of
       a header seen so far, unmasked on the way out and decoded on the way in */
    size_t    raw_out_skip, raw_in_skip;
    uint8_t   raw_out_hdr[5], raw_in_hdr[5];
    size_t    raw_out_hl, raw_in_hl;

    uint8_t  *rx;
    size_t    rx_cap, rx_off, rx_len;
    uint8_t   hdr[5];
    int       have_hdr;
    size_t    rec_len;
};

typedef struct {
    int      used;
    uint8_t  scope[32];
    uint8_t  pfs[PFS_KEY_LEN];
    uint8_t  ticket[TICKET_LEN];
    int64_t  expire;
    uint64_t seq;
} ticket_t;

static pthread_mutex_t ticket_lock = PTHREAD_MUTEX_INITIALIZER;
static ticket_t tickets[TICKET_SLOTS];
static uint64_t ticket_seq;

void vlc_tickets_reset(void) {
    pthread_mutex_lock(&ticket_lock);
    zero(tickets, sizeof tickets);
    pthread_mutex_unlock(&ticket_lock);
}

static int64_t now_s(const vlc_conn_t *c) {
    if (c->env.now) return c->env.now(c->env.now_ctx);
    return senko_now_ms() / 1000;
}

static int rnd(const vlc_conn_t *c, uint8_t *buf, size_t n) {
    if (c->env.rand) return c->env.rand(c->env.rand_ctx, buf, n);
    return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

/* uniform in [lo, hi) by rejection, lo when the range is empty */
static int rnd_between(const vlc_conn_t *c, uint32_t lo, uint32_t hi, uint32_t *out) {
    if (hi <= lo) { *out = lo; return 0; }
    uint32_t span = hi - lo;
    uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % span) - 1u;
    for (int i = 0; i < 64; ++i) {
        uint8_t b[4];
        if (rnd(c, b, 4) != 0) return -1;
        uint32_t v = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
        if (v <= limit) { *out = lo + v % span; return 0; }
    }
    return -1;
}

static void put16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static unsigned get16(const uint8_t *p) {
    return (unsigned)p[0] << 8 | p[1];
}

static void nonce_inc(uint8_t n[12]) {
    for (int i = 11; i >= 0; --i)
        if (++n[i] != 0) break;
}

static void aead_init(aead_t *a, const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *key, size_t key_len, int aes) {
    blake3_derive_key(ctx, ctx_len, key, key_len, a->key);
    memset(a->nonce, 0, sizeof a->nonce);
    a->aes = aes;
}

/* out holds len + 16 bytes; a null nonce uses and advances the counter, which
   is incremented before use, so the first message runs under nonce 1 */
static vlc_status_t aead_seal(aead_t *a, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len, uint8_t *out) {
    if (!nonce) { nonce_inc(a->nonce); nonce = a->nonce; }
    rc_status_t rc = a->aes
        ? rc_aes256gcm_seal(a->key, nonce, aad, aad_len, in, len, out, out + len)
        : rc_chacha20poly1305_seal(a->key, nonce, aad, aad_len, in, len, out, out + len);
    return rc == RC_OK ? VLC_OK : VLC_ERR_SYSTEM;
}

/* in holds len + 16 bytes; out gets len plaintext bytes only after the tag verifies */
static vlc_status_t aead_open(aead_t *a, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len, uint8_t *out) {
    if (!nonce) { nonce_inc(a->nonce); nonce = a->nonce; }
    rc_status_t rc = a->aes
        ? rc_aes256gcm_open(a->key, nonce, aad, aad_len, in, len, in + len, out)
        : rc_chacha20poly1305_open(a->key, nonce, aad, aad_len, in, len, in + len, out);
    if (rc == RC_OK) return VLC_OK;
    return rc == RC_ERR_CRYPTO ? VLC_ERR_AUTH : VLC_ERR_SYSTEM;
}

static EVP_CIPHER_CTX *ctr_new(const uint8_t *key, size_t key_len, const uint8_t iv[IV_LEN]) {
    uint8_t k[32];
    blake3_derive_key("VLESS", 5, key, key_len, k);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    if (x && EVP_EncryptInit_ex(x, EVP_aes_256_ctr(), NULL, k, iv) != 1) {
        EVP_CIPHER_CTX_free(x);
        x = NULL;
    }
    zero(k, sizeof k);
    return x;
}

static int ctr_xor(EVP_CIPHER_CTX *x, const uint8_t *in, uint8_t *out, size_t len) {
    int n = 0;
    return EVP_EncryptUpdate(x, out, &n, in, (int)len) == 1 && (size_t)n == len;
}

static void default_env(vlc_env_t *e) {
    memset(e, 0, sizeof *e);
    e->use_aes = -1;
}

/* the server accepts either cipher, the client picks what its cpu runs fast:
   arm64 has the aes instructions, the armv7 slice only has neon for chacha */
static int cpu_prefers_aes(void) {
#if defined(__aarch64__) || defined(__x86_64__) || defined(__i386__)
    return 1;
#else
    return 0;
#endif
}

vlc_conn_t *vlc_new(const vlenc_cfg_t *cfg, const char *scope, const vlc_env_t *env) {
    if (!cfg || !scope || cfg->n_keys == 0) return NULL;
    vlc_conn_t *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->own = *cfg;
    c->cfg = &c->own;
    if (env) c->env = *env; else default_env(&c->env);
    c->use_aes = c->env.use_aes >= 0 ? c->env.use_aes : cpu_prefers_aes();
    blake3_hash(scope, strlen(scope), c->scope);
    c->rx_cap = RX_BASE;
    c->rx = malloc(c->rx_cap);
    if (!c->rx) {
        free(c);
        return NULL;
    }
    return c;
}

void vlc_free(vlc_conn_t *c) {
    if (!c) return;
    if (c->ctr_tx) EVP_CIPHER_CTX_free(c->ctr_tx);
    if (c->ctr_rx) EVP_CIPHER_CTX_free(c->ctr_rx);
    if (c->hello) {
        zero(c->hello, c->hello_len);
        free(c->hello);
    }
    if (c->rx) {
        zero(c->rx, c->rx_cap);
        free(c->rx);
    }
    zero(c, sizeof *c);
    free(c);
}

int vlc_can_seal(const vlc_conn_t *c) {
    return c && c->tx_ready && c->state != ST_ERR;
}

int vlc_established(const vlc_conn_t *c) {
    return c && (c->state == ST_READY || c->state == ST_RAW);
}

int vlc_at_boundary(const vlc_conn_t *c) {
    return c && vlc_established(c) && !c->have_hdr && c->rx_len == c->rx_off;
}

int vlc_is_zero_rtt(const vlc_conn_t *c) {
    return c && c->zero_rtt;
}

static vlc_status_t fail(vlc_conn_t *c, vlc_status_t st) {
    c->state = ST_ERR;
    zero(c->pfs_priv, sizeof c->pfs_priv);
    zero(c->x25519_priv, sizeof c->x25519_priv);
    return st;
}

static int ticket_lookup(const vlc_conn_t *c, uint8_t pfs[PFS_KEY_LEN], uint8_t ticket[TICKET_LEN]) {
    int found = 0;
    int64_t now = now_s(c);
    pthread_mutex_lock(&ticket_lock);
    for (int i = 0; i < TICKET_SLOTS; ++i) {
        if (!tickets[i].used || memcmp(tickets[i].scope, c->scope, 32) != 0) continue;
        if (now < tickets[i].expire) {
            memcpy(pfs, tickets[i].pfs, PFS_KEY_LEN);
            memcpy(ticket, tickets[i].ticket, TICKET_LEN);
            found = 1;
        } else {
            zero(&tickets[i], sizeof tickets[i]);
        }
        break;
    }
    pthread_mutex_unlock(&ticket_lock);
    return found;
}

static void ticket_store(const vlc_conn_t *c, const uint8_t pfs[PFS_KEY_LEN],
                         const uint8_t ticket[TICKET_LEN], int64_t seconds) {
    int64_t now = now_s(c);
    pthread_mutex_lock(&ticket_lock);
    int slot = -1;
    for (int i = 0; i < TICKET_SLOTS; ++i)
        if (tickets[i].used && memcmp(tickets[i].scope, c->scope, 32) == 0) { slot = i; break; }
    for (int i = 0; slot < 0 && i < TICKET_SLOTS; ++i)
        if (!tickets[i].used || now >= tickets[i].expire) slot = i;
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < TICKET_SLOTS; ++i)
            if (tickets[i].seq < tickets[slot].seq) slot = i;
    }
    zero(&tickets[slot], sizeof tickets[slot]);
    tickets[slot].used = 1;
    memcpy(tickets[slot].scope, c->scope, 32);
    memcpy(tickets[slot].pfs, pfs, PFS_KEY_LEN);
    memcpy(tickets[slot].ticket, ticket, TICKET_LEN);
    tickets[slot].expire = now + seconds;
    tickets[slot].seq = ++ticket_seq;
    pthread_mutex_unlock(&ticket_lock);
}

/* only the ticket this connection used: a newer one stays */
static void ticket_drop(const vlc_conn_t *c) {
    pthread_mutex_lock(&ticket_lock);
    for (int i = 0; i < TICKET_SLOTS; ++i)
        if (tickets[i].used && memcmp(tickets[i].scope, c->scope, 32) == 0 &&
            memcmp(tickets[i].pfs, c->united, PFS_KEY_LEN) == 0)
            zero(&tickets[i], sizeof tickets[i]);
    pthread_mutex_unlock(&ticket_lock);
}

static const vlenc_pad_t DEF_LENS[DEFAULT_NLENS] = { { 100, 111, 1111 }, { 50, 0, 3333 } };

/* sizes of the random padding parts, one per length entry */
static vlc_status_t pick_padding(vlc_conn_t *c, uint32_t lens[], size_t *nlens, size_t *total) {
    const vlenc_pad_t *src = c->cfg->n_lens ? c->cfg->lens : DEF_LENS;
    size_t n = c->cfg->n_lens ? c->cfg->n_lens : DEFAULT_NLENS;
    *total = 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t roll = 0, l = 0;
        if (rnd_between(c, 0, 100, &roll) != 0) return VLC_ERR_SYSTEM;
        if (src[i].prob >= roll && rnd_between(c, src[i].min, src[i].max, &l) != 0)
            return VLC_ERR_SYSTEM;
        if (src[i].prob < roll) l = 0;
        lens[i] = l;
        *total += l;
    }
    *nlens = n;
    return VLC_OK;
}

static int x25519_agree(const uint8_t priv[32], const uint8_t pub[32], uint8_t out[32]) {
    uint8_t acc = 0;
    if (rc_x25519_shared(priv, pub, out) != RC_OK) return -1;
    for (int i = 0; i < 32; ++i) acc |= out[i];
    return acc ? 0 : -1; /* a low order peer point gives all zeros */
}

/* the relay chain: each static key adds one encapsulation or ephemeral
   public value, and every later relay is hidden under the previous key's
   stream so the server can only walk it in order */
static vlc_status_t build_relays(vlc_conn_t *c, uint8_t *relays) {
    const vlenc_cfg_t *cfg = c->cfg;
    EVP_CIPHER_CTX *last = NULL;
    vlc_status_t st = VLC_OK;
    uint8_t nfs[32];

    for (unsigned j = 0; j < cfg->n_keys && st == VLC_OK; ++j) {
        const uint8_t *kb = cfg->blob + cfg->key_off[j];
        size_t klen = cfg->key_len[j];
        int pq = klen == VLENC_MLKEM_EK_LEN;
        size_t index = pq ? RC_MLKEM768_CIPHERTEXTLEN : 32;

        if (pq) {
            if (rc_mlkem768_encap(kb, relays, nfs) != RC_OK) { st = VLC_ERR_SYSTEM; break; }
        } else {
            uint8_t priv[32];
            if (rnd(c, priv, 32) != 0 || rc_x25519_public(priv, relays) != RC_OK) {
                zero(priv, sizeof priv);
                st = VLC_ERR_SYSTEM;
                break;
            }
            int bad = x25519_agree(priv, kb, nfs);
            zero(priv, sizeof priv);
            if (bad) { st = VLC_ERR_KEY; break; }
        }
        if (cfg->xor_mode > 0) {
            EVP_CIPHER_CTX *m = ctr_new(kb, klen, c->iv);
            if (!m || !ctr_xor(m, relays, relays, index)) {
                if (m) EVP_CIPHER_CTX_free(m);
                st = VLC_ERR_SYSTEM;
                break;
            }
            EVP_CIPHER_CTX_free(m);
        }
        if (last && !ctr_xor(last, relays, relays, 32)) { st = VLC_ERR_SYSTEM; break; }
        if (j + 1 == cfg->n_keys) break;

        uint8_t next_hash[32];
        blake3_hash(cfg->blob + cfg->key_off[j + 1], cfg->key_len[j + 1], next_hash);
        if (last) EVP_CIPHER_CTX_free(last);
        last = ctr_new(nfs, 32, c->iv);
        if (!last || !ctr_xor(last, next_hash, relays + index, 32)) { st = VLC_ERR_SYSTEM; break; }
        relays += index + 32;
    }
    if (last) EVP_CIPHER_CTX_free(last);
    if (st == VLC_OK) memcpy(c->nfs_key, nfs, 32);
    zero(nfs, sizeof nfs);
    return st;
}

static size_t relays_len(const vlenc_cfg_t *cfg) {
    size_t n = 0;
    for (unsigned j = 0; j < cfg->n_keys; ++j)
        n += (cfg->key_len[j] == VLENC_MLKEM_EK_LEN ? RC_MLKEM768_CIPHERTEXTLEN : 32) + 32;
    return n - 32;
}

vlc_status_t vlc_hello(vlc_conn_t *c, const uint8_t **buf, size_t *len,
                       const size_t **segs, size_t *nsegs) {
    if (!c || !buf || !len || !segs || !nsegs) return VLC_ERR_ARG;
    if (c->state != ST_NEW) return VLC_ERR_STATE;

    size_t rl = relays_len(c->cfg);
    size_t head = IV_LEN + rl;
    vlc_status_t st;

    uint32_t lens[(VLENC_MAX_PAD + 1) / 2 + 1];
    size_t nlens = 0, padding = 0;
    int ticket_live = 0;
    uint8_t t_pfs[PFS_KEY_LEN], t_ticket[TICKET_LEN];

    if (rnd(c, c->iv, IV_LEN) != 0) return fail(c, VLC_ERR_SYSTEM);
    if (c->cfg->zero_rtt) ticket_live = ticket_lookup(c, t_pfs, t_ticket);

    size_t total = head;
    if (!ticket_live) {
        st = pick_padding(c, lens, &nlens, &padding);
        if (st != VLC_OK) return fail(c, st);
        total += CLIENT_PFS_LEN + padding;
    } else {
        total += 18 + SEC_TICKET_LEN;
    }

    uint8_t *h = calloc(1, total);
    if (!h) return fail(c, VLC_ERR_SYSTEM);
    c->hello = h;
    c->hello_len = total;
    memcpy(h, c->iv, IV_LEN);
    st = build_relays(c, h + IV_LEN);
    if (st != VLC_OK) return fail(c, st);

    aead_t nfs;
    aead_init(&nfs, c->iv, IV_LEN, c->nfs_key, 32, c->use_aes);

    if (ticket_live) {
        /* 0rtt: the united key is the stored pfs key plus this connection's
           fresh nfs key, so two connections never share a key. the replay
           guard on the server is that nfs key */
        uint8_t two[2];
        put16(two, 32);
        memcpy(c->pfs_key, t_pfs, PFS_KEY_LEN);
        memcpy(c->united, t_pfs, PFS_KEY_LEN);
        memcpy(c->united + PFS_KEY_LEN, c->nfs_key, 32);
        if (aead_seal(&nfs, NULL, NULL, 0, two, 2, h + head) != VLC_OK ||
            aead_seal(&nfs, NULL, NULL, 0, t_ticket, TICKET_LEN, h + head + 18) != VLC_OK) {
            zero(&nfs, sizeof nfs);
            return fail(c, VLC_ERR_SYSTEM);
        }
        memcpy(c->ticket_ct, h + head + 18, SEC_TICKET_LEN);
        aead_init(&c->tx, c->ticket_ct, SEC_TICKET_LEN, c->united, UNITED_LEN, c->use_aes);
        if (c->cfg->xor_mode == VLENC_XOR_RANDOM) {
            c->ctr_tx = ctr_new(c->united, UNITED_LEN, c->iv);
            if (!c->ctr_tx) { zero(&nfs, sizeof nfs); return fail(c, VLC_ERR_SYSTEM); }
        }
        c->pre_len = head + 18 + SEC_TICKET_LEN;
        memcpy(c->pre, h, c->pre_len);
        zero(h, total);
        free(h);
        c->hello = NULL;
        c->hello_len = 0;
        zero(&nfs, sizeof nfs);
        c->zero_rtt = 1;
        c->tx_ready = 1;
        c->state = ST_Z_RANDOM;
        c->first_record = 1;
        *buf = NULL;
        *len = 0;
        *segs = c->segs;
        *nsegs = 0;
        return VLC_OK;
    }

    /* fresh key exchange: the ml-kem encapsulation key and an x25519 public
       value, sealed under the nfs key */
    uint8_t *pfs = h + head;
    uint8_t two[2];
    put16(two, CLIENT_PFS_LEN - 18);
    if (rc_mlkem768_keygen(c->pfs_pub, c->pfs_priv) != RC_OK ||
        rnd(c, c->x25519_priv, 32) != 0 ||
        rc_x25519_public(c->x25519_priv, c->pfs_pub + RC_MLKEM768_PUBLICKEYLEN) != RC_OK) {
        zero(&nfs, sizeof nfs);
        return fail(c, VLC_ERR_SYSTEM);
    }
    if (aead_seal(&nfs, NULL, NULL, 0, two, 2, pfs) != VLC_OK ||
        aead_seal(&nfs, NULL, NULL, 0, c->pfs_pub, PFS_PUB_LEN, pfs + 18) != VLC_OK) {
        zero(&nfs, sizeof nfs);
        return fail(c, VLC_ERR_SYSTEM);
    }

    /* padding sealed as two messages, a length and a body of zeros, so it
       reads as random bytes and the server can skip it by length */
    uint8_t *pad = pfs + CLIENT_PFS_LEN;
    put16(two, (unsigned)padding - 18);
    if (aead_seal(&nfs, NULL, NULL, 0, two, 2, pad) != VLC_OK ||
        aead_seal(&nfs, NULL, NULL, 0, pad + 18, padding - 34, pad + 18) != VLC_OK) {
        zero(&nfs, sizeof nfs);
        return fail(c, VLC_ERR_SYSTEM);
    }

    c->nsegs = 0;
    for (size_t i = 0; i < nlens; ++i) {
        size_t seg = lens[i] + (i == 0 ? head + CLIENT_PFS_LEN : 0);
        if (seg) c->segs[c->nsegs++] = seg;
    }
    c->nfs_aead = nfs;
    zero(&nfs, sizeof nfs);
    c->state = ST_S_PFS;
    *buf = h;
    *len = total;
    *segs = c->segs;
    *nsegs = c->nsegs;
    return VLC_OK;
}

static vlc_status_t handle_pfs(vlc_conn_t *c, uint8_t *p) {
    uint8_t plain[SERVER_PFS_PLAIN];
    uint8_t mlkem[RC_MLKEM768_SHAREDLEN], x25519[RC_SHARED_LEN];
    vlc_status_t st = aead_open(&c->nfs_aead, MAX_NONCE, NULL, 0, p, SERVER_PFS_PLAIN, plain);
    if (st != VLC_OK) return fail(c, st);
    if (rc_mlkem768_decap(plain, c->pfs_priv, mlkem) != RC_OK) return fail(c, VLC_ERR_SYSTEM);
    if (x25519_agree(c->x25519_priv, plain + RC_MLKEM768_CIPHERTEXTLEN, x25519) != 0) {
        zero(mlkem, sizeof mlkem);
        return fail(c, VLC_ERR_KEY);
    }
    memcpy(c->pfs_key, mlkem, 32);
    memcpy(c->pfs_key + 32, x25519, 32);
    memcpy(c->united, c->pfs_key, PFS_KEY_LEN);
    memcpy(c->united + PFS_KEY_LEN, c->nfs_key, 32);
    aead_init(&c->tx, c->pfs_pub, PFS_PUB_LEN, c->united, UNITED_LEN, c->use_aes);
    aead_init(&c->rx_aead, plain, SERVER_PFS_PLAIN, c->united, UNITED_LEN, c->use_aes);
    if (c->cfg->xor_mode == VLENC_XOR_RANDOM) {
        c->ctr_tx = ctr_new(c->united, UNITED_LEN, c->iv);
        if (!c->ctr_tx) return fail(c, VLC_ERR_SYSTEM);
    }
    zero(mlkem, sizeof mlkem);
    zero(x25519, sizeof x25519);
    zero(plain, sizeof plain);
    zero(c->pfs_priv, sizeof c->pfs_priv);
    zero(c->x25519_priv, sizeof c->x25519_priv);
    c->tx_ready = 1;
    /* the server answered, so the caller sent the hello long ago */
    if (c->hello) {
        zero(c->hello, c->hello_len);
        free(c->hello);
        c->hello = NULL;
        c->hello_len = 0;
    }
    return VLC_OK;
}

static vlc_status_t handle_ticket(vlc_conn_t *c, uint8_t *p) {
    uint8_t tk[TICKET_LEN];
    vlc_status_t st = aead_open(&c->rx_aead, NULL, NULL, 0, p, TICKET_LEN, tk);
    if (st != VLC_OK) return fail(c, st);
    memcpy(c->ticket16, tk, TICKET_LEN);
    unsigned seconds = get16(tk);
    if (c->cfg->zero_rtt && seconds > 0) ticket_store(c, c->pfs_key, tk, (int64_t)seconds);
    if (c->cfg->xor_mode == VLENC_XOR_RANDOM) {
        c->ctr_rx = ctr_new(c->united, UNITED_LEN, tk);
        if (!c->ctr_rx) return fail(c, VLC_ERR_SYSTEM);
    }
    zero(tk, sizeof tk);
    return VLC_OK;
}

static size_t need_for(const vlc_conn_t *c) {
    switch (c->state) {
        case ST_S_PFS:    return SERVER_PFS_LEN;
        case ST_S_TICKET: return SEC_TICKET_LEN;
        case ST_S_PADLEN: return 18;
        case ST_S_PAD:    return c->pad_len;
        case ST_Z_RANDOM: return 16;
        default:          return RX_BASE;
    }
}

static void rx_compact(vlc_conn_t *c) {
    if (c->rx_off == 0) return;
    memmove(c->rx, c->rx + c->rx_off, c->rx_len - c->rx_off);
    c->rx_len -= c->rx_off;
    c->rx_off = 0;
}

vlc_status_t vlc_rx_space(vlc_conn_t *c, uint8_t **p, size_t *cap) {
    if (!c || !p || !cap) return VLC_ERR_ARG;
    if (c->state == ST_ERR) return VLC_ERR_STATE;
    rx_compact(c);
    size_t want = need_for(c);
    if (want < RX_BASE) want = RX_BASE;
    if (want > c->rx_cap) {
        uint8_t *n = realloc(c->rx, want);
        if (!n) return VLC_ERR_SYSTEM;
        c->rx = n;
        c->rx_cap = want;
    } else if (c->rx_cap > RX_BASE && want == RX_BASE && c->rx_len <= RX_BASE) {
        /* the long reply padding is done, give the memory back */
        uint8_t *n = realloc(c->rx, RX_BASE);
        if (n) {
            c->rx = n;
            c->rx_cap = RX_BASE;
        }
    }
    *p = c->rx + c->rx_len;
    *cap = c->rx_cap - c->rx_len;
    return VLC_OK;
}

vlc_status_t vlc_rx_commit(vlc_conn_t *c, size_t n) {
    if (!c || n > c->rx_cap - c->rx_len) return VLC_ERR_ARG;
    c->rx_len += n;
    return VLC_OK;
}

static int rekey_rx(vlc_conn_t *c, const uint8_t *hdr, const uint8_t *body, size_t body_len, aead_t *next) {
    uint8_t *ctx = malloc(5 + body_len);
    if (!ctx) return -1;
    memcpy(ctx, hdr, 5);
    memcpy(ctx + 5, body, body_len);
    aead_init(next, ctx, 5 + body_len, c->united, UNITED_LEN, c->use_aes);
    zero(ctx, 5 + body_len);
    free(ctx);
    return 0;
}

vlc_status_t vlc_pull(vlc_conn_t *c, uint8_t *out, size_t cap, size_t *out_len) {
    if (!c || !out || !out_len) return VLC_ERR_ARG;
    *out_len = 0;
    for (;;) {
        uint8_t *p = c->rx + c->rx_off;
        size_t avail = c->rx_len - c->rx_off;
        vlc_status_t st;
        switch (c->state) {
        case ST_NEW:
            return VLC_ERR_STATE;
        case ST_ERR:
            return VLC_ERR_STATE;
        case ST_RAW:
            return VLC_NEED_MORE;
        case ST_S_PFS:
            if (avail < SERVER_PFS_LEN) return VLC_NEED_MORE;
            if ((st = handle_pfs(c, p)) != VLC_OK) return st;
            c->rx_off += SERVER_PFS_LEN;
            c->state = ST_S_TICKET;
            break;
        case ST_S_TICKET:
            if (avail < SEC_TICKET_LEN) return VLC_NEED_MORE;
            if ((st = handle_ticket(c, p)) != VLC_OK) return st;
            c->rx_off += SEC_TICKET_LEN;
            c->state = ST_S_PADLEN;
            break;
        case ST_S_PADLEN: {
            uint8_t two[2];
            if (avail < 18) return VLC_NEED_MORE;
            if ((st = aead_open(&c->rx_aead, NULL, NULL, 0, p, 2, two)) != VLC_OK) return fail(c, st);
            c->pad_len = get16(two);
            /* a padding body is at least its own tag */
            if (c->pad_len < 16) return fail(c, VLC_ERR_PROTO);
            c->rx_off += 18;
            c->state = ST_S_PAD;
            break;
        }
        case ST_S_PAD:
            if (avail < c->pad_len) return VLC_NEED_MORE;
            if ((st = aead_open(&c->rx_aead, NULL, NULL, 0, p, c->pad_len - 16, p)) != VLC_OK)
                return fail(c, st);
            c->rx_off += c->pad_len;
            c->state = ST_READY;
            break;
        case ST_Z_RANDOM:
            if (avail < 16) return VLC_NEED_MORE;
            aead_init(&c->rx_aead, p, 16, c->united, UNITED_LEN, c->use_aes);
            if (c->cfg->xor_mode == VLENC_XOR_RANDOM) {
                c->ctr_rx = ctr_new(c->united, UNITED_LEN, p);
                if (!c->ctr_rx) return fail(c, VLC_ERR_SYSTEM);
            }
            c->rx_off += 16;
            c->state = ST_READY;
            break;
        case ST_READY: {
            if (!c->have_hdr) {
                if (avail < 5) return VLC_NEED_MORE;
                memcpy(c->hdr, p, 5);
                if (c->ctr_rx && !ctr_xor(c->ctr_rx, c->hdr, c->hdr, 5)) return fail(c, VLC_ERR_SYSTEM);
                size_t l = (size_t)c->hdr[3] << 8 | c->hdr[4];
                if (c->hdr[0] != 23 || c->hdr[1] != 3 || c->hdr[2] != 3 || l < 17 || l > VLC_REC_MAX) {
                    /* a server that lost the ticket answers with noise that
                       is no record header */
                    if (c->zero_rtt && c->first_record) {
                        ticket_drop(c);
                        return fail(c, VLC_ERR_TICKET);
                    }
                    return fail(c, VLC_ERR_PROTO);
                }
                c->rec_len = l;
                c->have_hdr = 1;
                c->rx_off += 5;
                continue;
            }
            if (avail < c->rec_len) return VLC_NEED_MORE;
            size_t plain = c->rec_len - 16;
            if (cap < plain) return VLC_ERR_ARG;
            aead_t next;
            int rekey = memcmp(c->rx_aead.nonce, MAX_NONCE, 12) == 0;
            if (rekey && rekey_rx(c, c->hdr, p, c->rec_len, &next) != 0) return fail(c, VLC_ERR_SYSTEM);
            st = aead_open(&c->rx_aead, NULL, c->hdr, 5, p, plain, out);
            if (rekey) c->rx_aead = next;
            if (st != VLC_OK) return fail(c, st);
            c->rx_off += c->rec_len;
            c->have_hdr = 0;
            c->first_record = 0;
            *out_len = plain;
            return VLC_DATA;
        }
        }
    }
}

vlc_status_t vlc_seal(vlc_conn_t *c, const uint8_t *in, size_t len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    if (!c || !in || !out || !out_len || len == 0 || len > VLC_PLAIN_MAX) return VLC_ERR_ARG;
    if (!c->tx_ready || c->state == ST_ERR) return VLC_ERR_STATE;
    size_t need = c->pre_len + len + VLC_SEAL_EXTRA;
    if (cap < need) return VLC_ERR_ARG;

    uint8_t *rec = out + c->pre_len;
    rec[0] = 23;
    rec[1] = 3;
    rec[2] = 3;
    put16(rec + 3, (unsigned)len + 16);
    int max = memcmp(c->tx.nonce, MAX_NONCE, 12) == 0;
    if (aead_seal(&c->tx, NULL, rec, 5, in, len, rec + 5) != VLC_OK) return fail(c, VLC_ERR_SYSTEM);
    if (max) aead_init(&c->tx, rec, 5 + len + 16, c->united, UNITED_LEN, c->use_aes);
    if (c->ctr_tx && !ctr_xor(c->ctr_tx, rec, rec, 5)) return fail(c, VLC_ERR_SYSTEM);
    if (c->pre_len) {
        memcpy(out, c->pre, c->pre_len);
        zero(c->pre, sizeof c->pre);
        c->pre_len = 0;
    }
    *out_len = need;
    return VLC_OK;
}

/* the length a plain record header announces; anything that is no application
   data header announces nothing and the next bytes are a header again */
static size_t raw_header_len(const uint8_t h[5]) {
    if (h[0] != 23 || h[1] != 3 || h[2] != 3) return 0;
    return (size_t)h[3] << 8 | h[4];
}

void vlc_raw_encode(vlc_conn_t *c, uint8_t *buf, size_t len) {
    if (!c || !c->ctr_tx) return;
    uint8_t *p = buf;
    size_t n = len;
    for (;;) {
        if (n <= c->raw_out_skip) {
            c->raw_out_skip -= n;
            break;
        }
        p += c->raw_out_skip;
        n -= c->raw_out_skip;
        c->raw_out_skip = 0;
        size_t need = 5 - c->raw_out_hl;
        if (n < need) {
            memcpy(c->raw_out_hdr + c->raw_out_hl, p, n);
            c->raw_out_hl += n;
            ctr_xor(c->ctr_tx, p, p, n);
            break;
        }
        memcpy(c->raw_out_hdr + c->raw_out_hl, p, need);
        c->raw_out_skip = raw_header_len(c->raw_out_hdr);
        c->raw_out_hl = 0;
        ctr_xor(c->ctr_tx, p, p, need);
        p += need;
        n -= need;
    }
}

void vlc_raw_decode(vlc_conn_t *c, uint8_t *buf, size_t len) {
    if (!c || !c->ctr_rx) return;
    uint8_t *p = buf;
    size_t n = len;
    for (;;) {
        if (n <= c->raw_in_skip) {
            c->raw_in_skip -= n;
            break;
        }
        p += c->raw_in_skip;
        n -= c->raw_in_skip;
        c->raw_in_skip = 0;
        size_t need = 5 - c->raw_in_hl;
        if (n < need) {
            ctr_xor(c->ctr_rx, p, p, n);
            memcpy(c->raw_in_hdr + c->raw_in_hl, p, n);
            c->raw_in_hl += n;
            break;
        }
        ctr_xor(c->ctr_rx, p, p, need);
        memcpy(c->raw_in_hdr + c->raw_in_hl, p, need);
        c->raw_in_skip = raw_header_len(c->raw_in_hdr);
        c->raw_in_hl = 0;
        p += need;
        n -= need;
    }
}

size_t vlc_take_raw(vlc_conn_t *c, uint8_t *out, size_t cap) {
    if (!c || !out) return 0;
    size_t n = c->rx_len - c->rx_off;
    if (n > cap) n = cap;
    memcpy(out, c->rx + c->rx_off, n);
    c->rx_off += n;
    if (c->rx_off == c->rx_len) c->rx_off = c->rx_len = 0;
    c->state = ST_RAW;
    vlc_raw_decode(c, out, n);
    return n;
}
