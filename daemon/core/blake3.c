#include "blake3.h"

#include <string.h>

#define CHUNK_START  1u
#define CHUNK_END    2u
#define PARENT       4u
#define ROOT         8u
#define DERIVE_CTX   32u
#define DERIVE_MAT   64u

#define CHUNK_LEN 1024u

static const uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t PERM[16] = { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

static uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void g(uint32_t *s, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rotr(s[b] ^ s[c], 7);
}

static void round_fn(uint32_t *s, const uint32_t *m) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

/* the 16 word output, the first 8 words are the next chaining value */
static void compress(const uint32_t cv[8], const uint8_t block[64], uint8_t block_len,
                     uint64_t counter, uint8_t flags, uint32_t out[16]) {
    uint32_t m[16], s[16];
    for (int i = 0; i < 16; ++i)
        m[i] = (uint32_t)block[4 * i] | (uint32_t)block[4 * i + 1] << 8 |
               (uint32_t)block[4 * i + 2] << 16 | (uint32_t)block[4 * i + 3] << 24;
    memcpy(s, cv, 32);
    memcpy(s + 8, IV, 16);
    s[12] = (uint32_t)counter;
    s[13] = (uint32_t)(counter >> 32);
    s[14] = block_len;
    s[15] = flags;
    for (int r = 0; r < 7; ++r) {
        round_fn(s, m);
        if (r < 6) {
            uint32_t p[16];
            for (int i = 0; i < 16; ++i) p[i] = m[PERM[i]];
            memcpy(m, p, sizeof m);
        }
    }
    for (int i = 0; i < 8; ++i) {
        out[i] = s[i] ^ s[i + 8];
        out[i + 8] = s[i + 8] ^ cv[i];
    }
}

static void words_to_bytes(const uint32_t *w, size_t nwords, uint8_t *out) {
    for (size_t i = 0; i < nwords; ++i) {
        out[4 * i] = (uint8_t)w[i];
        out[4 * i + 1] = (uint8_t)(w[i] >> 8);
        out[4 * i + 2] = (uint8_t)(w[i] >> 16);
        out[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

static void parent_cv(const uint32_t key[8], const uint32_t left[8], const uint32_t right[8],
                      uint8_t flags, uint32_t out[16]) {
    uint8_t block[64];
    words_to_bytes(left, 8, block);
    words_to_bytes(right, 8, block + 32);
    compress(key, block, 64, 0, (uint8_t)(PARENT | flags), out);
}

static void init_with_key(blake3_t *h, const uint32_t key[8], uint8_t flags) {
    memset(h, 0, sizeof *h);
    memcpy(h->key, key, 32);
    memcpy(h->cv, key, 32);
    h->flags = flags;
}

void blake3_init(blake3_t *h) {
    init_with_key(h, IV, 0);
}

static void add_chunk_cv(blake3_t *h, const uint32_t cv[8], uint64_t total_chunks) {
    uint32_t cur[8];
    memcpy(cur, cv, 32);
    while ((total_chunks & 1u) == 0) {
        uint32_t out[16];
        parent_cv(h->key, h->stack[--h->stack_len], cur, h->flags, out);
        memcpy(cur, out, 32);
        total_chunks >>= 1;
    }
    memcpy(h->stack[h->stack_len++], cur, 32);
}

static uint8_t chunk_start_flag(const blake3_t *h) {
    return h->blocks_done == 0 ? CHUNK_START : 0;
}

void blake3_update(blake3_t *h, const void *vin, size_t len) {
    const uint8_t *in = vin;
    while (len > 0) {
        /* a full block is compressed only when more input follows, so the
           last block of a chunk can still carry CHUNK_END */
        if (h->block_len == 64) {
            if (h->blocks_done == 15) {
                uint32_t out[16];
                compress(h->cv, h->block, 64, h->chunk_counter,
                         (uint8_t)(h->flags | chunk_start_flag(h) | CHUNK_END), out);
                h->chunk_counter++;
                add_chunk_cv(h, out, h->chunk_counter);
                memcpy(h->cv, h->key, 32);
                h->blocks_done = 0;
            } else {
                uint32_t out[16];
                compress(h->cv, h->block, 64, h->chunk_counter,
                         (uint8_t)(h->flags | chunk_start_flag(h)), out);
                memcpy(h->cv, out, 32);
                h->blocks_done++;
            }
            h->block_len = 0;
        }
        size_t take = 64u - h->block_len;
        if (take > len) take = len;
        memcpy(h->block + h->block_len, in, take);
        h->block_len = (uint8_t)(h->block_len + take);
        in += take;
        len -= take;
    }
}

void blake3_final(const blake3_t *h, uint8_t out[BLAKE3_OUT_LEN]) {
    uint32_t w[16];
    uint8_t block[64] = {0};
    memcpy(block, h->block, h->block_len);
    uint8_t fl = (uint8_t)(h->flags | chunk_start_flag(h) | CHUNK_END);
    uint32_t cv[8];
    size_t depth = h->stack_len;
    if (depth == 0) {
        compress(h->cv, block, h->block_len, h->chunk_counter, (uint8_t)(fl | ROOT), w);
        words_to_bytes(w, 8, out);
        return;
    }
    compress(h->cv, block, h->block_len, h->chunk_counter, fl, w);
    memcpy(cv, w, 32);
    while (depth > 1) {
        parent_cv(h->key, h->stack[--depth], cv, h->flags, w);
        memcpy(cv, w, 32);
    }
    parent_cv(h->key, h->stack[0], cv, (uint8_t)(h->flags | ROOT), w);
    words_to_bytes(w, 8, out);
}

void blake3_hash(const void *in, size_t len, uint8_t out[BLAKE3_OUT_LEN]) {
    blake3_t h;
    blake3_init(&h);
    blake3_update(&h, in, len);
    blake3_final(&h, out);
    memset(&h, 0, sizeof h);
}

void blake3_derive_key(const void *ctx, size_t ctx_len,
                       const void *material, size_t material_len,
                       uint8_t out[BLAKE3_OUT_LEN]) {
    blake3_t h;
    uint8_t ctx_key[32];
    uint32_t kw[8];
    init_with_key(&h, IV, DERIVE_CTX);
    blake3_update(&h, ctx, ctx_len);
    blake3_final(&h, ctx_key);
    for (int i = 0; i < 8; ++i)
        kw[i] = (uint32_t)ctx_key[4 * i] | (uint32_t)ctx_key[4 * i + 1] << 8 |
                (uint32_t)ctx_key[4 * i + 2] << 16 | (uint32_t)ctx_key[4 * i + 3] << 24;
    init_with_key(&h, kw, DERIVE_MAT);
    blake3_update(&h, material, material_len);
    blake3_final(&h, out);
    memset(&h, 0, sizeof h);
    memset(ctx_key, 0, sizeof ctx_key);
    memset(kw, 0, sizeof kw);
}
