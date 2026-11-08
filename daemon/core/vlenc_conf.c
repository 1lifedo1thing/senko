#include "vlenc_conf.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"

const char *vlenc_reason(vlenc_status_t st) {
    switch (st) {
        case VLENC_OK:               return "ok";
        case VLENC_ERR_ARG:          return "vless encryption";
        case VLENC_ERR_TOO_LONG:     return "vless encryption too long";
        case VLENC_ERR_FORMAT:       return "vless encryption format";
        case VLENC_ERR_VERSION:      return "vless encryption version";
        case VLENC_ERR_MODE:         return "vless encryption mode";
        case VLENC_ERR_RTT:          return "vless encryption rtt";
        case VLENC_ERR_PADDING:      return "vless encryption padding";
        case VLENC_ERR_KEY_ENCODING: return "vless encryption key encoding";
        case VLENC_ERR_KEY_LENGTH:   return "vless encryption key length";
        case VLENC_ERR_KEY_VALUE:    return "vless encryption key value";
        case VLENC_ERR_KEY_COUNT:    return "vless encryption key count";
        case VLENC_ERR_POOL_FULL:    return "vless encryption profiles full";
    }
    return "vless encryption";
}

int vlenc_is_set(const char *text) {
    return text && text[0] && strcmp(text, "none") != 0;
}

/* fips 203 section 7.2: every 12 bit coefficient of the encoded polynomials
   must be below q. a key that fails it is not an ml-kem key, and the go
   server refuses it as well */
int vlenc_mlkem_ek_valid(const uint8_t ek[VLENC_MLKEM_EK_LEN]) {
    for (size_t i = 0; i < 3 * 384; i += 3) {
        unsigned a = ek[i] | ((unsigned)(ek[i + 1] & 0x0f) << 8);
        unsigned b = (ek[i + 1] >> 4) | ((unsigned)ek[i + 2] << 4);
        if (a >= 3329 || b >= 3329) return 0;
    }
    return 1;
}

static int b64url_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/* decode one key element. the accepted alphabet is the url one without
   padding, what go's RawURLEncoding reads, so a string that works on the
   server side works here and nothing else does */
static vlenc_status_t decode_key(const char *s, size_t n, uint8_t *dst, size_t cap, size_t *out_len) {
    for (size_t i = 0; i < n; ++i)
        if (!b64url_char(s[i])) return VLENC_ERR_KEY_ENCODING;
    if (n % 4 == 1) return VLENC_ERR_KEY_ENCODING;
    size_t want = n / 4 * 3 + (n % 4 ? n % 4 - 1 : 0);
    if (want != VLENC_X25519_LEN && want != VLENC_MLKEM_EK_LEN) return VLENC_ERR_KEY_LENGTH;
    if (want > cap) return VLENC_ERR_KEY_COUNT;
    size_t got = 0;
    if (b64_decode(s, n, dst, cap, &got) != 0 || got != want) return VLENC_ERR_KEY_ENCODING;
    *out_len = got;
    return VLENC_OK;
}

/* "prob-min-max", three plain decimal integers each below 65536 */
static int parse_triple(const char *s, size_t n, vlenc_pad_t *out) {
    unsigned long v[3];
    size_t i = 0;
    for (int f = 0; f < 3; ++f) {
        size_t start = i;
        unsigned long x = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            x = x * 10 + (unsigned long)(s[i] - '0');
            if (x > 65535) return -1;
            ++i;
        }
        if (i == start || i - start > 5) return -1;
        v[f] = x;
        if (f < 2) {
            if (i >= n || s[i] != '-') return -1;
            ++i;
        }
    }
    if (i != n || v[1] > v[2]) return -1;
    out->prob = (uint16_t)v[0];
    out->min = (uint16_t)v[1];
    out->max = (uint16_t)v[2];
    return 0;
}

static int looks_like_padding(const char *s, size_t n) {
    if (n == 0) return 0;
    for (size_t i = 0; i < n; ++i)
        if (!(s[i] >= '0' && s[i] <= '9') && s[i] != '-') return 0;
    return 1;
}

vlenc_status_t vlenc_parse(const char *text, vlenc_cfg_t *out) {
    if (!text || !out) return VLENC_ERR_ARG;
    memset(out, 0, sizeof *out);
    size_t total = strlen(text);
    if (total >= VLENC_TEXT_MAX) return VLENC_ERR_TOO_LONG;

    vlenc_status_t st = VLENC_OK;
    size_t pos = 0;
    int field = 0;
    int in_keys = 0;
    size_t pad_total = 0;
    size_t blob_used = 0;

    while (pos <= total) {
        const char *f = text + pos;
        const char *dot = memchr(f, '.', total - pos);
        size_t n = dot ? (size_t)(dot - f) : total - pos;

        if (field == 0) {
            if (n != strlen(VLENC_VERSION_NAME) || memcmp(f, VLENC_VERSION_NAME, n) != 0) {
                st = VLENC_ERR_VERSION;
                goto fail;
            }
        } else if (field == 1) {
            if (n == 6 && memcmp(f, "native", 6) == 0) out->xor_mode = VLENC_XOR_NATIVE;
            else if (n == 6 && memcmp(f, "xorpub", 6) == 0) out->xor_mode = VLENC_XOR_PUB;
            else if (n == 6 && memcmp(f, "random", 6) == 0) out->xor_mode = VLENC_XOR_RANDOM;
            else { st = VLENC_ERR_MODE; goto fail; }
        } else if (field == 2) {
            if (n == 4 && memcmp(f, "0rtt", 4) == 0) out->zero_rtt = 1;
            else if (n == 4 && memcmp(f, "1rtt", 4) == 0) out->zero_rtt = 0;
            else { st = VLENC_ERR_RTT; goto fail; }
        } else if (!in_keys && looks_like_padding(f, n)) {
            /* lengths sit at even places, gaps at odd ones */
            int is_len = (out->n_lens + out->n_gaps) % 2 == 0;
            if (out->n_lens + out->n_gaps >= VLENC_MAX_PAD) { st = VLENC_ERR_PADDING; goto fail; }
            vlenc_pad_t *slot = is_len ? &out->lens[out->n_lens] : &out->gaps[out->n_gaps];
            if (parse_triple(f, n, slot) != 0) { st = VLENC_ERR_PADDING; goto fail; }
            if (is_len) {
                /* the first length carries the long handshake record: the
                   server rejects anything below one aead tag and header */
                if (out->n_lens == 0 && (slot->prob < 100 || slot->min < 35 || slot->max < 35)) {
                    st = VLENC_ERR_PADDING;
                    goto fail;
                }
                pad_total += slot->max > slot->min ? slot->max : slot->min;
                if (pad_total > VLENC_PAD_TOTAL_MAX) { st = VLENC_ERR_PADDING; goto fail; }
                out->n_lens++;
            } else {
                out->n_gaps++;
            }
        } else {
            in_keys = 1;
            if (out->n_keys >= VLENC_MAX_KEYS) { st = VLENC_ERR_KEY_COUNT; goto fail; }
            size_t got = 0;
            st = decode_key(f, n, out->blob + blob_used, sizeof out->blob - blob_used, &got);
            if (st != VLENC_OK) goto fail;
            if (got == VLENC_MLKEM_EK_LEN && !vlenc_mlkem_ek_valid(out->blob + blob_used)) {
                st = VLENC_ERR_KEY_VALUE;
                goto fail;
            }
            out->key_off[out->n_keys] = (uint16_t)blob_used;
            out->key_len[out->n_keys] = (uint16_t)got;
            out->n_keys++;
            blob_used += got;
        }

        ++field;
        if (!dot) break;
        pos += n + 1;
    }

    if (field < 4 || out->n_keys == 0) { st = field < 4 ? VLENC_ERR_FORMAT : VLENC_ERR_KEY_COUNT; goto fail; }
    return VLENC_OK;

fail:
    memset(out, 0, sizeof *out);
    return st;
}

static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    char *text;
    vlenc_cfg_t *cfg;
} pool[VLENC_POOL_MAX];
static size_t pool_n; /* slots ever used; a freed slot inside it has text NULL */

vlenc_status_t vlenc_intern(const char *text, uint16_t *id_out) {
    if (!text || !id_out) return VLENC_ERR_ARG;
    *id_out = 0;
    vlenc_cfg_t *cfg = malloc(sizeof *cfg);
    if (!cfg) return VLENC_ERR_ARG;
    vlenc_status_t st = vlenc_parse(text, cfg);
    if (st != VLENC_OK) {
        free(cfg);
        return st;
    }

    pthread_mutex_lock(&pool_lock);
    size_t hole = pool_n;
    for (size_t i = 0; i < pool_n; ++i) {
        if (!pool[i].text) {
            if (hole == pool_n) hole = i;
            continue;
        }
        if (strcmp(pool[i].text, text) == 0) {
            pthread_mutex_unlock(&pool_lock);
            free(cfg);
            *id_out = (uint16_t)(i + 1);
            return VLENC_OK;
        }
    }
    if (hole >= VLENC_POOL_MAX) {
        pthread_mutex_unlock(&pool_lock);
        free(cfg);
        return VLENC_ERR_POOL_FULL;
    }
    size_t tl = strlen(text) + 1;
    char *copy = malloc(tl);
    if (!copy) {
        pthread_mutex_unlock(&pool_lock);
        free(cfg);
        return VLENC_ERR_ARG;
    }
    memcpy(copy, text, tl);
    pool[hole].text = copy;
    pool[hole].cfg = cfg;
    if (hole == pool_n) ++pool_n;
    *id_out = (uint16_t)(hole + 1);
    pthread_mutex_unlock(&pool_lock);
    return VLENC_OK;
}

const char *vlenc_text(uint16_t id) {
    const char *t = NULL;
    pthread_mutex_lock(&pool_lock);
    if (id >= 1 && id <= pool_n) t = pool[id - 1].text;
    pthread_mutex_unlock(&pool_lock);
    return t;
}

const vlenc_cfg_t *vlenc_cfg(uint16_t id) {
    const vlenc_cfg_t *c = NULL;
    pthread_mutex_lock(&pool_lock);
    if (id >= 1 && id <= pool_n) c = pool[id - 1].cfg;
    pthread_mutex_unlock(&pool_lock);
    return c;
}

void vlenc_pool_retain(const uint16_t *ids, size_t n) {
    pthread_mutex_lock(&pool_lock);
    for (size_t i = 0; i < pool_n; ++i) {
        int keep = 0;
        for (size_t k = 0; k < n && !keep; ++k)
            keep = ids[k] == i + 1;
        if (keep || !pool[i].text) continue;
        free(pool[i].text);
        if (pool[i].cfg) {
            memset(pool[i].cfg, 0, sizeof *pool[i].cfg);
            free(pool[i].cfg);
        }
        pool[i].text = NULL;
        pool[i].cfg = NULL;
    }
    while (pool_n > 0 && !pool[pool_n - 1].text) --pool_n;
    pthread_mutex_unlock(&pool_lock);
}

void vlenc_pool_reset(void) {
    pthread_mutex_lock(&pool_lock);
    for (size_t i = 0; i < pool_n; ++i) {
        free(pool[i].text);
        free(pool[i].cfg);
    }
    pool_n = 0;
    memset(pool, 0, sizeof pool);
    pthread_mutex_unlock(&pool_lock);
}
