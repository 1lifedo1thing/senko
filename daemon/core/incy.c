#include "incy.h"
#include "happ.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>

#include "third_party/cJSON.h"

/* declared in config.h; avoid circular include */
int url_percent_decode(const char *src, size_t src_len, char *dst, size_t cap);

#define INCY_LINK_MAX 8192
#define INCY_IV_LEN 12
#define INCY_TAG_LEN 16

/* sha256 of the published seed in @incy/link-encoder 1.3.0 (salts "incy",
   "deep", "crypt1", "v2026.06" plus two 32 byte keymat slices). INCY calls
   crypt1 obfuscation: every client carries this key. fingerprint (sha256 of
   the key) is b6bf7084...c08c, as the package expects */
static const uint8_t k_crypt1_key[32] = {
    0xf6, 0xd4, 0x0e, 0xa0, 0xc8, 0xa8, 0x89, 0x9d, 0x7c, 0x68, 0x2d, 0x09,
    0xba, 0x0d, 0x41, 0x65, 0xdf, 0xe2, 0xb3, 0xdd, 0x45, 0xe6, 0xbb, 0x3e,
    0x25, 0xcb, 0x23, 0x3c, 0xf0, 0x0c, 0x24, 0x62
};

static int has_prefix(const char *s, const char *prefix) {
    return strncasecmp(s, prefix, strlen(prefix)) == 0;
}

static int is_http_url(const char *s) {
    return has_prefix(s, "http://") || has_prefix(s, "https://");
}

static int has_control_or_space(const char *s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f) return 1;
    }
    return 0;
}

static int has_control(const char *s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 1;
    }
    return 0;
}

/* the label is cosmetic, so a long one is cut instead of refused. the store
   keeps 63 bytes of it; the cut must not leave half of a utf-8 sequence */
static incy_status_t set_name(const char *src, size_t n, char *name, size_t cap) {
    if (!name || cap == 0) return INCY_OK;
    if (has_control(src, n)) return INCY_ERR_MALFORMED;
    if (n >= cap) {
        n = cap - 1;
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80) --n;
    }
    memcpy(name, src, n);
    name[n] = '\0';
    return INCY_OK;
}

static incy_status_t copy_source(const char *src, size_t n, char *out, size_t cap) {
    if (n + 1 > cap) return INCY_ERR_TOO_LONG;
    memcpy(out, src, n);
    out[n] = '\0';
    return INCY_OK;
}

static incy_status_t decrypt_crypt1(const char *payload, size_t plen,
                                    char *out, size_t out_cap,
                                    char *name, size_t name_cap) {
    unsigned char wire[INCY_LINK_MAX];
    char plain[INCY_LINK_MAX];
    size_t wire_len = 0;
    int n = 0, fin = 0;
    EVP_CIPHER_CTX *ctx;
    cJSON *root;
    const cJSON *url, *ver, *label;
    incy_status_t st;

    /* the sender strips padding and may leave a trailing slash */
    while (plen > 0 && payload[plen - 1] == '/') --plen;
    if (plen == 0) return INCY_ERR_MALFORMED;
    for (size_t i = 0; i < plen; ++i) {
        unsigned char c = (unsigned char)payload[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '=') return INCY_ERR_MALFORMED;
    }
    if (happ_b64_decode_ex(payload, plen, wire, sizeof wire, &wire_len) != 0)
        return INCY_ERR_MALFORMED;
    if (wire_len < INCY_IV_LEN + INCY_TAG_LEN + 1) return INCY_ERR_MALFORMED;

    size_t ct_len = wire_len - INCY_IV_LEN - INCY_TAG_LEN;
    if (ct_len >= sizeof plain) return INCY_ERR_TOO_LONG;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return INCY_ERR_DECRYPT;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, INCY_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, k_crypt1_key, wire) != 1 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)plain, &n,
                          wire + INCY_IV_LEN, (int)ct_len) != 1 ||
        (size_t)n != ct_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, INCY_TAG_LEN,
                            wire + INCY_IV_LEN + ct_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, (unsigned char *)plain + n, &fin) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return INCY_ERR_DECRYPT;
    }
    EVP_CIPHER_CTX_free(ctx);

    root = cJSON_ParseWithLength(plain, ct_len);
    if (!root) return INCY_ERR_MALFORMED;
    url = cJSON_GetObjectItemCaseSensitive(root, "url");
    ver = cJSON_GetObjectItemCaseSensitive(root, "v");
    label = cJSON_GetObjectItemCaseSensitive(root, "n");
    /* a schema newer than 1 may change what the fields mean */
    if (!cJSON_IsObject(root) || !cJSON_IsString(url) || !url->valuestring[0] ||
        (ver && (!cJSON_IsNumber(ver) || ver->valuedouble != 1.0)) ||
        (label && !cJSON_IsString(label)) ||
        !is_http_url(url->valuestring) ||
        has_control_or_space(url->valuestring, strlen(url->valuestring))) {
        cJSON_Delete(root);
        return INCY_ERR_MALFORMED;
    }
    st = copy_source(url->valuestring, strlen(url->valuestring), out, out_cap);
    if (st == INCY_OK && label)
        st = set_name(label->valuestring, strlen(label->valuestring), name, name_cap);
    cJSON_Delete(root);
    return st;
}

/* the name after # in an http(s) url is for the list only, a server never sees it */
static incy_status_t fragment_name(const char *src, size_t n, char *name, size_t cap) {
    const char *hash = memchr(src, '#', n);
    char decoded[INCY_LINK_MAX];
    if (!hash || !name) return INCY_OK;
    ++hash;
    if (url_percent_decode(hash, (size_t)(src + n - hash), decoded, sizeof decoded) < 0)
        return INCY_ERR_MALFORMED;
    return set_name(decoded, strlen(decoded), name, cap);
}

static incy_status_t unwrap(const char *link, char *out, size_t out_cap,
                            char *name, size_t name_cap) {
    const char *p, *payload;
    size_t host_len, plen;

    if (!out || out_cap == 0) return INCY_ERR_MALFORMED;
    out[0] = '\0';
    if (name && name_cap) name[0] = '\0';
    if (!link || !has_prefix(link, "incy://")) return INCY_ERR_SCHEME;
    if (strlen(link) >= INCY_LINK_MAX) return INCY_ERR_TOO_LONG;

    p = link + 7;
    host_len = strcspn(p, "/");
    if (p[host_len] != '/') {
        /* connect, status and the other payload-free actions */
        return INCY_ERR_UNSUPPORTED;
    }
    payload = p + host_len + 1;
    plen = strlen(payload);

    if (host_len == 6 && strncasecmp(p, "crypt1", 6) == 0)
        return decrypt_crypt1(payload, plen, out, out_cap, name, name_cap);
    if (!((host_len == 3 && strncasecmp(p, "add", 3) == 0) ||
          (host_len == 6 && strncasecmp(p, "import", 6) == 0)))
        return INCY_ERR_UNSUPPORTED;

    if (plen == 0) return INCY_ERR_MALFORMED;
    if (is_http_url(payload)) {
        incy_status_t st;
        if (has_control_or_space(payload, plen)) return INCY_ERR_MALFORMED;
        st = fragment_name(payload, plen, name, name_cap);
        if (st != INCY_OK) return st;
    }
    return copy_source(payload, plen, out, out_cap);
}

incy_status_t incy_unwrap(const char *link, char *out, size_t out_cap,
                          char *name, size_t name_cap) {
    incy_status_t st = unwrap(link, out, out_cap, name, name_cap);
    /* a refused link leaves nothing behind for a caller to use by mistake */
    if (st != INCY_OK && out && out_cap) out[0] = '\0';
    if (st != INCY_OK && name && name_cap) name[0] = '\0';
    return st;
}
