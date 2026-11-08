#include "amnezia_gateway.h"

#include "b64.h"
#include "third_party/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "amnezia_gateway_key.inc"

static void set_reason(char *reason, size_t cap, const char *text) {
    if (reason && cap) snprintf(reason, cap, "%s", text);
}

static int rsa_encrypt_pkcs1(const char *pem, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap, size_t *out_len) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return -1;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return -1;
    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    size_t n = out_cap;
    if (ctx && EVP_PKEY_encrypt_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_PKEY_encrypt(ctx, out, &n, in, in_len) == 1) {
        *out_len = n;
        rc = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

amz_gw_status_t amz_gw_seal(const char *pem, const char *payload, size_t payload_len,
                            amz_gw_session_t *session, char *body, size_t body_cap,
                            size_t *body_len) {
    if (!payload || !payload_len || !session || !body || !body_cap || !body_len)
        return AMZ_GW_ERR_ARG;
    if (payload_len > AMZ_GW_MAX_PAYLOAD) return AMZ_GW_ERR_SPACE;
    if (!pem) pem = k_amz_gateway_pem;
    *body_len = 0;
    memset(session, 0, sizeof *session);

    uint8_t salt[8];
    if (RAND_bytes(session->key, sizeof session->key) != 1 ||
        RAND_bytes(session->iv, sizeof session->iv) != 1 || RAND_bytes(salt, sizeof salt) != 1)
        return AMZ_GW_ERR_CRYPTO;

    /* the gateway reads a salt field it never uses, and answers 400 without it */
    char kb[48], ib[48], sb[16];
    size_t kn = 0, in_ = 0, sn = 0;
    if (b64_encode(session->key, sizeof session->key, kb, sizeof kb, &kn) != 0 ||
        b64_encode(session->iv, sizeof session->iv, ib, sizeof ib, &in_) != 0 ||
        b64_encode(salt, sizeof salt, sb, sizeof sb, &sn) != 0)
        return AMZ_GW_ERR_CRYPTO;
    char keys_json[192];
    int kj = snprintf(keys_json, sizeof keys_json,
                      "{\"aes_key\":\"%s\",\"aes_iv\":\"%s\",\"aes_salt\":\"%s\"}", kb, ib, sb);
    if (kj <= 0 || (size_t)kj >= sizeof keys_json) return AMZ_GW_ERR_CRYPTO;

    uint8_t rsa[1024];
    size_t rsa_len = 0;
    amz_gw_status_t r = AMZ_GW_ERR_CRYPTO;
    uint8_t *ct = NULL;
    char *rsa_b64 = NULL;
    char *ct_b64 = NULL;
    if (rsa_encrypt_pkcs1(pem, (const uint8_t *)keys_json, (size_t)kj, rsa, sizeof rsa, &rsa_len) != 0)
        goto done;

    size_t ct_cap = payload_len + 16;
    int ct_len = 0, fin = 0;
    ct = (uint8_t *)malloc(ct_cap);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!ct || !c) { EVP_CIPHER_CTX_free(c); goto done; }
    int ok = EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, session->key, session->iv) == 1 &&
             EVP_EncryptUpdate(c, ct, &ct_len, (const uint8_t *)payload, (int)payload_len) == 1 &&
             EVP_EncryptFinal_ex(c, ct + ct_len, &fin) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) goto done;
    ct_len += fin;

    size_t rb = b64_encoded_maxlen((size_t)rsa_len), cb = b64_encoded_maxlen((size_t)ct_len);
    rsa_b64 = (char *)malloc(rb);
    ct_b64 = (char *)malloc(cb);
    size_t rn = 0, cn = 0;
    if (!rsa_b64 || !ct_b64 || b64_encode(rsa, rsa_len, rsa_b64, rb, &rn) != 0 ||
        b64_encode(ct, (size_t)ct_len, ct_b64, cb, &cn) != 0)
        goto done;
    int n = snprintf(body, body_cap, "{\"key_payload\":\"%s\",\"api_payload\":\"%s\"}", rsa_b64, ct_b64);
    if (n <= 0 || (size_t)n >= body_cap) { r = AMZ_GW_ERR_SPACE; goto done; }
    *body_len = (size_t)n;
    r = AMZ_GW_OK;
done:
    if (r != AMZ_GW_OK) memset(session, 0, sizeof *session);
    OPENSSL_cleanse(keys_json, sizeof keys_json);
    free(ct);
    free(rsa_b64);
    free(ct_b64);
    return r;
}

amz_gw_status_t amz_gw_open(const amz_gw_session_t *session, const uint8_t *in, size_t in_len,
                            char *out, size_t out_cap, size_t *out_len) {
    if (!session || !in || !out || !out_cap || !out_len) return AMZ_GW_ERR_ARG;
    *out_len = 0;
    out[0] = '\0';
    if (in_len == 0 || in_len % 16 != 0) return AMZ_GW_ERR_DECRYPT;
    if (in_len > out_cap) return AMZ_GW_ERR_SPACE;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return AMZ_GW_ERR_CRYPTO;
    int n = 0, fin = 0;
    /* a plaintext error page or a proxy's html fails here, not as garbage json */
    int ok = EVP_DecryptInit_ex(c, EVP_aes_256_cbc(), NULL, session->key, session->iv) == 1 &&
             EVP_DecryptUpdate(c, (uint8_t *)out, &n, in, (int)in_len) == 1 &&
             EVP_DecryptFinal_ex(c, (uint8_t *)out + n, &fin) == 1;
    EVP_CIPHER_CTX_free(c);
    ERR_clear_error();
    if (!ok || (size_t)(n + fin) >= out_cap) {
        OPENSSL_cleanse(out, out_cap);
        out[0] = '\0';
        return ok ? AMZ_GW_ERR_SPACE : AMZ_GW_ERR_DECRYPT;
    }
    *out_len = (size_t)(n + fin);
    out[*out_len] = '\0';
    return AMZ_GW_OK;
}

static int contains_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (; *hay; ++hay)
        if (strncasecmp(hay, needle, n) == 0) return 1;
    return 0;
}

/* the statuses and phrases follow apiUtils::checkApiResponseErrors of the
   official client; the gateway sends them in the body, not as the http code */
int amz_gw_api_error(const char *answer, size_t len, char *reason, size_t reason_cap) {
    set_reason(reason, reason_cap, "");
    if (!answer || len == 0) return 0;
    cJSON *doc = cJSON_ParseWithLength(answer, len);
    if (!cJSON_IsObject(doc)) {
        cJSON_Delete(doc);
        return 0;
    }
    const cJSON *st = cJSON_GetObjectItem(doc, "http_status");
    const cJSON *msg = cJSON_GetObjectItem(doc, "message");
    int status = cJSON_IsNumber(st) ? (int)st->valuedouble : -1;
    const char *m = cJSON_IsString(msg) && msg->valuestring ? msg->valuestring : "";
    if (status < 300) {
        cJSON_Delete(doc);
        return 0;
    }
    char text[200];
    switch (status) {
        case 402:
            if (cJSON_GetObjectItem(doc, "captcha_id") || cJSON_GetObjectItem(doc, "captcha_image") ||
                contains_ci(m, "captcha") || contains_ci(m, "rate limit"))
                snprintf(text, sizeof text, "the gateway asks for a captcha, try again later");
            else
                snprintf(text, sizeof text, "the premium subscription is not active");
            break;
        case 404: snprintf(text, sizeof text, "the gateway does not know this key"); break;
        case 408: snprintf(text, sizeof text, "the gateway timed out"); break;
        case 409:
            if (contains_ci(m, "trial"))
                snprintf(text, sizeof text, "the trial of this key was already used");
            else
                snprintf(text, sizeof text, "the device limit of this subscription is reached");
            break;
        case 422:
            if (strcmp(m, "Failed to retrieve subscription information. Is it activated?") == 0)
                snprintf(text, sizeof text, "the premium subscription has expired");
            else
                snprintf(text, sizeof text, "the gateway refused the request (422)");
            break;
        case 429: snprintf(text, sizeof text, "too many requests, try again later"); break;
        case 501: snprintf(text, sizeof text, "the gateway wants a newer client version"); break;
        default: {
            char clean[96];
            size_t n = 0;
            for (; m[n] && n + 1 < sizeof clean; ++n)
                clean[n] = (unsigned char)m[n] < 0x20 ? ' ' : m[n];
            clean[n] = '\0';
            snprintf(text, sizeof text, "gateway error %d%s%s", status, n ? ": " : "", clean);
        }
    }
    set_reason(reason, reason_cap, text);
    cJSON_Delete(doc);
    return status;
}

amz_gw_status_t amz_gw_request(const subfetch_cfg_t *cfg, const char *url, const char *pem,
                               const char *payload, size_t payload_len,
                               char *answer, size_t answer_cap, size_t *answer_len,
                               int timeout_ms, int *api_status, char *reason, size_t reason_cap) {
    set_reason(reason, reason_cap, "");
    if (api_status) *api_status = 0;
    if (!cfg || !url || !answer || !answer_cap || !answer_len) return AMZ_GW_ERR_ARG;
    *answer_len = 0;
    amz_gw_session_t session;
    memset(&session, 0, sizeof session);
    subfetch_info_t info;
    memset(&info, 0, sizeof info);
    size_t body_cap = 4096 + payload_len * 2;
    char *body = (char *)malloc(body_cap);
    uint8_t *raw = (uint8_t *)malloc(answer_cap);
    amz_gw_status_t r = AMZ_GW_ERR_SPACE;
    if (!body || !raw) goto done;
    size_t body_len = 0;
    r = amz_gw_seal(pem, payload, payload_len, &session, body, body_cap, &body_len);
    if (r != AMZ_GW_OK) {
        set_reason(reason, reason_cap, "could not seal the gateway request");
        goto done;
    }
    size_t raw_len = 0;
    subfetch_status_t t = subfetch_post_json(cfg, url, (const uint8_t *)body, body_len, raw,
                                             answer_cap, &raw_len, timeout_ms, &info);
    if (t != SUBFETCH_OK) {
        if (info.timed_out) {
            r = AMZ_GW_ERR_TIMEOUT;
            set_reason(reason, reason_cap, "the gateway did not answer in time");
        } else {
            r = AMZ_GW_ERR_NETWORK;
            set_reason(reason, reason_cap, t == SUBFETCH_ERR_DIAL ? "cannot reach the gateway"
                       : t == SUBFETCH_ERR_TOOBIG ? "the gateway answer is too large"
                       : "the gateway connection failed");
        }
        goto done;
    }
    r = amz_gw_open(&session, raw, raw_len, answer, answer_cap, answer_len);
    if (r != AMZ_GW_OK) {
        /* an answer in the clear is the gateway failing before it could read
           our key (rsa mismatch or a malformed envelope), or a middlebox */
        int plain = amz_gw_api_error((const char *)raw, raw_len, reason, reason_cap);
        if (plain) {
            char detail[200];
            snprintf(detail, sizeof detail, "gateway rejected the request (%d)", plain);
            set_reason(reason, reason_cap, detail);
            if (api_status) *api_status = plain;
            r = AMZ_GW_ERR_API;
        } else {
            set_reason(reason, reason_cap, "the gateway answer cannot be decrypted");
        }
        goto done;
    }
    int status = amz_gw_api_error(answer, *answer_len, reason, reason_cap);
    if (status != 0) {
        if (api_status) *api_status = status;
        r = AMZ_GW_ERR_API;
        OPENSSL_cleanse(answer, answer_cap);
        *answer_len = 0;
    }
done:
    OPENSSL_cleanse(&session, sizeof session);
    free(body);
    free(raw);
    return r;
}
