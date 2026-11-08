#define _POSIX_C_SOURCE 200809L

/* the premium gateway round trip against a stand-in that holds its own rsa
   key: seal and open, api errors, an unsealed failure, and a gateway that
   stalls, redirects, floods or sends something that is no ciphertext */
#include "amnezia_bundle.h"
#include "amnezia_gateway.h"
#include "awg_config.h"
#include "b64.h"
#include "third_party/cJSON.h"
#include "transport.h"

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <strings.h>

static int failed;

static void expect(int pass, const char *what) {
    if (pass) return;
    fprintf(stderr, "FAIL %s\n", what);
    failed++;
}

typedef enum {
    MODE_PREMIUM, MODE_API_409, MODE_API_402, MODE_API_422, MODE_API_429, MODE_PLAIN_500,
    MODE_HTML, MODE_SHORT, MODE_STALL, MODE_REDIRECT, MODE_FLOOD, MODE_NO_COUNTRIES
} mode_t_;

static EVP_PKEY *g_key;
static char g_pem[2048];
static mode_t_ g_mode;
static char g_seen_payload[4096];
static char g_seen_head[2048];
static int g_seen_len_ok;
static int g_api_status;
static const char *g_wg_priv = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

static void make_key(void) {
    g_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, g_key);
    char *data = NULL;
    long n = BIO_get_mem_data(bio, &data);
    memcpy(g_pem, data, (size_t)n);
    g_pem[n] = '\0';
    BIO_free(bio);
}

static int aes_cbc(int enc, const uint8_t *key, const uint8_t *iv, const uint8_t *in, size_t n,
                   uint8_t *out, size_t *out_n) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int a = 0, b = 0;
    int ok = EVP_CipherInit_ex(c, EVP_aes_256_cbc(), NULL, key, iv, enc) == 1 &&
             EVP_CipherUpdate(c, out, &a, in, (int)n) == 1 && EVP_CipherFinal_ex(c, out + a, &b) == 1;
    EVP_CIPHER_CTX_free(c);
    *out_n = ok ? (size_t)(a + b) : 0;
    return ok;
}

#include "premium_fixture.inc"

static void send_all(int fd, const void *data, size_t n) {
    const char *p = (const char *)data;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void reply(int fd, int status, const uint8_t *body, size_t n) {
    char head[160];
    int h = snprintf(head, sizeof head, "HTTP/1.0 %d X\r\nContent-Length: %zu\r\n\r\n", status, n);
    send_all(fd, head, (size_t)h);
    send_all(fd, body, n);
}

static void reply_sealed(int fd, int status, const uint8_t *key, const uint8_t *iv, const char *json) {
    uint8_t ct[8192];
    size_t cn = 0;
    aes_cbc(1, key, iv, (const uint8_t *)json, strlen(json), ct, &cn);
    reply(fd, status, ct, cn);
}

static void *gateway(void *arg) {
    int fd = (int)(intptr_t)arg;
    static char req[16384];
    size_t got = 0;
    char *body = NULL;
    size_t want = 0;
    while (got < sizeof req - 1) {
        ssize_t n = read(fd, req + got, sizeof req - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        req[got] = '\0';
        char *end = strstr(req, "\r\n\r\n");
        if (!end) continue;
        body = end + 4;
        char *cl = strstr(req, "Content-Length: ");
        want = cl ? (size_t)atol(cl + 16) : 0;
        if (got - (size_t)(body - req) >= want) break;
    }
    if (!body) { close(fd); return NULL; }
    snprintf(g_seen_head, sizeof g_seen_head, "%.*s", (int)(body - req), req);
    g_seen_len_ok = got - (size_t)(body - req) == want;

    if (g_mode == MODE_STALL) {
        char dummy;
        (void)!read(fd, &dummy, 1);
        close(fd);
        return NULL;
    }
    if (g_mode == MODE_REDIRECT) {
        const char *r = "HTTP/1.0 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n";
        send_all(fd, r, strlen(r));
        close(fd);
        return NULL;
    }
    if (g_mode == MODE_HTML) {
        const char *h = "<html>captive portal</html>";
        reply(fd, 200, (const uint8_t *)h, strlen(h));
        close(fd);
        return NULL;
    }
    if (g_mode == MODE_PLAIN_500) {
        const char *e = "{\"http_status\":500,\"message\":\"internal server error\"}";
        reply(fd, 500, (const uint8_t *)e, strlen(e));
        close(fd);
        return NULL;
    }
    if (g_mode == MODE_SHORT) {
        uint8_t odd[21] = { 1 };
        reply(fd, 200, odd, sizeof odd);
        close(fd);
        return NULL;
    }
    if (g_mode == MODE_FLOOD) {
        static uint8_t flood[64 * 1024];
        reply(fd, 200, flood, sizeof flood);
        close(fd);
        return NULL;
    }

    /* open the envelope the way the real gateway does */
    cJSON *env = cJSON_ParseWithLength(body, want);
    uint8_t key[32] = { 0 }, iv[32] = { 0 };
    int opened = 0;
    if (cJSON_IsObject(env)) {
        const cJSON *kp = cJSON_GetObjectItem(env, "key_payload");
        const cJSON *ap = cJSON_GetObjectItem(env, "api_payload");
        uint8_t rsa[512], plain[512], ct[4096], pt[4096];
        size_t rn = 0, cn = 0, pn = sizeof plain, tn = 0;
        if (cJSON_IsString(kp) && cJSON_IsString(ap) &&
            b64_decode(kp->valuestring, strlen(kp->valuestring), rsa, sizeof rsa, &rn) == 0 &&
            b64_decode(ap->valuestring, strlen(ap->valuestring), ct, sizeof ct, &cn) == 0) {
            EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(g_key, NULL);
            EVP_PKEY_decrypt_init(c);
            EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PADDING);
            if (EVP_PKEY_decrypt(c, plain, &pn, rsa, rn) == 1) {
                plain[pn] = '\0';
                cJSON *kj = cJSON_Parse((char *)plain);
                const cJSON *k = cJSON_GetObjectItem(kj, "aes_key");
                const cJSON *v = cJSON_GetObjectItem(kj, "aes_iv");
                const cJSON *s = cJSON_GetObjectItem(kj, "aes_salt");
                size_t a = 0, b = 0, d = 0;
                uint8_t salt[16];
                if (cJSON_IsString(k) && cJSON_IsString(v) && cJSON_IsString(s) &&
                    b64_decode(k->valuestring, strlen(k->valuestring), key, 32, &a) == 0 && a == 32 &&
                    b64_decode(v->valuestring, strlen(v->valuestring), iv, 32, &b) == 0 && b == 32 &&
                    b64_decode(s->valuestring, strlen(s->valuestring), salt, sizeof salt, &d) == 0 && d == 8 &&
                    aes_cbc(0, key, iv, ct, cn, pt, &tn)) {
                    pt[tn] = '\0';
                    snprintf(g_seen_payload, sizeof g_seen_payload, "%s", pt);
                    opened = 1;
                }
                cJSON_Delete(kj);
            }
            EVP_PKEY_CTX_free(c);
        }
    }
    cJSON_Delete(env);
    if (!opened) {
        const char *e = "{\"http_status\":400,\"message\":\"invalid payload\"}";
        reply(fd, 400, (const uint8_t *)e, strlen(e));
        close(fd);
        return NULL;
    }
    switch (g_mode) {
        case MODE_API_409:
            reply_sealed(fd, 409, key, iv, "{\"http_status\":409,\"message\":\"Config limit reached\"}"); break;
        case MODE_API_402:
            reply_sealed(fd, 402, key, iv, "{\"http_status\":402,\"message\":\"Payment required\"}"); break;
        case MODE_API_422:
            reply_sealed(fd, 422, key, iv,
                         "{\"http_status\":422,\"message\":\"Failed to retrieve subscription information. Is it activated?\"}");
            break;
        case MODE_API_429:
            reply_sealed(fd, 429, key, iv, "{\"http_status\":429,\"message\":\"slow down\"}"); break;
        default: {
            char *ans = premium_answer(g_mode != MODE_NO_COUNTRIES);
            reply_sealed(fd, 201, key, iv, ans);
            free(ans);
        }
    }
    close(fd);
    return NULL;
}

static int stand_in_dial(void *ctx, const char *host, uint16_t port, int budget_ms) {
    (void)ctx; (void)host; (void)port; (void)budget_ms;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    /* the daemon's dialers hand subfetch a nonblocking descriptor */
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    pthread_t t;
    if (pthread_create(&t, NULL, gateway, (void *)(intptr_t)sv[1]) != 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    pthread_detach(t);
    return sv[0];
}

static subfetch_cfg_t cfg(void) {
    subfetch_cfg_t c;
    memset(&c, 0, sizeof c);
    c.dial = stand_in_dial;
    c.tcp = &transport_tcp;
    return c;
}

static amz_gw_status_t run(mode_t_ mode, char *answer, size_t cap, size_t *n, char *reason,
                           size_t rcap, int timeout_ms) {
    subfetch_cfg_t c = cfg();
    g_mode = mode;
    g_seen_payload[0] = g_seen_head[0] = '\0';
    static const char payload[] = "{\"service_type\":\"amnezia-premium\",\"public_key\":\"x\"}";
    return amz_gw_request(&c, "http://gw.test:80/v1/config", g_pem, payload, strlen(payload),
                          answer, cap, n, timeout_ms, &g_api_status, reason, rcap);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN); /* the flood case writes into a closed socket */
    make_key();
    static char answer[AMZ_GW_MAX_ANSWER];
    char reason[256];
    size_t n = 0;

    amz_gw_status_t r = run(MODE_PREMIUM, answer, sizeof answer, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_OK, "sealed round trip");
    expect(strstr(g_seen_payload, "\"service_type\":\"amnezia-premium\"") != NULL,
           "the gateway read the plaintext payload");
    expect(strncmp(g_seen_head, "POST /v1/config HTTP/1.0\r\n", 26) == 0, "post request line");
    expect(strstr(g_seen_head, "Content-Type: application/json\r\n") != NULL, "json content type");
    expect(strstr(g_seen_head, "x-hwid") == NULL && strstr(g_seen_head, "Cookie") == NULL,
           "no device id or cookie goes to the gateway");
    expect(g_seen_len_ok, "content length matches the body");

    /* the profile out of the answer: the key slot is ours, the tunnel config parses */
    char conf[8192];
    size_t conf_len = 0;
    static amz_premium_profile_t profile;
    expect(amz_premium_parse_profile(answer, n, g_wg_priv, conf, sizeof conf, &conf_len, &profile,
                                     reason, sizeof reason) == AMZ_OK, "profile parses");
    expect(strstr(conf, g_wg_priv) != NULL && strstr(conf, "$WIREGUARD") == NULL,
           "private key replaces the placeholder");
    expect(conf_len == strlen(conf) && conf[conf_len - 1] == '\n', "conf length and newline");
    awg_config_t acfg;
    char why[160];
    expect(awg_config_parse(conf, conf_len, &acfg, why, sizeof why) == AWG_CFG_OK,
           "premium conf is a valid awg config");
    expect(strcmp(profile.country_code, "at") == 0 && strcmp(profile.country_name, "Austria") == 0,
           "current country");
    expect(strncmp(profile.expires_at, "2026-11-06", 10) == 0, "expiry");
    expect(profile.country_count == 4 && profile.countries[0].awg && profile.countries[1].awg &&
           profile.countries[2].awg && !profile.countries[3].awg &&
           strcmp(profile.countries[2].code, "us-east") == 0 &&
           strcmp(profile.countries[2].flag_code, "us") == 0,
           "countries keep the awg flag and the flag code");

    /* api errors keep their words and never hand back an answer */
    static const struct { mode_t_ m; const char *want; } api[] = {
        { MODE_API_409, "device limit" }, { MODE_API_402, "not active" },
        { MODE_API_422, "expired" }, { MODE_API_429, "too many" } };
    for (size_t i = 0; i < sizeof api / sizeof api[0]; ++i) {
        r = run(api[i].m, answer, sizeof answer, &n, reason, sizeof reason, 3000);
        expect(r == AMZ_GW_ERR_API && strstr(reason, api[i].want) && n == 0, api[i].want);
        expect(g_api_status == (api[i].m == MODE_API_409 ? 409 : api[i].m == MODE_API_402 ? 402
                                : api[i].m == MODE_API_422 ? 422 : 429), "the api status is reported");
    }
    r = run(MODE_PLAIN_500, answer, sizeof answer, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_ERR_API && strstr(reason, "500"), "unsealed gateway failure");
    r = run(MODE_HTML, answer, sizeof answer, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_ERR_DECRYPT, "html page is not an answer");
    r = run(MODE_SHORT, answer, sizeof answer, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_ERR_DECRYPT, "ciphertext not a block multiple");
    r = run(MODE_REDIRECT, answer, sizeof answer, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_ERR_NETWORK, "redirect is not followed");
    r = run(MODE_FLOOD, answer, 4096, &n, reason, sizeof reason, 3000);
    expect(r == AMZ_GW_ERR_NETWORK && strstr(reason, "too large"), "answer larger than the cap");
    r = run(MODE_STALL, answer, sizeof answer, &n, reason, sizeof reason, 400);
    expect(r == AMZ_GW_ERR_TIMEOUT, "stalled gateway times out");

    /* a key that is not the gateway's: the stand-in cannot open the envelope */
    {
        subfetch_cfg_t c = cfg();
        EVP_PKEY *other = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, other);
        char *d = NULL;
        long dn = BIO_get_mem_data(bio, &d);
        char other_pem[2048];
        memcpy(other_pem, d, (size_t)dn);
        other_pem[dn] = '\0';
        BIO_free(bio);
        EVP_PKEY_free(other);
        g_mode = MODE_PREMIUM;
        r = amz_gw_request(&c, "http://gw.test/v1/config", other_pem, "{\"a\":1}", 7, answer,
                           sizeof answer, &n, 3000, NULL, reason, sizeof reason);
        expect(r == AMZ_GW_ERR_API && strstr(reason, "400"), "wrong gateway key is reported");
    }

    /* bad arguments and unusable pems fail without touching the network */
    {
        subfetch_cfg_t c = cfg();
        expect(amz_gw_request(&c, "http://gw.test/", "not a pem", "{}", 2, answer, sizeof answer, &n,
                              1000, NULL, reason, sizeof reason) == AMZ_GW_ERR_CRYPTO, "bad pem");
        expect(amz_gw_request(&c, NULL, g_pem, "{}", 2, answer, sizeof answer, &n, 1000, NULL, reason,
                              sizeof reason) == AMZ_GW_ERR_ARG, "no url");
        amz_gw_session_t sess;
        char body[64];
        size_t bl = 0;
        expect(amz_gw_seal(g_pem, "{}", 2, &sess, body, sizeof body, &bl) == AMZ_GW_ERR_SPACE,
               "request body does not fit");
    }

    /* the request document */
    {
        amz_premium_key_t key;
        memset(&key, 0, sizeof key);
        snprintf(key.api_key, sizeof key.api_key, "KEY");
        snprintf(key.service_type, sizeof key.service_type, "amnezia-premium");
        snprintf(key.service_protocol, sizeof key.service_protocol, "awg");
        snprintf(key.user_country_code, sizeof key.user_country_code, "ru");
        char out[2048];
        size_t on = 0;
        expect(amz_premium_build_request(&key, "fi", "PUB=", "uuid-1", out, sizeof out, &on) == AMZ_OK,
               "request builds");
        cJSON *doc = cJSON_Parse(out);
        const cJSON *auth = cJSON_GetObjectItem(doc, "auth_data");
        expect(cJSON_IsObject(doc) && on == strlen(out), "request is json");
        expect(strcmp(cJSON_GetObjectItem(doc, "server_country_code")->valuestring, "fi") == 0 &&
               strcmp(cJSON_GetObjectItem(doc, "public_key")->valuestring, "PUB=") == 0 &&
               strcmp(cJSON_GetObjectItem(doc, "service_protocol")->valuestring, "awg") == 0 &&
               strcmp(cJSON_GetObjectItem(doc, "user_country_code")->valuestring, "ru") == 0 &&
               cJSON_IsObject(auth) && strcmp(cJSON_GetObjectItem(auth, "api_key")->valuestring, "KEY") == 0,
               "request fields");
        expect(strcmp(cJSON_GetObjectItem(doc, "app_version")->valuestring, "5.1.0.6") == 0 &&
               strcmp(cJSON_GetObjectItem(doc, "cli_name")->valuestring, "Senko") == 0,
               "the version the gateway gates on, under senko's own name");
        cJSON_Delete(doc);
        expect(amz_premium_build_request(&key, "", "PUB=", "uuid-1", out, sizeof out, &on) == AMZ_OK &&
               strstr(out, "server_country_code") == NULL, "empty country is left out");
        expect(amz_premium_build_request(&key, "fi", "PUB=", "uuid-1", out, 20, &on) != AMZ_OK,
               "request does not fit");
    }

    /* profile parsing refuses what it cannot use, and clears the conf */
    {
        char *good = premium_answer(1);
        size_t gl = strlen(good);
        expect(amz_premium_parse_profile(good, gl, "short", conf, sizeof conf, &conf_len, &profile,
                                         reason, sizeof reason) == AMZ_ERR_ARG, "bad private key");
        expect(amz_premium_parse_profile(good, gl, g_wg_priv, conf, 100, &conf_len, &profile, reason,
                                         sizeof reason) == AMZ_ERR_SPACE && conf[0] == '\0',
               "conf buffer too small");
        free(good);
        static const char no_config[] = "{\"http_status\":201}";
        expect(amz_premium_parse_profile(no_config, strlen(no_config), g_wg_priv, conf, sizeof conf,
                                         &conf_len, &profile, reason, sizeof reason) == AMZ_ERR_JSON,
               "answer without config");
        static const char bad_bundle[] = "{\"config\":\"vpn://AAAA\"}";
        expect(amz_premium_parse_profile(bad_bundle, strlen(bad_bundle), g_wg_priv, conf, sizeof conf,
                                         &conf_len, &profile, reason, sizeof reason) != AMZ_OK,
               "undecodable bundle");
        g_mode = MODE_NO_COUNTRIES;
        char *none = premium_answer(0);
        expect(amz_premium_parse_profile(none, strlen(none), g_wg_priv, conf, sizeof conf, &conf_len,
                                         &profile, reason, sizeof reason) == AMZ_ERR_JSON &&
               conf[0] == '\0' && conf_len == 0, "answer without a country list");
        free(none);
    }

    /* the api error reader */
    expect(amz_gw_api_error("{\"config\":\"x\",\"http_status\":201}", 31, reason, sizeof reason) == 0,
           "201 is no error");
    expect(amz_gw_api_error("not json", 8, reason, sizeof reason) == 0, "non json is no api error");
    expect(amz_gw_api_error("{\"http_status\":503,\"message\":\"a\\nb\"}", 36, reason, sizeof reason) == 503 &&
           strchr(reason, '\n') == NULL && strstr(reason, "503"), "unknown status keeps one line");

    if (!failed) printf("all amnezia gateway checks passed\n");
    return failed;
}
