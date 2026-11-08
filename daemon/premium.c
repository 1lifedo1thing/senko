#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "premium.h"

#include "core/amnezia_bundle.h"
#include "core/awg_config.h"
#include "core/b64.h"
#include "core/reality_crypto.h"
#include "core/third_party/cJSON.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#define STATE_VERSION 1
#define STATE_MAX_BYTES (96 * 1024)
#define CONF_CAP (64 * 1024)
#define KEY_TEXT_MAX 2048

typedef struct {
    char code[64];
    char flag[16];
    char name[128];
} listed_country_t;

typedef struct {
    char key[KEY_TEXT_MAX];
    char installation_uuid[40];
    char country[64];
    char expires_at[48];
    listed_country_t countries[AMZ_PREMIUM_MAX_COUNTRIES];
    size_t country_count;
} premium_state_t;

long premium_parse_expiry(const char *text) {
    if (!text) return 0;
    int y, mo, d, h, mi, s;
    int used = 0;
    if (sscanf(text, "%4d-%2d-%2d%*1[ T]%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &s, &used) != 6 ||
        y < 2000 || y > 2200 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60)
        return 0;
    const char *p = text + used;
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') ++p;
    }
    long offset = 0;
    if (*p == '+' || *p == '-') {
        int oh = 0, om = 0;
        if (sscanf(p + 1, "%2d:%2d", &oh, &om) != 2 || oh > 23 || om > 59) return 0;
        offset = (long)(oh * 3600 + om * 60) * (*p == '-' ? -1 : 1);
    } else if (*p != 'Z' && *p != '\0') {
        return 0;
    }
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = y - 1900;
    tmv.tm_mon = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = h;
    tmv.tm_min = mi;
    tmv.tm_sec = s;
    time_t t = timegm(&tmv);
    return t == (time_t)-1 ? 0 : (long)t - offset;
}

/* protocol lines are one line each, so nothing the gateway sent may carry a break */
static void clean_line(const char *in, char *out, size_t cap) {
    size_t n = 0;
    if (!cap) return;
    for (; in && *in && n + 1 < cap; ++in)
        out[n++] = (unsigned char)*in < 0x20 || *in == 0x7f ? ' ' : *in;
    out[n] = '\0';
}

/* a field the app splits on spaces: a space or break in it would shift the
   fields after it, or end the line and start one the gateway chose */
static void token_line(const char *in, char *out, size_t cap) {
    clean_line(in, out, cap);
    for (char *p = out; *p; ++p)
        if (*p == ' ') *p = '_';
}

static int fail(char *out, size_t cap, const char *text) {
    char clean[256];
    clean_line(text, clean, sizeof clean);
    snprintf(out, cap, "ERR %s\n", clean);
    return 1;
}

static int read_small_file(const char *path, char **data, size_t *len) {
    *data = NULL;
    *len = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    char *buf = (char *)malloc(STATE_MAX_BYTES + 1);
    if (!buf) { close(fd); return -1; }
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fd, buf + got, STATE_MAX_BYTES - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
        if (got == STATE_MAX_BYTES) break;
    }
    close(fd);
    buf[got] = '\0';
    *data = buf;
    *len = got;
    return 0;
}

static void copy_str(char *dst, size_t cap, const cJSON *v) {
    if (cJSON_IsString(v) && v->valuestring && strlen(v->valuestring) < cap)
        memcpy(dst, v->valuestring, strlen(v->valuestring) + 1);
}

/* 0 loaded, 1 no state saved, -1 unreadable or not ours */
static int load_state(const char *path, premium_state_t *st) {
    memset(st, 0, sizeof *st);
    char *data = NULL;
    size_t len = 0;
    int rc = read_small_file(path, &data, &len);
    if (rc != 0) return rc;
    cJSON *root = cJSON_ParseWithLength(data, len);
    OPENSSL_cleanse(data, len);
    free(data);
    const cJSON *ver = cJSON_IsObject(root) ? cJSON_GetObjectItem(root, "version") : NULL;
    if (!cJSON_IsNumber(ver) || (int)ver->valuedouble != STATE_VERSION) {
        cJSON_Delete(root);
        return -1;
    }
    copy_str(st->key, sizeof st->key, cJSON_GetObjectItem(root, "key"));
    copy_str(st->installation_uuid, sizeof st->installation_uuid,
             cJSON_GetObjectItem(root, "installation_uuid"));
    copy_str(st->country, sizeof st->country, cJSON_GetObjectItem(root, "country"));
    copy_str(st->expires_at, sizeof st->expires_at, cJSON_GetObjectItem(root, "expires_at"));
    const cJSON *list = cJSON_GetObjectItem(root, "countries");
    const cJSON *item = NULL;
    if (cJSON_IsArray(list)) {
        cJSON_ArrayForEach(item, list) {
            if (st->country_count == AMZ_PREMIUM_MAX_COUNTRIES) break;
            listed_country_t *c = &st->countries[st->country_count];
            copy_str(c->code, sizeof c->code, cJSON_GetObjectItem(item, "code"));
            copy_str(c->flag, sizeof c->flag, cJSON_GetObjectItem(item, "flag"));
            copy_str(c->name, sizeof c->name, cJSON_GetObjectItem(item, "name"));
            if (c->code[0]) st->country_count++;
        }
    }
    cJSON_Delete(root);
    return st->key[0] && st->installation_uuid[0] ? 0 : -1;
}

static char *state_text(const premium_state_t *st) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddNumberToObject(root, "version", STATE_VERSION);
    cJSON_AddStringToObject(root, "key", st->key);
    cJSON_AddStringToObject(root, "installation_uuid", st->installation_uuid);
    cJSON_AddStringToObject(root, "country", st->country);
    cJSON_AddStringToObject(root, "expires_at", st->expires_at);
    cJSON *list = cJSON_AddArrayToObject(root, "countries");
    for (size_t i = 0; list && i < st->country_count; ++i) {
        cJSON *c = cJSON_CreateObject();
        if (!c) break;
        cJSON_AddStringToObject(c, "code", st->countries[i].code);
        cJSON_AddStringToObject(c, "flag", st->countries[i].flag);
        cJSON_AddStringToObject(c, "name", st->countries[i].name);
        cJSON_AddItemToArray(list, c);
    }
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return text;
}

/* the profile belongs to whoever owns the directory it sits in: the app runs
   as mobile and replaces it again when the user edits or removes it */
static void adopt_dir_owner(int fd, const char *path) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    *slash = '\0';
    struct stat sb;
    if (stat(dir[0] ? dir : "/", &sb) == 0 && fchown(fd, sb.st_uid, sb.st_gid) != 0 && getuid() == 0)
        fprintf(stderr, "senkod: premium: could not hand %s to its directory owner\n", path);
}

/* writes beside the target and leaves the tmp path for the caller to rename */
static int write_tmp(const char *path, const char *data, size_t len, int adopt, char *tmp, size_t cap) {
    if (snprintf(tmp, cap, "%s.new", path) >= (int)cap) return -1;
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)n;
    }
    if (adopt) adopt_dir_owner(fd, path);
    if (fsync(fd) != 0 || close(fd) != 0) { unlink(tmp); return -1; }
    return 0;
}

/* the state is renamed first: it only names a country and an expiry, while the
   profile is what the tunnel dials. when the second rename fails the old state
   is put back, so the two files never describe different profiles */
static int commit(const premium_env_t *env, const premium_state_t *st, const char *conf, size_t conf_len) {
    char *state = state_text(st);
    if (!state) return -1;
    char state_tmp[512], conf_tmp[512], state_old[512];
    int rc = -1;
    int have_old = 0;
    if (snprintf(state_old, sizeof state_old, "%s.old", env->state_path) >= (int)sizeof state_old) goto done;
    if (write_tmp(env->state_path, state, strlen(state), 0, state_tmp, sizeof state_tmp) != 0) goto done;
    if (write_tmp(env->conf_path, conf, conf_len, 1, conf_tmp, sizeof conf_tmp) != 0) {
        unlink(state_tmp);
        goto done;
    }
    unlink(state_old);
    have_old = link(env->state_path, state_old) == 0;
    if (rename(state_tmp, env->state_path) != 0) {
        unlink(state_tmp);
        unlink(conf_tmp);
        goto done;
    }
    if (rename(conf_tmp, env->conf_path) != 0) {
        unlink(conf_tmp);
        if (have_old) rename(state_old, env->state_path);
        else unlink(env->state_path);
        have_old = 0;
        goto done;
    }
    rc = 0;
done:
    if (have_old) unlink(state_old);
    OPENSSL_cleanse(state, strlen(state));
    free(state);
    return rc;
}

static void new_uuid(char *out, size_t cap) {
    uint8_t b[16];
    if (RAND_bytes(b, sizeof b) != 1) {
        out[0] = '\0';
        return;
    }
    b[6] = (uint8_t)((b[6] & 0x0f) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3f) | 0x80);
    snprintf(out, cap, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
             b[13], b[14], b[15]);
}

static int plain_code(const char *code) {
    if (!code[0]) return 0;
    for (; *code; ++code)
        if ((unsigned char)*code <= 0x20 || *code == 0x7f) return 0;
    return 1;
}

static int awg_listed(const premium_state_t *st, const char *code) {
    for (size_t i = 0; i < st->country_count; ++i)
        if (strcmp(st->countries[i].code, code) == 0) return 1;
    return 0;
}

static void state_lines(const premium_state_t *st, char *out, size_t cap) {
    size_t used = 0;
    char current[64];
    token_line(st->country, current, sizeof current);
    int n = snprintf(out, cap, "PREMIUM STATE %s %ld\n", current[0] ? current : "-",
                     premium_parse_expiry(st->expires_at));
    if (n < 0 || (size_t)n >= cap) { out[0] = '\0'; return; }
    used = (size_t)n;
    for (size_t i = 0; i < st->country_count; ++i) {
        char name[128], flag[16];
        clean_line(st->countries[i].name, name, sizeof name);
        /* a flag code is a short word, so it can sit in front of the free-form name */
        token_line(st->countries[i].flag, flag, sizeof flag);
        char code[64];
        token_line(st->countries[i].code, code, sizeof code);
        n = snprintf(out + used, cap - used, "PREMIUM COUNTRY %s %s %s\n", code,
                     flag[0] ? flag : "-", name);
        if (n < 0 || (size_t)n >= cap - used) break;
        used += (size_t)n;
    }
}

/* asks the gateway for a profile of country (empty lets it choose), checks it,
   and only then replaces the saved one. st is updated in place on success */
static int fetch_profile(const premium_env_t *env, premium_state_t *st, const char *country,
                         const char *done_text, char *out, size_t cap) {
    amz_premium_key_t key;
    char reason[256];
    int rc = 1;
    char *answer = (char *)malloc(AMZ_GW_MAX_ANSWER);
    char *conf = (char *)malloc(CONF_CAP);
    amz_premium_profile_t *profile = (amz_premium_profile_t *)calloc(1, sizeof *profile);
    uint8_t priv[RC_X25519_KEYLEN], pub[RC_X25519_KEYLEN];
    char priv_b64[64], pub_b64[64];
    char payload[4096];
    size_t pn = 0, an = 0, cn = 0;
    memset(priv, 0, sizeof priv);
    memset(priv_b64, 0, sizeof priv_b64);
    if (!answer || !conf || !profile) {
        rc = fail(out, cap, "out of memory");
        goto done;
    }
    if (amz_premium_parse_key(st->key, strlen(st->key), &key, reason, sizeof reason) != AMZ_OK) {
        rc = fail(out, cap, reason);
        goto done;
    }
    if (rc_x25519_keygen(priv, pub) != RC_OK) {
        rc = fail(out, cap, "could not generate a wireguard key");
        goto done;
    }
    /* wg genkey clamps the private scalar, and wireguard peers expect that form */
    priv[0] &= 248;
    priv[31] = (uint8_t)((priv[31] & 127) | 64);
    size_t l = 0;
    if (b64_encode(priv, sizeof priv, priv_b64, sizeof priv_b64, &l) != 0 ||
        b64_encode(pub, sizeof pub, pub_b64, sizeof pub_b64, &l) != 0) {
        rc = fail(out, cap, "could not encode the wireguard key");
        goto done;
    }
    if (amz_premium_build_request(&key, country, pub_b64, st->installation_uuid, payload,
                                  sizeof payload, &pn) != AMZ_OK) {
        rc = fail(out, cap, "could not build the gateway request");
        goto done;
    }
    amz_gw_status_t g = env->request(env->request_ctx, AMZ_GW_PATH_CONFIG, payload, pn, answer,
                                     AMZ_GW_MAX_ANSWER, &an, NULL, reason, sizeof reason);
    OPENSSL_cleanse(payload, sizeof payload);
    if (g != AMZ_GW_OK) {
        rc = fail(out, cap, reason[0] ? reason : "the gateway request failed");
        goto done;
    }
    if (amz_premium_parse_profile(answer, an, priv_b64, conf, CONF_CAP, &cn, profile, reason,
                                  sizeof reason) != AMZ_OK) {
        rc = fail(out, cap, reason);
        goto done;
    }
    awg_config_t cfg;
    char why[160];
    awg_cfg_status_t v = awg_config_parse(conf, cn, &cfg, why, sizeof why);
    OPENSSL_cleanse(&cfg, sizeof cfg);
    if (v != AWG_CFG_OK) {
        char text[224];
        snprintf(text, sizeof text, "the premium profile is not usable: %s", why);
        rc = fail(out, cap, text);
        goto done;
    }

    premium_state_t next = *st;
    next.country_count = 0;
    /* a country that only serves vless cannot be dialed, so it is not offered */
    for (size_t i = 0; i < profile->country_count; ++i) {
        if (!profile->countries[i].awg) continue;
        /* the code goes back to the gateway and onto a control line as is */
        if (!plain_code(profile->countries[i].code)) continue;
        listed_country_t *c = &next.countries[next.country_count++];
        snprintf(c->code, sizeof c->code, "%s", profile->countries[i].code);
        snprintf(c->flag, sizeof c->flag, "%s", profile->countries[i].flag_code);
        snprintf(c->name, sizeof c->name, "%s", profile->countries[i].name);
    }
    snprintf(next.country, sizeof next.country, "%s", plain_code(profile->country_code) ? profile->country_code : "");
    snprintf(next.expires_at, sizeof next.expires_at, "%s", profile->expires_at);
    if (commit(env, &next, conf, cn) != 0) {
        rc = fail(out, cap, "could not save the premium profile");
        goto done;
    }
    *st = next;
    OPENSSL_cleanse(&next, sizeof next);
    size_t used = 0;
    state_lines(st, out, cap);
    used = strlen(out);
    snprintf(out + used, cap - used, "OK %s\n", done_text);
    fprintf(stderr, "senkod: premium profile stored for %s\n", st->country);
    rc = 0;
done:
    OPENSSL_cleanse(priv, sizeof priv);
    OPENSSL_cleanse(priv_b64, sizeof priv_b64);
    if (conf) OPENSSL_cleanse(conf, CONF_CAP);
    free(answer);
    free(conf);
    free(profile);
    return rc;
}

/* asks the gateway to drop this install. a slot the gateway no longer knows
   (404) is as good as released. on failure why gets the reason */
static void release_slot(const premium_env_t *env, const premium_state_t *st, char *why, size_t why_cap) {
    amz_premium_key_t key;
    char reason[256] = "";
    char payload[2048];
    size_t pn = 0;
    why[0] = '\0';
    if (amz_premium_parse_key(st->key, strlen(st->key), &key, reason, sizeof reason) != AMZ_OK ||
        amz_premium_build_revoke(&key, st->country, st->installation_uuid, payload, sizeof payload,
                                 &pn) != AMZ_OK) {
        snprintf(why, why_cap, "the saved key cannot be read");
        return;
    }
    char *answer = (char *)malloc(AMZ_GW_MAX_ANSWER);
    size_t an = 0;
    int api_status = 0;
    if (!answer) {
        snprintf(why, why_cap, "out of memory");
        return;
    }
    amz_gw_status_t g = env->request(env->request_ctx, AMZ_GW_PATH_REVOKE, payload, pn, answer,
                                     AMZ_GW_MAX_ANSWER, &an, &api_status, reason, sizeof reason);
    if (g != AMZ_GW_OK && !(g == AMZ_GW_ERR_API && api_status == 404)) {
        char clean[160];
        clean_line(reason[0] ? reason : "the gateway request failed", clean, sizeof clean);
        snprintf(why, why_cap, "%s", clean);
    }
    OPENSSL_cleanse(payload, sizeof payload);
    OPENSSL_cleanse(&key, sizeof key);
    free(answer);
}

int premium_run(const premium_env_t *env, const char *op, const char *arg, char *out, size_t cap) {
    if (!env || !env->state_path || !env->conf_path || !env->request || !op || !out || cap < 64)
        return 1;
    out[0] = '\0';
    premium_state_t *st = (premium_state_t *)calloc(1, sizeof *st);
    if (!st) return fail(out, cap, "out of memory");
    int rc = 1;
    int have = load_state(env->state_path, st);

    if (strcmp(op, "KEY") == 0) {
        amz_premium_key_t key;
        char reason[160];
        if (!arg || amz_premium_parse_key(arg, strlen(arg), &key, reason, sizeof reason) != AMZ_OK) {
            rc = fail(out, cap, arg ? reason : "no premium key given");
            goto done;
        }
        if (strlen(arg) >= sizeof st->key) {
            rc = fail(out, cap, "the premium key is too long");
            goto done;
        }
        premium_state_t fresh;
        memset(&fresh, 0, sizeof fresh);
        /* the install id is what the gateway counts devices by, so a new key
           on the same phone reuses it */
        if (have == 0) memcpy(fresh.installation_uuid, st->installation_uuid, sizeof fresh.installation_uuid);
        if (!fresh.installation_uuid[0]) new_uuid(fresh.installation_uuid, sizeof fresh.installation_uuid);
        if (!fresh.installation_uuid[0]) {
            rc = fail(out, cap, "could not generate an install id");
            goto done;
        }
        snprintf(fresh.key, sizeof fresh.key, "%s", arg);
        rc = fetch_profile(env, &fresh, "", "premium profile added", out, cap);
        /* the old key keeps counting this phone as a device until released.
           it is already replaced, so a failure here only leaves a log line */
        if (rc == 0 && have == 0 && strcmp(st->key, fresh.key) != 0) {
            char released[200];
            release_slot(env, st, released, sizeof released);
            if (released[0])
                fprintf(stderr, "senkod: premium: old key slot not released: %s\n", released);
        }
        OPENSSL_cleanse(&fresh, sizeof fresh);
    } else if (strcmp(op, "COUNTRY") == 0 || strcmp(op, "REFRESH") == 0) {
        if (have != 0) {
            rc = fail(out, cap, have > 0 ? "no premium key is saved" : "the saved premium state is unreadable");
            goto done;
        }
        int pick = op[0] == 'C';
        if (pick && (!arg || !awg_listed(st, arg))) {
            rc = fail(out, cap, "this country is not available");
            goto done;
        }
        rc = fetch_profile(env, st, pick ? arg : st->country, pick ? "premium country changed" : "premium profile refreshed",
                           out, cap);
    } else if (strcmp(op, "STATE") == 0) {
        if (have != 0) {
            rc = fail(out, cap, have > 0 ? "no premium key is saved" : "the saved premium state is unreadable");
            goto done;
        }
        state_lines(st, out, cap);
        size_t used = strlen(out);
        snprintf(out + used, cap - used, "OK premium state\n");
        rc = 0;
    } else if (strcmp(op, "FORGET") == 0) {
        /* the profile file is the app's to remove, since it owns the saved
           profile choice; the key goes here. the gateway counts devices, and
           a removed profile must not keep one of the user's slots */
        char released[200] = "";
        if (have == 0) release_slot(env, st, released, sizeof released);
        if (unlink(env->state_path) != 0 && errno != ENOENT) {
            rc = fail(out, cap, "could not remove the premium key");
            goto done;
        }
        if (released[0]) snprintf(out, cap, "OK premium key removed, device slot not released: %s\n", released);
        else snprintf(out, cap, "OK premium key removed\n");
        rc = 0;
    } else {
        rc = fail(out, cap, "unknown premium request");
    }
done:
    OPENSSL_cleanse(st, sizeof *st);
    free(st);
    return rc;
}
