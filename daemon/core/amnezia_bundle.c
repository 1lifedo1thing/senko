#include "amnezia_bundle.h"

#include "b64.h"
#include "third_party/cJSON.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static const char k_scheme[] = "vpn://";

static void set_reason(char *reason, size_t cap, const char *text) {
    if (!reason || cap == 0) return;
    snprintf(reason, cap, "%s", text ? text : "invalid amnezia bundle");
}

/* the qt writers emit a byte order mark and the share sheets add newlines */
static void trim_input(const char **start, const char **end) {
    const char *s = *start;
    const char *e = *end;
    if (e - s >= 3 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB &&
        (unsigned char)s[2] == 0xBF)
        s += 3;
    while (s < e && isspace((unsigned char)*s)) ++s;
    while (e > s && isspace((unsigned char)e[-1])) --e;
    *start = s;
    *end = e;
}

static int has_scheme(const char *s, const char *e) {
    size_t n = sizeof k_scheme - 1;
    return (size_t)(e - s) > n && strncmp(s, k_scheme, n) == 0;
}

/* a base64 body long enough to hold a compressed profile, nothing else */
static int looks_like_base64_body(const char *s, const char *e) {
    if (e - s < 64) return 0;
    for (const char *p = s; p < e; ++p) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '=')
            continue;
        if (isspace(c)) continue;
        return 0;
    }
    return 1;
}

/* the input is a byte range, not a c string: a pasted blob is not terminated */
static int span_contains(const char *s, const char *e, const char *needle) {
    size_t n = strlen(needle);
    if ((size_t)(e - s) < n) return 0;
    for (const char *p = s; (size_t)(e - p) >= n; ++p)
        if (memcmp(p, needle, n) == 0) return 1;
    return 0;
}

int amz_bundle_looks_like(const char *text, size_t len) {
    if (!text || len == 0) return 0;
    const char *s = text;
    const char *e = text + len;
    trim_input(&s, &e);
    if (s >= e) return 0;
    if (has_scheme(s, e)) return 1;
    /* a bare base64 body is indistinguishable from a base64 subscription feed,
       so only the scheme and the plain json shape classify without decoding */
    return *s == '{' && (span_contains(s, e, "\"containers\"") ||
                         span_contains(s, e, "\"last_config\""));
}

static uint32_t read_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* qCompress prefixes the zlib stream with the uncompressed size, but Qt only
   uses it as the first buffer guess and keeps inflating when it is short: the
   key AmneziaVPN issued for a real premium subscription declares 255 bytes and
   inflates to 262. the declared size therefore sizes the first buffer and
   nothing more, and AMZ_BUNDLE_MAX_JSON is the only hard bound on the output */
static amz_status_t qt_uncompress(const unsigned char *in, size_t in_len,
                                  char **out, size_t *out_len) {
    if (in_len < 6) return AMZ_ERR_DECODE;
    uint32_t declared = read_be32(in);
    size_t cap = declared < 1024 ? 1024 : declared > AMZ_BUNDLE_MAX_JSON ? AMZ_BUNDLE_MAX_JSON : declared;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) return AMZ_ERR_SPACE;

    z_stream zs;
    memset(&zs, 0, sizeof zs);
    zs.next_in = (Bytef *)(uintptr_t)(in + 4);
    zs.avail_in = (uInt)(in_len - 4);
    if (inflateInit(&zs) != Z_OK) {
        free(buf);
        return AMZ_ERR_DECODE;
    }
    int rc = Z_OK;
    for (;;) {
        zs.next_out = (Bytef *)buf + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) break;
        if (zs.avail_out != 0) break; /* input ran out inside the stream */
        if (cap >= AMZ_BUNDLE_MAX_JSON) break;
        size_t next = cap * 2 > AMZ_BUNDLE_MAX_JSON ? AMZ_BUNDLE_MAX_JSON : cap * 2;
        char *grown = (char *)realloc(buf, next + 1);
        if (!grown) {
            inflateEnd(&zs);
            free(buf);
            return AMZ_ERR_SPACE;
        }
        buf = grown;
        cap = next;
    }
    size_t produced = (size_t)zs.total_out;
    inflateEnd(&zs);
    if (rc != Z_STREAM_END || produced == 0) {
        free(buf);
        return AMZ_ERR_DECODE;
    }
    buf[produced] = '\0';
    *out = buf;
    *out_len = produced;
    return AMZ_OK;
}

/* the container that carries a wireguard profile, preferring the one the
   bundle names as default so a multi protocol share picks the same one twice */
static const cJSON *pick_protocol(const cJSON *root, const char **out_kind) {
    const cJSON *containers = cJSON_GetObjectItem((cJSON *)root, "containers");
    if (!cJSON_IsArray(containers)) return NULL;
    const cJSON *preferred = cJSON_GetObjectItem((cJSON *)root, "defaultContainer");
    const char *want = cJSON_IsString(preferred) ? preferred->valuestring : NULL;
    static const char *kinds[] = { "awg", "wireguard", NULL };

    for (int pass = 0; pass < 2; ++pass) {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, containers) {
            if (!cJSON_IsObject(item)) continue;
            if (pass == 0 && want) {
                const cJSON *name = cJSON_GetObjectItem((cJSON *)item, "container");
                if (!cJSON_IsString(name) || strcmp(name->valuestring, want) != 0)
                    continue;
            } else if (pass == 0) {
                continue;
            }
            for (size_t i = 0; kinds[i]; ++i) {
                const cJSON *proto = cJSON_GetObjectItem((cJSON *)item, kinds[i]);
                if (cJSON_IsObject(proto)) {
                    if (out_kind) *out_kind = kinds[i];
                    return proto;
                }
            }
        }
    }
    return NULL;
}

/* last_config is a json document stored as a json string; a few generators
   store the object directly, and both spellings carry the same config field */
static const char *config_text_of(const cJSON *proto, cJSON **owned) {
    const cJSON *last = cJSON_GetObjectItem((cJSON *)proto, "last_config");
    if (cJSON_IsObject(last)) {
        const cJSON *cfg = cJSON_GetObjectItem((cJSON *)last, "config");
        return cJSON_IsString(cfg) ? cfg->valuestring : NULL;
    }
    if (!cJSON_IsString(last)) return NULL;
    cJSON *inner = cJSON_Parse(last->valuestring);
    if (!inner) return NULL;
    const cJSON *cfg = cJSON_GetObjectItem(inner, "config");
    if (!cJSON_IsString(cfg)) {
        cJSON_Delete(inner);
        return NULL;
    }
    *owned = inner;
    return cfg->valuestring;
}

static amz_status_t emit(const char *conf, char *out, size_t cap, size_t *out_len,
                         char *reason, size_t reason_cap) {
    size_t n = strlen(conf);
    while (n && (conf[n - 1] == '\n' || conf[n - 1] == '\r' || conf[n - 1] == ' '))
        --n;
    if (n == 0) {
        set_reason(reason, reason_cap, "amnezia bundle carries an empty config");
        return AMZ_ERR_JSON;
    }
    if (n + 2 > cap) {
        set_reason(reason, reason_cap, "amnezia config does not fit");
        return AMZ_ERR_SPACE;
    }
    memcpy(out, conf, n);
    out[n] = '\n';
    out[n + 1] = '\0';
    *out_len = n + 1;
    return AMZ_OK;
}

static amz_status_t decode_bundle(const char *in, size_t len, cJSON **out_root,
                                  char *reason, size_t reason_cap) {
    *out_root = NULL;
    const char *s = in;
    const char *e = in + len;
    trim_input(&s, &e);
    if (s >= e) return AMZ_ERR_NOT_BUNDLE;

    char *json = NULL;
    size_t json_len = 0;
    if (*s == '{') {
        if ((size_t)(e - s) > AMZ_BUNDLE_MAX_JSON) {
            set_reason(reason, reason_cap, "amnezia bundle is too large");
            return AMZ_ERR_SPACE;
        }
        json_len = (size_t)(e - s);
        json = (char *)malloc(json_len + 1);
        if (!json) return AMZ_ERR_SPACE;
        memcpy(json, s, json_len);
        json[json_len] = '\0';
    } else {
        if (has_scheme(s, e)) s += sizeof k_scheme - 1;
        else if (!looks_like_base64_body(s, e)) return AMZ_ERR_NOT_BUNDLE;
        size_t body_len = (size_t)(e - s);
        if (body_len > AMZ_BUNDLE_MAX_JSON) {
            set_reason(reason, reason_cap, "amnezia bundle is too large");
            return AMZ_ERR_SPACE;
        }
        size_t raw_cap = b64_decoded_maxlen(body_len);
        unsigned char *raw = (unsigned char *)malloc(raw_cap);
        if (!raw) return AMZ_ERR_SPACE;
        size_t raw_len = 0;
        if (b64_decode(s, body_len, raw, raw_cap, &raw_len) != 0 || raw_len == 0) {
            free(raw);
            set_reason(reason, reason_cap, "amnezia bundle is not base64");
            return AMZ_ERR_DECODE;
        }
        if (raw[0] == '{') {
            json_len = raw_len;
            json = (char *)malloc(json_len + 1);
            if (json) {
                memcpy(json, raw, json_len);
                json[json_len] = '\0';
            }
            free(raw);
            if (!json) return AMZ_ERR_SPACE;
        } else {
            amz_status_t r = qt_uncompress(raw, raw_len, &json, &json_len);
            free(raw);
            if (r != AMZ_OK) {
                set_reason(reason, reason_cap, "amnezia bundle does not decompress");
                return r;
            }
        }
    }

    cJSON *root = cJSON_ParseWithLength(json, json_len);
    free(json);
    if (!root) {
        set_reason(reason, reason_cap, "amnezia bundle is not json");
        return AMZ_ERR_JSON;
    }

    *out_root = root;
    return AMZ_OK;
}

static int copy_json_field(const cJSON *obj, const char *name, char *out, size_t cap) {
    const cJSON *value = cJSON_GetObjectItem((cJSON *)obj, name);
    if (!cJSON_IsString(value) || !value->valuestring || !value->valuestring[0]) return -1;
    size_t len = strlen(value->valuestring);
    if (len >= cap) return -1;
    memcpy(out, value->valuestring, len + 1);
    return 0;
}

amz_status_t amz_premium_parse_key(const char *in, size_t len,
                                   amz_premium_key_t *key,
                                   char *reason, size_t reason_cap) {
    if (!in || !key) return AMZ_ERR_ARG;
    memset(key, 0, sizeof *key);
    cJSON *root = NULL;
    amz_status_t r = decode_bundle(in, len, &root, reason, reason_cap);
    if (r != AMZ_OK) return r;
    const cJSON *auth = cJSON_GetObjectItem(root, "auth_data");
    if (!auth) {
        cJSON_Delete(root);
        set_reason(reason, reason_cap, "not a premium subscription key");
        return AMZ_ERR_NOT_BUNDLE;
    }
    const cJSON *api = cJSON_GetObjectItem(root, "api_config");
    const cJSON *version = cJSON_GetObjectItem(root, "config_version");
    if (!cJSON_IsObject(auth) || !cJSON_IsObject(api) || !cJSON_IsNumber(version) ||
        version->valuedouble != 2 ||
        copy_json_field(auth, "api_key", key->api_key, sizeof key->api_key) ||
        copy_json_field(api, "service_type", key->service_type, sizeof key->service_type) ||
        copy_json_field(api, "service_protocol", key->service_protocol, sizeof key->service_protocol) ||
        copy_json_field(api, "user_country_code", key->user_country_code, sizeof key->user_country_code)) {
        memset(key, 0, sizeof *key);
        set_reason(reason, reason_cap, AMZ_PREMIUM_INVALID_REASON);
        r = AMZ_ERR_JSON;
    } else {
        set_reason(reason, reason_cap, "ok");
    }
    cJSON_Delete(root);
    return r;
}

/* a country that names its protocols and leaves out awg is kept with awg
   cleared, not rejected */
static int has_protocol(const cJSON *item, const char *want, int *valid) {
    const cJSON *list = cJSON_GetObjectItem((cJSON *)item, "available_protocols");
    *valid = 1;
    if (!list) return 1;
    if (!cJSON_IsArray(list)) { *valid = 0; return 0; }
    int found = 0;
    const cJSON *p = NULL;
    cJSON_ArrayForEach(p, list) {
        if (!cJSON_IsString(p)) { *valid = 0; return 0; }
        if (strcmp(p->valuestring, want) == 0) found = 1;
    }
    /* an empty list says nothing, and the official client treats it the same */
    return cJSON_GetArraySize(list) == 0 ? 1 : found;
}

static amz_status_t countries_of(const cJSON *root, amz_premium_country_t *countries,
                                 size_t cap, size_t *count, char *reason, size_t reason_cap) {
    *count = 0;
    const cJSON *api = cJSON_GetObjectItem((cJSON *)root, "api_config");
    const cJSON *list = cJSON_IsObject(api) ? cJSON_GetObjectItem((cJSON *)api, "available_countries") : NULL;
    if (!cJSON_IsArray(list)) {
        set_reason(reason, reason_cap, "premium country list missing");
        return AMZ_ERR_JSON;
    }
    size_t n = 0;
    amz_status_t result = AMZ_OK;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, list) {
        if (n == cap) { result = AMZ_ERR_SPACE; break; }
        amz_premium_country_t country;
        memset(&country, 0, sizeof country);
        if (!cJSON_IsObject(item) ||
            copy_json_field(item, "server_country_code", country.code, sizeof country.code) ||
            copy_json_field(item, "server_country_name", country.name, sizeof country.name)) {
            result = AMZ_ERR_JSON;
            break;
        }
        const cJSON *flag = cJSON_GetObjectItem((cJSON *)item, "server_country_code_l10n");
        if (flag && (!cJSON_IsString(flag) || !flag->valuestring ||
                     strlen(flag->valuestring) >= sizeof country.flag_code)) {
            result = AMZ_ERR_JSON;
            break;
        }
        if (flag) memcpy(country.flag_code, flag->valuestring, strlen(flag->valuestring) + 1);
        int valid = 0;
        country.awg = has_protocol(item, "awg", &valid);
        if (!valid) { result = AMZ_ERR_JSON; break; }
        countries[n++] = country;
    }
    if (result != AMZ_OK) {
        memset(countries, 0, n * sizeof *countries);
        set_reason(reason, reason_cap, result == AMZ_ERR_SPACE ?
                   "premium country list exceeds capacity" : "invalid premium country");
        return result;
    }
    *count = n;
    set_reason(reason, reason_cap, "ok");
    return AMZ_OK;
}

amz_status_t amz_premium_parse_countries(const char *json, size_t len,
                                         amz_premium_country_t *countries, size_t cap,
                                         size_t *count, char *reason, size_t reason_cap) {
    if (!json || !countries || !count || cap == 0) return AMZ_ERR_ARG;
    *count = 0;
    if (len == 0 || len > AMZ_BUNDLE_MAX_JSON) return AMZ_ERR_SPACE;
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        set_reason(reason, reason_cap, "invalid premium configuration");
        return AMZ_ERR_JSON;
    }
    amz_status_t r = countries_of(root, countries, cap, count, reason, reason_cap);
    cJSON_Delete(root);
    return r;
}

/* the gateway answers 501 "client version update is required" to a request
   without a recent app_version, whatever cli_name says, and takes 5.1.0.6, the
   release this request format was read from. cli_name stays Senko: the
   gateway does not gate on it. raise this when the gateway raises its floor */
#define AMZ_GATEWAY_APP_VERSION "5.1.0.6"

static int add_text(cJSON *obj, const char *name, const char *value) {
    return value && value[0] && cJSON_AddStringToObject(obj, name, value) != NULL;
}

amz_status_t amz_premium_build_request(const amz_premium_key_t *key, const char *country,
                                       const char *public_key_b64, const char *installation_uuid,
                                       char *out, size_t cap, size_t *out_len) {
    if (!key || !key->api_key[0] || !public_key_b64 || !public_key_b64[0] || !out || !cap ||
        !out_len)
        return AMZ_ERR_ARG;
    *out_len = 0;
    cJSON *root = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    amz_status_t r = AMZ_ERR_SPACE;
    if (!root || !auth) goto done;
    if (!add_text(auth, "api_key", key->api_key)) goto done;
    if (!add_text(root, "user_country_code", key->user_country_code) ||
        (country && country[0] && !add_text(root, "server_country_code", country)) ||
        !add_text(root, "service_type", key->service_type) ||
        !add_text(root, "service_protocol", key->service_protocol) ||
        !add_text(root, "public_key", public_key_b64) ||
        !add_text(root, "os_version", "ios") ||
        !add_text(root, "app_language", "en") ||
        !add_text(root, "cli_name", "Senko") ||
        !add_text(root, "app_version", AMZ_GATEWAY_APP_VERSION) ||
        !add_text(root, "distribution", "github") ||
        !add_text(root, "installation_uuid", installation_uuid))
        goto done;
    cJSON_AddItemToObject(root, "auth_data", auth);
    auth = NULL;
    if (!cJSON_PrintPreallocated(root, out, (int)(cap > 65536 ? 65536 : cap), 0)) goto done;
    *out_len = strlen(out);
    r = AMZ_OK;
done:
    cJSON_Delete(auth);
    cJSON_Delete(root);
    return r;
}

amz_status_t amz_premium_build_revoke(const amz_premium_key_t *key, const char *country,
                                      const char *installation_uuid,
                                      char *out, size_t cap, size_t *out_len) {
    if (!key || !key->api_key[0] || !installation_uuid || !installation_uuid[0] || !out || !cap ||
        !out_len)
        return AMZ_ERR_ARG;
    *out_len = 0;
    cJSON *root = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    amz_status_t r = AMZ_ERR_SPACE;
    if (!root || !auth || !add_text(auth, "api_key", key->api_key)) goto done;
    if (!add_text(root, "user_country_code", key->user_country_code) ||
        (country && country[0] && !add_text(root, "server_country_code", country)) ||
        !add_text(root, "service_type", key->service_type) ||
        !add_text(root, "os_version", "ios") ||
        !add_text(root, "cli_name", "Senko") ||
        !add_text(root, "app_version", AMZ_GATEWAY_APP_VERSION) ||
        !add_text(root, "installation_uuid", installation_uuid))
        goto done;
    cJSON_AddItemToObject(root, "auth_data", auth);
    auth = NULL;
    if (!cJSON_PrintPreallocated(root, out, (int)(cap > 65536 ? 65536 : cap), 0)) goto done;
    *out_len = strlen(out);
    r = AMZ_OK;
done:
    cJSON_Delete(auth);
    cJSON_Delete(root);
    return r;
}

static const char k_key_placeholder[] = "$WIREGUARD_CLIENT_PRIVATE_KEY";

/* a base64 wireguard key, so nothing the gateway sent can reach the config
   text through the key slot and the caller's value cannot break the line */
static int wg_key_text_ok(const char *k) {
    if (!k || strlen(k) != 44 || k[43] != '=') return 0;
    for (size_t i = 0; i < 43; ++i)
        if (!isalnum((unsigned char)k[i]) && k[i] != '+' && k[i] != '/') return 0;
    return 1;
}

amz_status_t amz_premium_parse_profile(const char *response, size_t len,
                                       const char *private_key_b64,
                                       char *conf, size_t conf_cap, size_t *conf_len,
                                       amz_premium_profile_t *profile,
                                       char *reason, size_t reason_cap) {
    if (!response || !conf || !conf_cap || !conf_len || !profile) return AMZ_ERR_ARG;
    *conf_len = 0;
    memset(profile, 0, sizeof *profile);
    if (!wg_key_text_ok(private_key_b64)) return AMZ_ERR_ARG;
    if (len == 0 || len > AMZ_BUNDLE_MAX_JSON) return AMZ_ERR_SPACE;
    cJSON *answer = cJSON_ParseWithLength(response, len);
    const cJSON *bundle = cJSON_IsObject(answer) ? cJSON_GetObjectItem(answer, "config") : NULL;
    if (!cJSON_IsString(bundle) || !bundle->valuestring[0]) {
        cJSON_Delete(answer);
        set_reason(reason, reason_cap, "the gateway answer carries no config");
        return AMZ_ERR_JSON;
    }
    cJSON *root = NULL;
    amz_status_t r = decode_bundle(bundle->valuestring, strlen(bundle->valuestring), &root,
                                   reason, reason_cap);
    cJSON_Delete(answer);
    if (r != AMZ_OK) return r;

    cJSON *owned = NULL;
    const cJSON *proto = pick_protocol(root, NULL);
    const char *text = proto ? config_text_of(proto, &owned) : NULL;
    if (!text) {
        set_reason(reason, reason_cap, proto ? "the premium container has no config text"
                                             : "the gateway sent no amneziawg container");
        r = proto ? AMZ_ERR_JSON : AMZ_ERR_UNSUPPORTED;
        goto done;
    }
    /* the placeholder is replaced here, not in the json: the key is base64
       and the config text is a plain string, so no escaping is involved */
    size_t pl = sizeof k_key_placeholder - 1;
    size_t kl = strlen(private_key_b64);
    size_t used = 0;
    int replaced = 0;
    for (const char *p = text; *p;) {
        const char *hit = strstr(p, k_key_placeholder);
        size_t chunk = hit ? (size_t)(hit - p) : strlen(p);
        if (used + chunk + kl + 2 > conf_cap) {
            memset(conf, 0, conf_cap);
            set_reason(reason, reason_cap, "amnezia config does not fit");
            r = AMZ_ERR_SPACE;
            goto done;
        }
        memcpy(conf + used, p, chunk);
        used += chunk;
        if (!hit) break;
        memcpy(conf + used, private_key_b64, kl);
        used += kl;
        ++replaced;
        p = hit + pl;
    }
    conf[used] = '\0';
    if (replaced == 0 || strstr(conf, "$WIREGUARD") != NULL) {
        memset(conf, 0, conf_cap);
        set_reason(reason, reason_cap, "the premium config has no usable private key slot");
        r = AMZ_ERR_JSON;
        goto done;
    }
    while (used && (conf[used - 1] == '\n' || conf[used - 1] == '\r' || conf[used - 1] == ' '))
        --used;
    if (used + 2 > conf_cap) {
        memset(conf, 0, conf_cap);
        set_reason(reason, reason_cap, "amnezia config does not fit");
        r = AMZ_ERR_SPACE;
        goto done;
    }
    conf[used++] = '\n';
    conf[used] = '\0';
    *conf_len = used;

    copy_json_field(root, "server_country_code", profile->country_code, sizeof profile->country_code);
    copy_json_field(root, "server_country_name", profile->country_name, sizeof profile->country_name);
    {
        const cJSON *api = cJSON_GetObjectItem(root, "api_config");
        const cJSON *pk = cJSON_IsObject(api) ? cJSON_GetObjectItem((cJSON *)api, "public_key") : NULL;
        if (cJSON_IsObject(pk))
            copy_json_field(pk, "expires_at", profile->expires_at, sizeof profile->expires_at);
    }
    r = countries_of(root, profile->countries, AMZ_PREMIUM_MAX_COUNTRIES, &profile->country_count,
                     reason, reason_cap);
    if (r != AMZ_OK) {
        memset(conf, 0, conf_cap);
        *conf_len = 0;
        goto done;
    }
    set_reason(reason, reason_cap, "ok");
done:
    if (owned) cJSON_Delete(owned);
    cJSON_Delete(root);
    return r;
}

amz_status_t amz_bundle_extract_conf(const char *in, size_t len,
                                     char *out, size_t cap, size_t *out_len,
                                     char *reason, size_t reason_cap) {
    if (!in || !out || !out_len || cap == 0) return AMZ_ERR_ARG;
    *out_len = 0;
    /* every later path either replaces this or returns AMZ_ERR_NOT_BUNDLE, so
       the caller never reads a reason nobody wrote */
    set_reason(reason, reason_cap, "invalid amnezia bundle");
    cJSON *root = NULL;
    amz_status_t decoded = decode_bundle(in, len, &root, reason, reason_cap);
    if (decoded != AMZ_OK) return decoded;

    const char *kind = NULL;
    const cJSON *proto = pick_protocol(root, &kind);
    if (!proto) {
        cJSON_Delete(root);
        set_reason(reason, reason_cap,
                   "amnezia bundle has no amneziawg or wireguard container");
        return AMZ_ERR_UNSUPPORTED;
    }

    cJSON *owned = NULL;
    const char *conf = config_text_of(proto, &owned);
    if (!conf) {
        if (owned) cJSON_Delete(owned);
        cJSON_Delete(root);
        set_reason(reason, reason_cap, "amnezia container has no config text");
        return AMZ_ERR_JSON;
    }

    amz_status_t r = emit(conf, out, cap, out_len, reason, reason_cap);
    if (owned) cJSON_Delete(owned);
    cJSON_Delete(root);
    if (r == AMZ_OK) set_reason(reason, reason_cap, "ok");
    return r;
}
