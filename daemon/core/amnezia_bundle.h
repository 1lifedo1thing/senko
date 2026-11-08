#ifndef AMNEZIA_BUNDLE_H
#define AMNEZIA_BUNDLE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the amnezia client shares a profile as vpn://<base64url(qCompress(json))>,
   as a .vpn file holding the same base64 body, or as the plain json. all three
   wrap the amneziawg .conf inside containers[].awg.last_config.config */
#define AMZ_BUNDLE_MAX_JSON (512 * 1024)

typedef enum {
    AMZ_OK = 0,
    AMZ_ERR_ARG = -1,
    /* the input is not an amnezia bundle, so the caller can keep sniffing */
    AMZ_ERR_NOT_BUNDLE = -2,
    AMZ_ERR_DECODE = -3,
    AMZ_ERR_JSON = -4,
    /* a real bundle carrying only containers senko cannot dial */
    AMZ_ERR_UNSUPPORTED = -5,
    AMZ_ERR_SPACE = -6
} amz_status_t;

typedef struct {
    char api_key[512];
    char service_type[64];
    char service_protocol[32];
    char user_country_code[16];
} amz_premium_key_t;

/* the reason of a premium key that names a subscription but cannot be used. a
   bundle without auth_data is no premium key at all and returns
   AMZ_ERR_NOT_BUNDLE, so a caller can offer it to the ready bundle decoder */
#define AMZ_PREMIUM_INVALID_REASON "invalid premium subscription key"

amz_status_t amz_premium_parse_key(const char *in, size_t len,
                                   amz_premium_key_t *key,
                                   char *reason, size_t reason_cap);

typedef struct {
    char code[64];
    char name[128];
    char flag_code[16]; /* the code of the flag to draw: us-east shows the us flag */
    /* the country serves amneziawg. the gateway lists vless-only countries
       too, and senko cannot dial those */
    int  awg;
} amz_premium_country_t;

amz_status_t amz_premium_parse_countries(const char *json, size_t len,
                                         amz_premium_country_t *countries, size_t cap,
                                         size_t *count, char *reason, size_t reason_cap);

#define AMZ_PREMIUM_MAX_COUNTRIES 96

/* what a gateway answer carries besides the tunnel config */
typedef struct {
    char country_code[64];
    char country_name[128];
    char expires_at[48];
    amz_premium_country_t countries[AMZ_PREMIUM_MAX_COUNTRIES];
    size_t country_count;
} amz_premium_profile_t;

/* the plain json document the gateway wants for v1/config. country may be
   empty (the gateway picks one); public_key is the base64 wireguard public key */
amz_status_t amz_premium_build_request(const amz_premium_key_t *key, const char *country,
                                       const char *public_key_b64, const char *installation_uuid,
                                       char *out, size_t cap, size_t *out_len);

/* the document that releases this install's device slot (v1/revoke_config) */
amz_status_t amz_premium_build_revoke(const amz_premium_key_t *key, const char *country,
                                      const char *installation_uuid,
                                      char *out, size_t cap, size_t *out_len);

/* the decrypted gateway answer to that request: config is a vpn:// bundle whose
   private key is still the $WIREGUARD_CLIENT_PRIVATE_KEY placeholder. conf gets
   the amneziawg text with private_key_b64 in its place */
amz_status_t amz_premium_parse_profile(const char *response, size_t len,
                                       const char *private_key_b64,
                                       char *conf, size_t conf_cap, size_t *conf_len,
                                       amz_premium_profile_t *profile,
                                       char *reason, size_t reason_cap);

/* cheap classification for an import sniffer: no allocation, no decoding */
int amz_bundle_looks_like(const char *text, size_t len);

/* write the embedded amneziawg config text, newline terminated */
amz_status_t amz_bundle_extract_conf(const char *in, size_t len,
                                     char *out, size_t cap, size_t *out_len,
                                     char *reason, size_t reason_cap);

#ifdef __cplusplus
}
#endif

#endif
