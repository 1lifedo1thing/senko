#ifndef AMNEZIA_GATEWAY_H
#define AMNEZIA_GATEWAY_H

#include <stddef.h>
#include <stdint.h>

#include "subfetch.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the amnezia premium gateway takes json sealed the way libagw and the official
   client seal it: a random aes-256 key and iv, the body in aes-cbc, the key
   material in rsa pkcs#1 v1.5 under the gateway key. the answer comes back in
   the same aes key. the transport is plain http, so the seal is all there is */
#define AMZ_GW_BASE_URL "http://gw.amnezia.org:80/"
#define AMZ_GW_PATH_CONFIG "v1/config"
#define AMZ_GW_PATH_REVOKE "v1/revoke_config"
#define AMZ_GW_MAX_PAYLOAD (16 * 1024)
#define AMZ_GW_MAX_ANSWER (256 * 1024)

typedef enum {
    AMZ_GW_OK = 0,
    AMZ_GW_ERR_ARG = -1,
    AMZ_GW_ERR_CRYPTO = -2,   /* local rsa or aes failure */
    AMZ_GW_ERR_SPACE = -3,
    AMZ_GW_ERR_NETWORK = -4,  /* dial, transfer or http framing failed */
    AMZ_GW_ERR_TIMEOUT = -5,
    AMZ_GW_ERR_DECRYPT = -6,  /* the answer is not sealed to our key */
    AMZ_GW_ERR_API = -7       /* the gateway answered with an error status */
} amz_gw_status_t;

typedef struct {
    uint8_t key[32];
    uint8_t iv[32]; /* the wire carries 32 bytes, cbc uses the first 16 */
} amz_gw_session_t;

/* seals payload to the gateway key in pem into the request body, and fills
   session with the secrets that open the answer */
amz_gw_status_t amz_gw_seal(const char *pem, const char *payload, size_t payload_len,
                            amz_gw_session_t *session, char *body, size_t body_cap,
                            size_t *body_len);

/* opens an answer body. out is nul terminated */
amz_gw_status_t amz_gw_open(const amz_gw_session_t *session, const uint8_t *in, size_t in_len,
                            char *out, size_t out_cap, size_t *out_len);

/* the api error inside an opened answer: 0 when the answer is no error, else
   the status the gateway put in http_status. reason gets the user's words */
int amz_gw_api_error(const char *answer, size_t len, char *reason, size_t reason_cap);

/* one sealed round trip over cfg's dialer. url and pem are parameters so the
   tests can aim at a local stand-in; production passes AMZ_GW_BASE_URL plus a
   path, and NULL for the built in gateway key. on AMZ_GW_ERR_API the reason is
   the api's own and *api_status (when given) is the status it sent, else 0 */
amz_gw_status_t amz_gw_request(const subfetch_cfg_t *cfg, const char *url, const char *pem,
                               const char *payload, size_t payload_len,
                               char *answer, size_t answer_cap, size_t *answer_len,
                               int timeout_ms, int *api_status, char *reason, size_t reason_cap);

#ifdef __cplusplus
}
#endif

#endif
