#ifndef PREMIUM_H
#define PREMIUM_H

#include <stddef.h>

#include "core/amnezia_gateway.h"

#ifdef __cplusplus
extern "C" {
#endif

/* one sealed round trip for a request document; the daemon supplies the dialer
   and the retry order, the tests supply a stand-in gateway */
typedef amz_gw_status_t (*premium_request_fn)(void *ctx, const char *path,
                                               const char *payload, size_t payload_len,
                                               char *answer, size_t answer_cap, size_t *answer_len,
                                               int *api_status, char *reason, size_t reason_cap);

typedef struct {
    const char *state_path; /* root only json: key, install id, country list */
    const char *conf_path;  /* the amneziawg profile the tunnel dials */
    premium_request_fn request;
    void *request_ctx;
} premium_env_t;

/* ops: KEY <vpn://...>, COUNTRY <code>, REFRESH, STATE, FORGET.
   out gets protocol lines, newline terminated:
     PREMIUM STATE <country> <expires epoch, 0 unknown>
     PREMIUM COUNTRY <code> <flag> <name>   (only countries that serve amneziawg;
                                              flag is the code of the flag to draw, - for none)
     OK <text> or ERR <text>
   returns 0 when the last line is OK. a failed op leaves the saved profile and
   state as they were. FORGET always drops the key, and first asks the gateway
   to release this install's device slot: the answer says whether it did */
int premium_run(const premium_env_t *env, const char *op, const char *arg,
                char *out, size_t cap);

/* seconds since the epoch of a gateway timestamp such as
   "2026-11-06 13:51:03.573146+00:00", 0 when it cannot be read */
long premium_parse_expiry(const char *text);

#ifdef __cplusplus
}
#endif

#endif
