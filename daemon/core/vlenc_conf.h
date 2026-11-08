#ifndef VLENC_CONF_H
#define VLENC_CONF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* vless encryption parameter string, as the xray server's vlessenc command
   prints it and as the "encryption" field of a vless user carries it:

     mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>...].<key>[.<key>...]

   padding elements are "prob-min-max" integer triples, a length, a gap, a
   length and so on. a key is unpadded base64url of a 32 byte x25519 public
   key (the server "password") or a 1184 byte ml-kem-768 encapsulation key.
   the keys form a relay chain, the server holds the matching private keys in
   the same order */

#define VLENC_VERSION_NAME   "mlkem768x25519plus"
#define VLENC_MAX_KEYS       4
#define VLENC_MAX_PAD        9      /* lengths and gaps together */
#define VLENC_TEXT_MAX       4096   /* the whole string, with its nul */
#define VLENC_X25519_LEN     32
#define VLENC_MLKEM_EK_LEN   1184
#define VLENC_BLOB_MAX       3072   /* raw key bytes of every key together */
#define VLENC_PAD_TOTAL_MAX  (18 + 65535)

typedef enum {
    VLENC_OK = 0,
    VLENC_ERR_ARG,
    VLENC_ERR_TOO_LONG,
    VLENC_ERR_FORMAT,       /* fewer fields than the grammar needs */
    VLENC_ERR_VERSION,
    VLENC_ERR_MODE,
    VLENC_ERR_RTT,
    VLENC_ERR_PADDING,
    VLENC_ERR_KEY_ENCODING, /* not unpadded base64url */
    VLENC_ERR_KEY_LENGTH,   /* neither 32 nor 1184 bytes */
    VLENC_ERR_KEY_VALUE,    /* an ml-kem key that fails the fips 203 check */
    VLENC_ERR_KEY_COUNT,
    VLENC_ERR_POOL_FULL
} vlenc_status_t;

typedef enum {
    VLENC_XOR_NATIVE = 0,   /* records look like tls application data */
    VLENC_XOR_PUB    = 1,   /* the handshake public values are masked */
    VLENC_XOR_RANDOM = 2    /* masked handshake and masked record headers */
} vlenc_xor_t;

typedef struct {
    uint16_t prob;          /* percent, above 100 behaves as 100 */
    uint16_t min;
    uint16_t max;
} vlenc_pad_t;

typedef struct {
    uint8_t  xor_mode;
    uint8_t  zero_rtt;      /* 0rtt: reuse a server ticket when one is live */
    uint8_t  n_lens;
    uint8_t  n_gaps;
    vlenc_pad_t lens[(VLENC_MAX_PAD + 1) / 2];
    vlenc_pad_t gaps[VLENC_MAX_PAD / 2 + 1];
    uint8_t  n_keys;
    uint16_t key_len[VLENC_MAX_KEYS];
    uint16_t key_off[VLENC_MAX_KEYS];
    uint8_t  blob[VLENC_BLOB_MAX];
} vlenc_cfg_t;

/* a short wording for cfg_reason and logs, never the string itself: the keys
   are secrets */
const char *vlenc_reason(vlenc_status_t st);

/* parse and check one string into out. nothing is partly accepted: any
   problem leaves out zeroed and names the first field at fault */
vlenc_status_t vlenc_parse(const char *text, vlenc_cfg_t *out);

/* 1 when the value asks for the protocol layer: not empty, not "none" */
int vlenc_is_set(const char *text);

/* the fips 203 modulus check on an encapsulation key, 1 when it passes */
int vlenc_mlkem_ek_valid(const uint8_t ek[VLENC_MLKEM_EK_LEN]);

/* profiles are interned by text. a server record holds the small id, so
   copies of vl_server_t stay cheap. a connection copies the profile it dials
   with, so freeing a slot never touches a running session. ids start at 1, 0
   means no encryption. the pool holds as many profiles as the store holds
   servers, so one full import always fits */
#define VLENC_POOL_MAX 1024

vlenc_status_t vlenc_intern(const char *text, uint16_t *id_out);

/* null for 0 and for ids nothing interned or since released. a pointer stays
   valid until the next vlenc_pool_retain, so copy what must outlive it */
const char *vlenc_text(uint16_t id);
const vlenc_cfg_t *vlenc_cfg(uint16_t id);

/* free every profile whose id is not listed. ids of the kept ones do not
   change. the caller lists the ids of every server record it still holds, and
   calls this only when no import is half done, since a fresh id that is not
   stored yet would be freed */
void vlenc_pool_retain(const uint16_t *ids, size_t n);

/* tests only: forget every profile */
void vlenc_pool_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* vlenc_conf_h */
