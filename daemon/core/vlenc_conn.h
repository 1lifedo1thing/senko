#ifndef VLENC_CONN_H
#define VLENC_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "vlenc_conf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* client side of vless encryption (mlkem768x25519plus), no sockets inside.
   the caller moves bytes: it sends what vlc_hello and vlc_seal produce,
   reads from the socket into vlc_rx_space, and pulls plaintext with vlc_pull */

typedef enum {
    VLC_OK = 0,
    VLC_NEED_MORE,      /* feed more input before pulling again */
    VLC_DATA,           /* vlc_pull produced plaintext */
    VLC_ERR_ARG,
    VLC_ERR_STATE,      /* the call is not allowed in this phase */
    VLC_ERR_SYSTEM,     /* a primitive or an allocation failed */
    VLC_ERR_AUTH,       /* a protected message failed its tag */
    VLC_ERR_PROTO,      /* bad header, bad length, reserved value */
    VLC_ERR_KEY,        /* a peer value no key agreement can use */
    VLC_ERR_TICKET      /* the server dropped a 0rtt ticket, reconnect for a full handshake */
} vlc_status_t;

#define VLC_PLAIN_MAX     8192      /* plaintext bytes per record we send */
#define VLC_REC_MAX       16640     /* ciphertext bytes per record we accept */
#define VLC_SEAL_EXTRA    (5 + 16)  /* record header and tag */

typedef struct {
    /* 0 on success; null means the system generator */
    int (*rand)(void *ctx, uint8_t *buf, size_t len);
    void *rand_ctx;
    /* monotonic seconds for ticket lifetime; null means the system clock */
    int64_t (*now)(void *ctx);
    void *now_ctx;
    /* 1 aes-256-gcm, 0 chacha20-poly1305, -1 pick by cpu: the server tries both */
    int use_aes;
} vlc_env_t;

typedef struct vlc_conn vlc_conn_t;

/* cfg is copied, so it need not outlive the call. scope names the server
   a ticket belongs to: host, port and profile text, so a ticket never meets
   other keys or another inbound */
vlc_conn_t *vlc_new(const vlenc_cfg_t *cfg, const char *scope, const vlc_env_t *env);

/* zeroes every secret */
void vlc_free(vlc_conn_t *c);

/* the bytes to send first, in the order and fragments the profile asks for.
   0rtt with a live ticket sends nothing here: its preamble leaves with the
   first vlc_seal. segs holds the fragment sizes, they sum to *len. the
   buffer stays valid until the server's reply has been read (or vlc_free) */
vlc_status_t vlc_hello(vlc_conn_t *c, const uint8_t **buf, size_t *len,
                       const size_t **segs, size_t *nsegs);

/* a window to read socket bytes into, then how many landed */
vlc_status_t vlc_rx_space(vlc_conn_t *c, uint8_t **p, size_t *cap);
vlc_status_t vlc_rx_commit(vlc_conn_t *c, size_t n);

/* VLC_DATA with up to VLC_REC_MAX bytes in out, VLC_NEED_MORE, or an error
   that ends the connection. out must hold VLC_REC_MAX bytes */
vlc_status_t vlc_pull(vlc_conn_t *c, uint8_t *out, size_t cap, size_t *out_len);

/* 1 once application bytes may be sealed */
int vlc_can_seal(const vlc_conn_t *c);

/* one record of at most VLC_PLAIN_MAX bytes. out needs len + VLC_SEAL_EXTRA
   plus, on the first call of a 0rtt connection, VLC_PREAMBLE_MAX */
#define VLC_PREAMBLE_MAX  (16 + VLENC_MAX_KEYS * (1088 + 32) + 18 + 32)
vlc_status_t vlc_seal(vlc_conn_t *c, const uint8_t *in, size_t len,
                      uint8_t *out, size_t cap, size_t *out_len);

/* 1 once the server's side of the handshake has been read and checked */
int vlc_established(const vlc_conn_t *c);

/* 1 when no part of a record or of the handshake reply sits in the buffer, so
   an end of stream here is a clean one */
int vlc_at_boundary(const vlc_conn_t *c);

/* 1 when the peer ticket made this a 0rtt connection */
int vlc_is_zero_rtt(const vlc_conn_t *c);

/* the vision direct switch. from the direct command on, both sides write the
   inner tls records themselves and the aead records are gone, as xray does:
   the connection below carries the stream as is. only the "random" profile
   keeps masking, it covers the five byte header of each inner record.
   vlc_take_raw stops the record parser and returns the bytes already buffered,
   unmasked; vlc_raw_decode unmasks what is read afterwards, vlc_raw_encode
   masks what is written. both work in place and are a no-op without masking */
size_t vlc_take_raw(vlc_conn_t *c, uint8_t *out, size_t cap);
void vlc_raw_decode(vlc_conn_t *c, uint8_t *buf, size_t len);
void vlc_raw_encode(vlc_conn_t *c, uint8_t *buf, size_t len);

/* tests: forget every cached ticket */
void vlc_tickets_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* vlenc_conn_h */
