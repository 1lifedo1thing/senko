#ifndef VLENC_SERVER_H
#define VLENC_SERVER_H

#include <stddef.h>
#include <stdint.h>

/* test-only peer for vless encryption: the server half of the handshake and
   the record layer, written from the same wire description as the client but
   sharing no code with it besides blake3 and the primitives. sans-io, like
   the client */

#define VLS_MAX_KEYS 4

typedef struct {
    int      pq;             /* 1 ml-kem-768 key, 0 x25519 */
    uint8_t  sk[2400];
    size_t   sk_len;
    uint8_t  pk[1184];
    size_t   pk_len;
} vls_key_t;

typedef struct vls_ctx vls_ctx_t;
typedef struct vls vls_t;

/* ticket_seconds 0 refuses 0rtt */
vls_ctx_t *vls_ctx_new(const vls_key_t *keys, int nkeys, int xor_mode, int ticket_seconds);
void vls_ctx_free(vls_ctx_t *x);

/* forget every ticket the server issued, as a restart would */
void vls_ctx_forget_tickets(vls_ctx_t *x);

vls_t *vls_new(vls_ctx_t *x);
void vls_free(vls_t *s);

/* 0 fine, negative once the connection is dead; vls_why names the reason */
int vls_feed(vls_t *s, const uint8_t *in, size_t n);
const char *vls_why(const vls_t *s);

/* bytes the server wants on the wire */
size_t vls_wire_out(vls_t *s, uint8_t *buf, size_t cap);
/* application bytes the client sent */
size_t vls_plain_in(vls_t *s, uint8_t *buf, size_t cap);
/* queue application bytes for the client, valid once the handshake is done */
int vls_send(vls_t *s, const uint8_t *plain, size_t n);

int vls_handshake_done(const vls_t *s);
int vls_was_zero_rtt(const vls_t *s);

/* generate a key for the chain */
int vls_key_make(vls_key_t *k, int pq);

#endif /* vlenc_server_h */

/* the vision direct switch as the server sees it: from here the stream is the
   inner tls records, read and written without aead records. only the random
   profile masks the five byte header of each inner record */
void vls_raw_begin(vls_t *s);
/* masks n server bytes in place for the wire */
void vls_raw_encode(vls_t *s, uint8_t *buf, size_t n);

/* tests: set the aead nonce counters of an established connection (which 0 = what the server
   sends with, 1 = what it opens) to exercise the key rollover at the counter limit */
void vls_debug_set_nonce(vls_t *s, int which, const uint8_t nonce[12]);
