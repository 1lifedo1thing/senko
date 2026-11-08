#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3_OUT_LEN 32

/* chunk chaining state: 54 stack entries cover inputs up to 2^64 bytes */
typedef struct {
    uint32_t key[8];
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t  block[64];
    uint8_t  block_len;
    uint8_t  blocks_done;
    uint8_t  flags;
    uint32_t stack[54][8];
    uint8_t  stack_len;
} blake3_t;

/* the plain hash of in, 32 bytes */
void blake3_hash(const void *in, size_t len, uint8_t out[BLAKE3_OUT_LEN]);

/* derive_key mode: a context string (any bytes) and key material give one
   32 byte key. vless encryption feeds raw handshake bytes as the context */
void blake3_derive_key(const void *ctx, size_t ctx_len,
                       const void *material, size_t material_len,
                       uint8_t out[BLAKE3_OUT_LEN]);

void blake3_init(blake3_t *h);
void blake3_update(blake3_t *h, const void *in, size_t len);
void blake3_final(const blake3_t *h, uint8_t out[BLAKE3_OUT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* blake3_h */
