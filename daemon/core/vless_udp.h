#ifndef SENKO_VLESS_UDP_H
#define SENKO_VLESS_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "vless.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VLESS_UDP_PAYLOAD_MAX 1500
#define VLESS_UDP_FRAME_MAX 1600

typedef enum {
    VLESS_UDP_LENGTH = 0,
    VLESS_UDP_XUDP
} vless_udp_mode_t;

typedef enum {
    VLESS_UDP_OK = 0,
    VLESS_UDP_NEED_MORE = 1,
    VLESS_UDP_SKIPPED = 2,
    VLESS_UDP_END = 3, /* xudp: the server closed the association */
    VLESS_UDP_ERR_ARG = -1,
    VLESS_UDP_ERR_SPACE = -2,
    VLESS_UDP_ERR_FRAME = -3
} vless_udp_status_t;

typedef struct {
    vless_udp_mode_t mode;
    vless_dest_t target;
    int sent_first;
    uint8_t pending[VLESS_UDP_FRAME_MAX];
    size_t pending_len;
} vless_udp_t;

vless_udp_status_t vless_udp_init(vless_udp_t *codec, vless_udp_mode_t mode,
                                  const vless_dest_t *target);

/* the caller sends the whole returned frame before encoding the next one */
vless_udp_status_t vless_udp_encode(vless_udp_t *codec,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t cap, size_t *out_len);

/* one complete datagram or a control frame at most. call again with the unconsumed input.
   the returned payload lives in codec until the next feed call */
vless_udp_status_t vless_udp_feed(vless_udp_t *codec, const uint8_t *input,
                                  size_t input_len, size_t *consumed,
                                  const uint8_t **payload, size_t *payload_len,
                                  vless_dest_t *source);

#ifdef __cplusplus
}
#endif

#endif
