#ifndef SENKO_AWG_LINK_H
#define SENKO_AWG_LINK_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "core/awg_tunnel.h"
#include "core/utun_frame.h"
#include "utun_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/* moves packets between the utun device and the amneziawg server once the
   first handshake is done, and renews the keys without stopping traffic. it
   touches no routes and no system state, so a host test can drive it with two
   socketpairs */

/* wireguard's timers: new keys after two minutes, a retry every five seconds
   while the server has not answered, and no traffic on keys older than three */
#define AWG_LINK_REKEY_AFTER_MS  120000
#define AWG_LINK_REKEY_RETRY_MS    5000
#define AWG_LINK_REJECT_AFTER_MS 180000

typedef enum {
    AWG_LINK_STOPPED     =  0, /* the owner asked through wake_fd */
    AWG_LINK_ERR_DEVICE  = -1, /* the utun descriptor failed */
    AWG_LINK_ERR_UDP     = -2, /* the server socket failed */
    AWG_LINK_ERR_EXPIRED = -3  /* the server stopped answering handshakes */
} awg_link_status_t;

typedef struct {
    const awg_config_t *cfg;
    utun_device_t *device;
    int udp_fd;  /* nonblocking, connected to the server */
    int wake_fd; /* readable when the owner wants the link to stop */
    pthread_mutex_t *stats_lock; /* guards bytes_up and bytes_down, may be NULL */

    awg_tunnel_t current;
    /* the keys before the last renewal: the server keeps sending with them
       for a moment after it answered */
    awg_tunnel_t previous;
    int have_previous;
    awg_handshake_t pending;
    int rekey_pending;
    int64_t rekey_sent_ms;
    int64_t handshake_ms; /* when the current keys were accepted */
    int64_t last_tx_ms;

    uint64_t bytes_up;
    uint64_t bytes_down;
    uint32_t renewals; /* one word, so another thread can read it whole */
    uint32_t dropped;  /* packets refused by the kernel, the peer or the crypto */

    uint8_t frame[UTUN_FRAME_MAX];
    uint8_t wire[AWG_DATAGRAM_MAX];
} awg_link_t;

/* established carries the keys of a handshake the server accepted at now_ms */
void awg_link_init(awg_link_t *link, const awg_config_t *cfg, utun_device_t *device,
                   int udp_fd, int wake_fd, const awg_handshake_t *established,
                   int64_t now_ms);

/* runs until wake_fd is readable or the link fails; reason says why it ended */
awg_link_status_t awg_link_run(awg_link_t *link, char *reason, size_t reason_cap);

/* wipes every key the link holds */
void awg_link_clear(awg_link_t *link);

#ifdef __cplusplus
}
#endif

#endif
