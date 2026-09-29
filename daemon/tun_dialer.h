#ifndef SENKO_TUN_DIALER_H
#define SENKO_TUN_DIALER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "core/endpoint_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUN_DIALER_DEFAULT_TIMEOUT_MS 8000
#define TUN_DIALER_MAX_TIMEOUT_MS 30000

/* resolved addresses must already have endpoint pins before init */
typedef struct {
    pthread_mutex_t lock;
    endpoint_pool_t pool;
    uint16_t port;
    int timeout_ms;
    int ready;
    int cancelled;
} tun_dialer_t;

int tun_dialer_init(tun_dialer_t *dialer,
                    const uint8_t addresses[][16], const uint8_t *address_lens,
                    size_t count, uint16_t port, int timeout_ms);

/* matches tun_opener_dial_fn; returns only a verified connected socket */
int tun_dialer_connect(void *ctx, char *error, size_t error_cap);

/* prevents new connects and ends pending polls within one short poll interval */
void tun_dialer_cancel(tun_dialer_t *dialer);
/* join the opener workers before destroying their borrowed dialer */
void tun_dialer_destroy(tun_dialer_t *dialer);

#ifdef __cplusplus
}
#endif

#endif
