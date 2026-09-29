#ifndef SENKO_TUN_OPENER_H
#define SENKO_TUN_OPENER_H

#include <stddef.h>
#include <stdint.h>

#include "core/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* a fixed pool of threads that open server connections for captured flows.
   connecting and some transport opens block, so they run here and never on
   the thread that owns the tunnel.

   a job is identified by the tag the owner gave it, usually a flow id. a
   finished job waits until the owner takes it on its own thread; the notify
   callback only says that something finished, so a wakeup that could not be
   delivered loses nothing. a result whose flow has gone is closed by the owner,
   and whatever nobody took is closed when the pool stops */

#define TUN_OPENER_THREADS_MAX 16
#define TUN_OPENER_JOBS_MAX 64
#define TUN_OPENER_MESSAGE_MAX 192

/* connect to the server and return the descriptor, blocking allowed but
   bounded by the dialer's own deadline. -1 with a sentence in error */
typedef int (*tun_opener_dial_fn)(void *ctx, char *error, size_t error_cap);
/* called on a worker thread when a job finished */
typedef void (*tun_opener_notify_fn)(void *ctx);

typedef struct {
    const transport_vt_t *vt;
    /* borrowed: the strings must outlive the pool */
    transport_tls_cfg_t   tls;
    tun_opener_dial_fn    dial;
    void                 *dial_ctx;
    tun_opener_notify_fn  notify;
    void                 *notify_ctx;
    size_t                threads; /* at most TUN_OPENER_THREADS_MAX */
} tun_opener_config_t;

typedef struct {
    uint64_t tag;
    int      ok;
    int      fd;       /* -1 unless ok */
    void    *th;       /* the transport handle, NULL unless ok */
    char     message[TUN_OPENER_MESSAGE_MAX]; /* why it failed, in plain words */
} tun_opener_result_t;

typedef enum {
    TUN_OPENER_OK         =  0,
    TUN_OPENER_ERR_ARG    = -1,
    TUN_OPENER_ERR_FULL   = -2, /* every job slot is taken */
    TUN_OPENER_ERR_SYSTEM = -3, /* a thread or lock could not be created */
    TUN_OPENER_ERR_STOPPED = -4
} tun_opener_status_t;

typedef struct tun_opener tun_opener_t;

size_t tun_opener_size(void);

tun_opener_status_t tun_opener_start(tun_opener_t *opener, const tun_opener_config_t *config);

tun_opener_status_t tun_opener_submit(tun_opener_t *opener, uint64_t tag);

/* one finished job, oldest first. returns 1 when a result was taken; the
   caller then owns its descriptor and handle */
int tun_opener_take(tun_opener_t *opener, tun_opener_result_t *out);

/* the flow went away. a job that has not started is dropped; one that is
   running finishes and comes back through take() for the owner to close */
void tun_opener_cancel(tun_opener_t *opener, uint64_t tag);

/* refuse new jobs, let the running ones end, join every thread and close
   every result nobody took. safe to call twice */
void tun_opener_stop(tun_opener_t *opener);

/* close a taken result that is no longer wanted */
void tun_opener_discard(const tun_opener_t *opener, tun_opener_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
