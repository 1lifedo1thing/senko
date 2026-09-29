#include "tun_opener.h"

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum {
    JOB_FREE = 0,
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_DONE
} job_state_t;

typedef struct {
    job_state_t         state;
    uint64_t            order; /* first in, first out */
    tun_opener_result_t result;
} job_t;

struct tun_opener {
    tun_opener_config_t config;
    pthread_mutex_t     lock;
    pthread_cond_t      wake;
    pthread_t           threads[TUN_OPENER_THREADS_MAX];
    size_t              running_threads;
    int                 lock_ready;
    int                 stopping;
    int                 stopped;
    uint64_t            next_order;
    job_t               jobs[TUN_OPENER_JOBS_MAX];
};

size_t tun_opener_size(void) {
    return sizeof(struct tun_opener);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static job_t *oldest(tun_opener_t *opener, job_state_t state) {
    job_t *found = NULL;
    for (size_t i = 0; i < TUN_OPENER_JOBS_MAX; ++i) {
        job_t *job = &opener->jobs[i];
        if (job->state != state) continue;
        if (!found || job->order < found->order) found = job;
    }
    return found;
}

static void open_one(tun_opener_t *opener, tun_opener_result_t *result) {
    char reason[TUN_OPENER_MESSAGE_MAX] = "";
    int fd = opener->config.dial(opener->config.dial_ctx, reason, sizeof reason);
    if (fd < 0) {
        snprintf(result->message, sizeof result->message, "%s",
                 reason[0] ? reason : "the server could not be reached");
        return;
    }
    int socket_error = 0;
    socklen_t socket_error_len = sizeof socket_error;
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof peer;
    int saved = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_len) != 0)
        saved = errno;
    else if (socket_error_len != sizeof socket_error)
        saved = EPROTO;
    else if (socket_error != 0)
        saved = socket_error;
    else if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0)
        saved = errno;
    if (saved != 0) {
        close(fd);
        snprintf(result->message, sizeof result->message,
                 "the server socket is not connected (errno %d)", saved);
        return;
    }
    if (set_nonblocking(fd) != 0) {
        int saved = errno;
        close(fd);
        snprintf(result->message, sizeof result->message,
                 "cannot make the server socket nonblocking (errno %d)", saved);
        return;
    }
    void *th = opener->config.vt->open(fd, &opener->config.tls);
    if (!th) {
        close(fd);
        snprintf(result->message, sizeof result->message,
                 "the connection to the server opened but its transport did not start");
        return;
    }
    result->ok = 1;
    result->fd = fd;
    result->th = th;
}

static void *worker_main(void *arg) {
    tun_opener_t *opener = arg;
    for (;;) {
        pthread_mutex_lock(&opener->lock);
        job_t *job = NULL;
        while (!opener->stopping && !(job = oldest(opener, JOB_QUEUED)))
            pthread_cond_wait(&opener->wake, &opener->lock);
        if (opener->stopping) {
            pthread_mutex_unlock(&opener->lock);
            return NULL;
        }
        job->state = JOB_RUNNING;
        tun_opener_result_t result;
        memset(&result, 0, sizeof result);
        result.tag = job->result.tag;
        result.fd = -1;
        pthread_mutex_unlock(&opener->lock);

        open_one(opener, &result);

        pthread_mutex_lock(&opener->lock);
        job->result = result;
        job->state = JOB_DONE;
        pthread_mutex_unlock(&opener->lock);

        if (opener->config.notify) opener->config.notify(opener->config.notify_ctx);
    }
}

tun_opener_status_t tun_opener_start(tun_opener_t *opener, const tun_opener_config_t *config) {
    if (!opener || !config || !config->vt || !config->vt->open || !config->dial)
        return TUN_OPENER_ERR_ARG;
    if (config->threads == 0 || config->threads > TUN_OPENER_THREADS_MAX)
        return TUN_OPENER_ERR_ARG;
    memset(opener, 0, sizeof *opener);
    opener->config = *config;
    if (pthread_mutex_init(&opener->lock, NULL) != 0) return TUN_OPENER_ERR_SYSTEM;
    if (pthread_cond_init(&opener->wake, NULL) != 0) {
        pthread_mutex_destroy(&opener->lock);
        return TUN_OPENER_ERR_SYSTEM;
    }
    opener->lock_ready = 1;
    for (size_t i = 0; i < config->threads; ++i) {
        if (pthread_create(&opener->threads[i], NULL, worker_main, opener) != 0) {
            tun_opener_stop(opener);
            return TUN_OPENER_ERR_SYSTEM;
        }
        ++opener->running_threads;
    }
    return TUN_OPENER_OK;
}

tun_opener_status_t tun_opener_submit(tun_opener_t *opener, uint64_t tag) {
    if (!opener || !opener->lock_ready) return TUN_OPENER_ERR_ARG;
    pthread_mutex_lock(&opener->lock);
    tun_opener_status_t status = TUN_OPENER_ERR_FULL;
    if (opener->stopping) {
        status = TUN_OPENER_ERR_STOPPED;
    } else {
        for (size_t i = 0; i < TUN_OPENER_JOBS_MAX; ++i) {
            job_t *job = &opener->jobs[i];
            if (job->state != JOB_FREE) continue;
            memset(job, 0, sizeof *job);
            job->state = JOB_QUEUED;
            job->order = opener->next_order++;
            job->result.tag = tag;
            job->result.fd = -1;
            pthread_cond_signal(&opener->wake);
            status = TUN_OPENER_OK;
            break;
        }
    }
    pthread_mutex_unlock(&opener->lock);
    return status;
}

int tun_opener_take(tun_opener_t *opener, tun_opener_result_t *out) {
    if (!opener || !out || !opener->lock_ready) return 0;
    pthread_mutex_lock(&opener->lock);
    job_t *job = oldest(opener, JOB_DONE);
    if (job) {
        *out = job->result;
        memset(job, 0, sizeof *job);
    }
    pthread_mutex_unlock(&opener->lock);
    return job != NULL;
}

void tun_opener_cancel(tun_opener_t *opener, uint64_t tag) {
    if (!opener || !opener->lock_ready) return;
    pthread_mutex_lock(&opener->lock);
    for (size_t i = 0; i < TUN_OPENER_JOBS_MAX; ++i) {
        job_t *job = &opener->jobs[i];
        if (job->state == JOB_QUEUED && job->result.tag == tag) memset(job, 0, sizeof *job);
    }
    pthread_mutex_unlock(&opener->lock);
}

void tun_opener_discard(const tun_opener_t *opener, tun_opener_result_t *result) {
    if (!opener || !result) return;
    if (result->th) opener->config.vt->close(result->th);
    if (result->fd >= 0) close(result->fd);
    result->th = NULL;
    result->fd = -1;
    result->ok = 0;
}

void tun_opener_stop(tun_opener_t *opener) {
    if (!opener || !opener->lock_ready || opener->stopped) return;
    pthread_mutex_lock(&opener->lock);
    opener->stopping = 1;
    pthread_cond_broadcast(&opener->wake);
    pthread_mutex_unlock(&opener->lock);

    /* a thread in the middle of a connect finishes it; the dialer's deadline
       bounds how long that takes */
    for (size_t i = 0; i < opener->running_threads; ++i)
        pthread_join(opener->threads[i], NULL);
    opener->running_threads = 0;

    for (size_t i = 0; i < TUN_OPENER_JOBS_MAX; ++i) {
        job_t *job = &opener->jobs[i];
        if (job->state == JOB_DONE) tun_opener_discard(opener, &job->result);
        memset(job, 0, sizeof *job);
    }
    pthread_cond_destroy(&opener->wake);
    pthread_mutex_destroy(&opener->lock);
    opener->lock_ready = 0;
    opener->stopped = 1;
}
