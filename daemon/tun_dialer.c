#define _DEFAULT_SOURCE

#include "tun_dialer.h"
#include "core/senko_time.h"
#include "route_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int cancelled(tun_dialer_t *dialer) {
    pthread_mutex_lock(&dialer->lock);
    int value = dialer->cancelled;
    pthread_mutex_unlock(&dialer->lock);
    return value;
}

int tun_dialer_init(tun_dialer_t *dialer,
                    const uint8_t addresses[][16], const uint8_t *address_lens,
                    size_t count, uint16_t port, int timeout_ms) {
    if (!dialer || !addresses || !address_lens || count == 0 ||
        count > ENDPOINT_POOL_MAX || port == 0 || timeout_ms < 0 ||
        timeout_ms > TUN_DIALER_MAX_TIMEOUT_MS)
        return -1;
    memset(dialer, 0, sizeof *dialer);
    endpoint_pool_init(&dialer->pool);
    if (endpoint_pool_set_resolved(&dialer->pool, addresses, address_lens,
                                   count, (uint64_t)senko_now_ms(), 60) != ENDPOINT_POOL_OK)
        return -1;
    if (pthread_mutex_init(&dialer->lock, NULL) != 0) return -1;
    dialer->port = port;
    dialer->timeout_ms = timeout_ms ? timeout_ms : TUN_DIALER_DEFAULT_TIMEOUT_MS;
    dialer->ready = 1;
    return 0;
}

static int pick(const endpoint_pool_t *pool, const int *used, uint64_t now_ms) {
    size_t good = pool->last_good;
    if (good < pool->count && !used[good] &&
        pool->entries[good].cooldown_until_ms <= now_ms)
        return (int)good;
    for (size_t i = 0; i < pool->count; ++i)
        if (!used[i] && pool->entries[i].cooldown_until_ms <= now_ms)
            return (int)i;
    size_t earliest = SIZE_MAX;
    for (size_t i = 0; i < pool->count; ++i)
        if (!used[i] && (earliest == SIZE_MAX ||
            pool->entries[i].cooldown_until_ms < pool->entries[earliest].cooldown_until_ms))
            earliest = i;
    return earliest == SIZE_MAX ? -1 : (int)earliest;
}

static int connect_one(tun_dialer_t *dialer, const endpoint_t *endpoint,
                       int64_t deadline_ms, int *out_error) {
    struct sockaddr_storage storage;
    socklen_t address_len;
    memset(&storage, 0, sizeof storage);
    if (endpoint->address_len == 4) {
        struct sockaddr_in *address = (struct sockaddr_in *)&storage;
        address->sin_family = AF_INET;
        address->sin_port = htons(dialer->port);
        memcpy(&address->sin_addr, endpoint->address, 4);
        address_len = sizeof *address;
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(dialer->port);
        memcpy(&address->sin6_addr, endpoint->address, 16);
        address_len = sizeof *address;
    }

    int fd = socket(storage.ss_family, SOCK_STREAM, 0);
    if (fd < 0) { *out_error = errno; return -1; }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        *out_error = errno;
        close(fd);
        return -1;
    }
    int status = connect(fd, (struct sockaddr *)&storage, address_len);
    if (status < 0 && errno != EINPROGRESS) {
        *out_error = errno;
        close(fd);
        return -1;
    }
    while (status < 0) {
        if (cancelled(dialer)) { *out_error = ECANCELED; close(fd); return -1; }
        int64_t remain = deadline_ms - senko_now_ms();
        if (remain <= 0) { *out_error = ETIMEDOUT; close(fd); return -1; }
        struct pollfd item = { fd, POLLOUT, 0 };
        int wait_ms = remain > 100 ? 100 : (int)remain;
        int polled = poll(&item, 1, wait_ms);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) { *out_error = errno; close(fd); return -1; }
        if (polled == 0) continue;
        int socket_error = 0;
        socklen_t error_len = sizeof socket_error;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0) {
            *out_error = errno;
            close(fd);
            return -1;
        }
        if (error_len != sizeof socket_error || socket_error != 0) {
            *out_error = socket_error ? socket_error : EPROTO;
            close(fd);
            return -1;
        }
        status = 0;
    }
    if (cancelled(dialer)) { *out_error = ECANCELED; close(fd); return -1; }
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof peer;
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) {
        *out_error = errno;
        close(fd);
        return -1;
    }
    *out_error = 0;
    return fd;
}

int tun_dialer_connect(void *ctx, char *error, size_t error_cap) {
    tun_dialer_t *dialer = ctx;
    if (error && error_cap) error[0] = '\0';
    if (!dialer || !dialer->ready || !error || error_cap == 0) return -1;
    endpoint_pool_t snapshot;
    pthread_mutex_lock(&dialer->lock);
    snapshot = dialer->pool;
    int stopped = dialer->cancelled;
    pthread_mutex_unlock(&dialer->lock);
    if (stopped) {
        snprintf(error, error_cap, "the server connect was cancelled");
        return -1;
    }

    int64_t deadline_ms = senko_now_ms() + dialer->timeout_ms;
    int used[ENDPOINT_POOL_MAX] = {0};
    int last_error = 0;
    char last_address[INET6_ADDRSTRLEN] = "";
    for (size_t attempt = 0; attempt < snapshot.count; ++attempt) {
        if (cancelled(dialer)) { last_error = ECANCELED; break; }
        if (senko_now_ms() >= deadline_ms) { last_error = ETIMEDOUT; break; }
        int index = pick(&snapshot, used, (uint64_t)senko_now_ms());
        if (index < 0) break;
        used[index] = 1;
        const endpoint_t *endpoint = &snapshot.entries[index];
        int family = endpoint->address_len == 4 ? AF_INET : AF_INET6;
        (void)inet_ntop(family, endpoint->address, last_address, sizeof last_address);
        int fd = connect_one(dialer, endpoint, deadline_ms, &last_error);
        /* a tunnel shutting down says nothing about the endpoint */
        if (fd >= 0 || last_error != ECANCELED) {
            pthread_mutex_lock(&dialer->lock);
            if (fd >= 0)
                endpoint_pool_mark_success(&dialer->pool, (size_t)index,
                                           (uint64_t)senko_now_ms());
            else
                endpoint_pool_mark_failure(&dialer->pool, (size_t)index,
                                           (uint64_t)senko_now_ms());
            pthread_mutex_unlock(&dialer->lock);
        }
        if (fd >= 0) return fd;
        if (last_error == ECANCELED || last_error == ETIMEDOUT) break;
    }
    if (last_error == ECANCELED) {
        snprintf(error, error_cap, "the server connect was cancelled");
        return -1;
    }
    snprintf(error, error_cap, "cannot connect to the server at %s port %u",
             last_address[0] ? last_address : "any pinned address",
             (unsigned)dialer->port);
    route_errno_append(error, error_cap, last_error);
    return -1;
}

void tun_dialer_cancel(tun_dialer_t *dialer) {
    if (!dialer || !dialer->ready) return;
    pthread_mutex_lock(&dialer->lock);
    dialer->cancelled = 1;
    pthread_mutex_unlock(&dialer->lock);
}

void tun_dialer_destroy(tun_dialer_t *dialer) {
    if (!dialer || !dialer->ready) return;
    tun_dialer_cancel(dialer);
    pthread_mutex_destroy(&dialer->lock);
    dialer->ready = 0;
}
