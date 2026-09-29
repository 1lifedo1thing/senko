#include "real_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "senko_time.h"
#include "session.h"
#include "transport_pick.h"
#include "vless.h"

/* vision holds its first write for a short bootstrap, and the session only
   notices the deadline when it is pumped */
#define REAL_PROBE_TICK_MS 50

static void set_reason(char *reason, size_t cap, const char *text) {
    if (reason && cap) snprintf(reason, cap, "%s", text);
}

int real_probe_answer_ok(const char *buf, size_t len) {
    return buf && len >= 5 && memcmp(buf, "HTTP/", 5) == 0;
}

static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - senko_now_ms();
        if (left <= 0) return 0;
        struct pollfd p;
        p.fd = fd;
        p.events = events;
        p.revents = 0;
        int rc = poll(&p, 1, left > REAL_PROBE_TICK_MS ? REAL_PROBE_TICK_MS : (int)left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (rc > 0) return 1;
        return 0;
    }
}

static int dial_ipv4(const char *ip, uint16_t port, real_probe_bind_fn bind_fd,
                     int64_t deadline) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!ip || inet_pton(AF_INET, ip, &addr.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind_fd) bind_fd(fd);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    while (senko_now_ms() < deadline) {
        int ready = wait_fd(fd, POLLOUT, deadline);
        if (ready < 0) break;
        if (ready == 0) continue;
        int soerr = 0;
        socklen_t len = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) break;
        return fd;
    }
    close(fd);
    return -1;
}

int real_probe_run(const vl_server_t *server, const char *ip,
                   real_probe_bind_fn bind_fd, int timeout_ms,
                   char *reason, size_t reason_cap) {
    static const char request[] =
        "GET /generate_204 HTTP/1.1\r\n"
        "Host: " REAL_PROBE_HOST "\r\n"
        "User-Agent: senko\r\n"
        "Connection: close\r\n\r\n";
    const size_t request_len = sizeof request - 1;

    set_reason(reason, reason_cap, "");
    if (!server || !ip || timeout_ms <= 0) {
        set_reason(reason, reason_cap, "bad probe arguments");
        return -1;
    }
    const transport_vt_t *vt = transport_for_server(server);
    if (!vt) {
        set_reason(reason, reason_cap, "unsupported transport");
        return -1;
    }
    uint8_t uuid[VLESS_UUID_LEN];
    memset(uuid, 0, sizeof uuid);
    if (server->proto == VL_PROTO_VLESS &&
        vless_uuid_parse(server->uuid, uuid) != VLESS_OK) {
        set_reason(reason, reason_cap, "invalid uuid");
        return -1;
    }

    int64_t start = senko_now_ms();
    int64_t deadline = start + timeout_ms;
    int fd = dial_ipv4(ip, server->port, bind_fd, deadline);
    if (fd < 0) {
        set_reason(reason, reason_cap, "tcp connect failed");
        return -1;
    }

    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sni = server->sni;
    cfg.fingerprint = server->fp;
    cfg.reality_pbk = server->pbk;
    cfg.reality_sid = server->sid;
    cfg.path = server->path;
    cfg.ws_host = server->ws_host;
    cfg.xhttp_mode = server->mode;
    cfg.peer_host = server->host;
    cfg.insecure = server->insecure;
    void *th = vt->open(fd, &cfg);
    if (!th) {
        close(fd);
        set_reason(reason, reason_cap, "transport handshake failed");
        return -1;
    }

    int ms = -1;
    session_t *s = (session_t *)calloc(1, sizeof *s);
    if (!s) {
        set_reason(reason, reason_cap, "out of memory");
        goto done;
    }
    if (session_init(s, vt, th, server->proto,
                     server->proto == VL_PROTO_VLESS ? uuid : NULL,
                     server->flow[0] ? server->flow : NULL,
                     server->user[0] ? server->user : NULL,
                     server->pass[0] ? server->pass : NULL) != SESS_OK) {
        set_reason(reason, reason_cap, "protocol session could not start");
        goto done;
    }

    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_DOMAIN;
    snprintf(dest.domain, sizeof dest.domain, "%s", REAL_PROBE_HOST);
    dest.port = REAL_PROBE_PORT;
    size_t fed = 0;
    if (session_start_from_transparent_dest(s, &dest, (const uint8_t *)request,
                                            request_len, &fed) != SESS_OK) {
        set_reason(reason, reason_cap, "proxy request could not be encoded");
        goto done;
    }

    char answer[8];
    size_t answer_len = 0;
    for (;;) {
        if (senko_now_ms() >= deadline) {
            set_reason(reason, reason_cap, "no answer through the server");
            goto done;
        }
        if (fed < request_len) {
            size_t consumed = 0;
            if (session_feed_client(s, (const uint8_t *)request + fed,
                                    request_len - fed, &consumed) != SESS_OK) {
                set_reason(reason, reason_cap, "proxy request failed");
                goto done;
            }
            fed += consumed;
        }
        if (session_pump_remote(s) != SESS_OK) {
            set_reason(reason, reason_cap, "server dropped the proxy session");
            goto done;
        }
        uint8_t chunk[64];
        size_t n = session_take_client(s, chunk, sizeof chunk);
        if (n > 0 && answer_len < sizeof answer) {
            size_t copy = sizeof answer - answer_len;
            if (copy > n) copy = n;
            memcpy(answer + answer_len, chunk, copy);
            answer_len += copy;
        }
        if (answer_len >= 5) {
            if (!real_probe_answer_ok(answer, answer_len)) {
                set_reason(reason, reason_cap, "unexpected answer through the server");
                goto done;
            }
            ms = (int)(senko_now_ms() - start);
            goto done;
        }
        if (s->state == SESS_ERROR || s->state == SESS_CLOSED) {
            set_reason(reason, reason_cap, "server closed the proxy session");
            goto done;
        }
        short events = POLLIN;
        if ((s->to_remote_len > 0 && !s->to_remote_wait_read) ||
            (vt->want_write && vt->want_write(th)))
            events |= POLLOUT;
        if (wait_fd(fd, events, deadline) < 0) {
            set_reason(reason, reason_cap, "socket failed");
            goto done;
        }
    }

done:
    vt->close(th);
    close(fd);
    free(s);
    return ms;
}
