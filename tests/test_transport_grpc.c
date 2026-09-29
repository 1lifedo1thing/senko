/* drive the xhttp/gRPC transport against recorded server response fixtures
   over a local socketpair, in the byte style real servers produce */
#include "transport.h"
#include "transport_pick.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "grpc_fixtures.inc"

static int g_fail = 0;
static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

static void nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static const char g_path[] = "/Tun/Tun";
static const char g_host[] = "proxy.example";
static const char g_peer[] = "203.0.113.10";

typedef struct {
    int sv[2];
    void *th;
    uint8_t client_out[8192];
    size_t client_len;
} grpc_test_t;

static int start_mode(grpc_test_t *t, const uint8_t *fx, size_t fx_len,
                      const char *mode) {
    memset(t, 0, sizeof *t);
    t->sv[0] = t->sv[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, t->sv) != 0) return -1;
    nonblock(t->sv[0]);
    nonblock(t->sv[1]);

    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.path = g_path;
    cfg.ws_host = g_host;
    cfg.xhttp_mode = mode;
    cfg.peer_host = g_peer;

    t->th = transport_xhttp_tcp.open(t->sv[0], &cfg);
    if (!t->th) return -1;

/* drain the client preface and request headers */
    uint8_t one = 0;
    transport_xhttp_tcp.write(t->th, &one, 0);
    for (;;) {
        ssize_t n = read(t->sv[1], t->client_out + t->client_len,
                         sizeof t->client_out - t->client_len);
        if (n > 0) {
            t->client_len += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }

/* play the recorded server bytes into the socket */
    size_t off = 0;
    while (off < fx_len) {
        ssize_t n = write(t->sv[1], fx + off, fx_len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int start(grpc_test_t *t, const uint8_t *fx, size_t fx_len) {
    return start_mode(t, fx, fx_len, "grpc");
}

static void stop(grpc_test_t *t) {
    if (t->th) transport_xhttp_tcp.close(t->th);
    if (t->sv[0] >= 0) close(t->sv[0]);
    if (t->sv[1] >= 0) close(t->sv[1]);
}

/* read until payload accumulates or the transport finishes */
static int drain(grpc_test_t *t, uint8_t *buf, size_t cap, size_t *total) {
    *total = 0;
    for (int round = 0; round < 8; ++round) {
        int rc = transport_xhttp_tcp.read(t->th, buf + *total, cap - *total);
        if (rc > 0) {
            *total += (size_t)rc;
            continue;
        }
        if (rc == TRANSPORT_WANT_READ || rc == TRANSPORT_WANT_WRITE) continue;
        return rc; /* EOF or ERR */
    }
    return 0;
}

static int client_contains(grpc_test_t *t, const char *needle) {
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= t->client_len; ++i)
        if (memcmp(t->client_out + i, needle, n) == 0) return 1;
    return 0;
}

static int client_padding_at_least(grpc_test_t *t, const char *prefix,
                                   size_t minimum) {
    size_t n = strlen(prefix);
    for (size_t i = 0; i + n < t->client_len; i++) {
        if (memcmp(t->client_out + i, prefix, n) != 0) continue;
        size_t j = i + n;
        while (j < t->client_len) {
            unsigned char c = t->client_out[j];
            if (!((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9'))) break;
            j++;
        }
        return j - (i + n) >= minimum;
    }
    return 0;
}

static void run(const char *name, const uint8_t *fx, size_t fx_len,
                int want_rc, const char *want_payload) {
    grpc_test_t t;
    if (start(&t, fx, fx_len) != 0) {
        ok(name, 0);
        stop(&t);
        return;
    }
    uint8_t buf[4096];
    size_t total = 0;
    int rc = drain(&t, buf, sizeof buf, &total);
    if (want_payload) {
        ok(name, total == strlen(want_payload) &&
           memcmp(buf, want_payload, total) == 0);
    } else {
        ok(name, rc == want_rc);
    }
    stop(&t);
}

int main(void) {
/* request side: strict serviceName, path and authority separation */
    {
        grpc_test_t t;
        ok("start", start(&t, fx_happy, sizeof fx_happy) == 0);
        ok("client preface sent", t.client_len > 24 &&
           memcmp(t.client_out, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
        ok("authority is host param", client_contains(&t, "proxy.example"));
        ok("path keeps serviceName", client_contains(&t, "/Tun/Tun"));
        ok("grpc content-type", client_contains(&t, "application/grpc"));
        uint8_t buf[4096];
        size_t total = 0;
        int rc = drain(&t, buf, sizeof buf, &total);
        ok("payload across two messages", rc > 0 || total > 0);
        ok("payload matches", total == 10 && memcmp(buf, "HELLOWORLD", 10) == 0);
        stop(&t);
    }

/* stream-one uses the same normalized slash as the XHTTP server route */
    {
        grpc_test_t t;
        ok("stream-one start",
           start_mode(&t, fx_happy, sizeof fx_happy, "stream-one") == 0);
        ok("stream-one path has trailing slash",
           client_contains(&t, "/Tun/Tun/?x_padding="));
        ok("stream-one padding meets server minimum",
           client_padding_at_least(&t, "/Tun/Tun/?x_padding=", 100));
        stop(&t);
    }

    run("http status 404 rejected", fx_status404, sizeof fx_status404,
        TRANSPORT_ERR, NULL);
    run("grpc status 12 rejected", fx_grpc12, sizeof fx_grpc12,
        TRANSPORT_ERR, NULL);
    run("rst stream rejected", fx_rst, sizeof fx_rst, TRANSPORT_ERR, NULL);
    run("goaway rejected", fx_goaway, sizeof fx_goaway, TRANSPORT_ERR, NULL);
    run("window overflow rejected", fx_win_overflow, sizeof fx_win_overflow,
        TRANSPORT_ERR, NULL);
    run("window update 0 rejected", fx_win_zero, sizeof fx_win_zero,
        TRANSPORT_ERR, NULL);
    run("missing status rejected", fx_no_status, sizeof fx_no_status,
        TRANSPORT_ERR, NULL);

/* xray ends every stream-one response with END_STREAM and then RST_STREAM
   NO_ERROR to stop the upload; that is a clean end, a bare NO_ERROR reset
   before the response finished is still a truncation */
    {
        static const uint8_t fx_one_done[] = {
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 'h', 'i',
            0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        };
        static const uint8_t fx_one_cut[] = {
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'h', 'i',
            0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        };
        grpc_test_t t;
        uint8_t buf[64];
        size_t total = 0;
        ok("stream-one finished start",
           start_mode(&t, fx_one_done, sizeof fx_one_done, "stream-one") == 0);
        int rc = drain(&t, buf, sizeof buf, &total);
        ok("reset after a complete response is a clean end",
           rc == TRANSPORT_EOF && total == 2 && memcmp(buf, "hi", 2) == 0);
        stop(&t);
        ok("stream-one cut start",
           start_mode(&t, fx_one_cut, sizeof fx_one_cut, "stream-one") == 0);
        rc = drain(&t, buf, sizeof buf, &total);
        ok("reset before the response ended is an error", rc == TRANSPORT_ERR);
        stop(&t);
    }

/* half close ends the upload stream after a clean relay */
    {
        grpc_test_t t;
        ok("restart for shutdown", start(&t, fx_happy, sizeof fx_happy) == 0);
        uint8_t buf[4096];
        size_t total = 0;
        (void)drain(&t, buf, sizeof buf, &total);
        uint8_t tail[1024];
        size_t tail_len = 0;
        transport_xhttp_tcp.shutdown(t.th);
        for (;;) {
            ssize_t n = read(t.sv[1], tail + tail_len, sizeof tail - tail_len);
            if (n > 0) { tail_len += (size_t)n; continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        ok("shutdown flushes end stream", tail_len >= 9);
        if (tail_len >= 9) {
/* last frame must be DATA with END_STREAM on stream 1 */
            const uint8_t *f = tail + tail_len - 9;
            ok("end stream data frame", f[3] == 0x00 && f[4] == 0x01 &&
               f[5] == 0 && f[6] == 0 && f[7] == 0 && f[8] == 1);
        }
        stop(&t);
    }

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    puts("all transport grpc fixture checks passed");
    return 0;
}
