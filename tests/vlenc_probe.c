/* blocking client for the vless encryption interop test: dials a reference
   server, runs the handshake and echoes data in both directions, N times.
   usage: vlenc_probe <port> <profile> <connections> */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "vlenc_conf.h"
#include "vlenc_conn.h"

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* read until n plaintext bytes arrived; returns -1 on any failure */
static int read_plain(int fd, vlc_conn_t *c, uint8_t *dst, size_t n, vlc_status_t *why) {
    size_t got = 0;
    while (got < n) {
        uint8_t out[VLC_REC_MAX];
        size_t ol = 0;
        vlc_status_t st = vlc_pull(c, out, sizeof out, &ol);
        if (st == VLC_DATA) {
            if (got + ol > n) return -2;
            memcpy(dst + got, out, ol);
            got += ol;
            continue;
        }
        if (st != VLC_NEED_MORE) { *why = st; return -1; }
        uint8_t *p;
        size_t cap;
        if (vlc_rx_space(c, &p, &cap) != VLC_OK) return -1;
        ssize_t r = read(fd, p, cap);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { *why = VLC_ERR_STATE; return -1; }
        vlc_rx_commit(c, (size_t)r);
    }
    return 0;
}

static int one(int port, const vlenc_cfg_t *cfg, const char *scope, int n) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { perror("connect"); return -1; }
    vlc_env_t env = { .use_aes = n % 2 };
    vlc_conn_t *c = vlc_new(cfg, scope, &env);
    const uint8_t *hello;
    size_t hl, ns;
    const size_t *segs;
    if (vlc_hello(c, &hello, &hl, &segs, &ns) != VLC_OK) return -1;
    size_t off = 0;
    for (size_t i = 0; i < ns; ++i) {
        if (write_all(fd, hello + off, segs[i])) return -1;
        off += segs[i];
    }
    int zrtt = vlc_is_zero_rtt(c);
    static const size_t sizes[] = { 1, 100, 8192, 50000 };
    vlc_status_t why = VLC_OK;
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; ++k) {
        size_t len = sizes[k];
        uint8_t *msg = malloc(len), *back = malloc(len);
        for (size_t i = 0; i < len; ++i) msg[i] = (uint8_t)(i * 31 + k);
        for (size_t o = 0; o < len;) {
            size_t t = len - o > VLC_PLAIN_MAX ? VLC_PLAIN_MAX : len - o;
            uint8_t wire[VLC_PREAMBLE_MAX + VLC_PLAIN_MAX + VLC_SEAL_EXTRA];
            size_t wl;
            vlc_status_t st;
            /* 1rtt: the reply has to be read before the first record may go */
            while ((st = vlc_seal(c, msg + o, t, wire, sizeof wire, &wl)) == VLC_ERR_STATE) {
                uint8_t scratch[1];
                uint8_t *p;
                size_t cap;
                vlc_status_t pst = vlc_pull(c, scratch, sizeof scratch, &wl);
                if (pst == VLC_NEED_MORE && !vlc_can_seal(c)) {
                    vlc_rx_space(c, &p, &cap);
                    ssize_t r = read(fd, p, cap);
                    if (r <= 0) { fprintf(stderr, "conn %d: no reply\n", n); return -1; }
                    vlc_rx_commit(c, (size_t)r);
                } else if (pst != VLC_OK && pst != VLC_NEED_MORE) {
                    fprintf(stderr, "conn %d: handshake status %d\n", n, pst);
                    return -1;
                }
            }
            if (st != VLC_OK) { fprintf(stderr, "conn %d: seal %d\n", n, st); return -1; }
            if (write_all(fd, wire, wl)) return -1;
            o += t;
        }
        if (read_plain(fd, c, back, len, &why) != 0 || memcmp(back, msg, len) != 0) {
            fprintf(stderr, "conn %d size %zu: echo failed (status %d)\n", n, len, why);
            return -1;
        }
        free(msg);
        free(back);
    }
    printf("conn %d: ok zero_rtt=%d\n", n, zrtt);
    vlc_free(c);
    close(fd);
    return zrtt;
}

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    static vlenc_cfg_t cfg;
    if (vlenc_parse(argv[2], &cfg) != VLENC_OK) { fprintf(stderr, "profile rejected\n"); return 2; }
    int conns = atoi(argv[3]);
    for (int i = 0; i < conns; ++i)
        if (one(atoi(argv[1]), &cfg, argv[2], i) < 0) return 1;
    return 0;
}
