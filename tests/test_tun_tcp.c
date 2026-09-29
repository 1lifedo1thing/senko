/* the tcp bridge end to end. apps connect to addresses on the internet
   through a socketpair standing in for the utun descriptor; the bridge opens
   vless over plain tcp to a deterministic server in this process, which checks
   the request and plays the destination by its port: echo, a fixed download,
   a slow sink, a reset. the app side speaks tcp by hand, respecting the
   window it is given, so every byte can be counted on both ends */

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "packet_fixture.h"
#include "tun_loop.h"
#include "tun_tcp.h"

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static const uint8_t APP4[4]   = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t DEST_A[4] = { 203, 0, 113, 7 };
static const uint8_t DEST_B[4] = { 203, 0, 113, 8 };
static const uint8_t APP6[16]   = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
static const uint8_t LOCAL6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,2 };
static const uint8_t SYNTH6[16] = { 0xfd, 0, 0x5e, 0x4b, 0,0,0,0, 0,0,0,0, 0,0,0,3 };
static const uint8_t DEST6[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,7 };

static const uint8_t UUID[16] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                                  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

enum { PORT_ECHO = 7, PORT_SINK = 9, PORT_CHARGEN = 19, PORT_RESET = 13,
       PORT_SLOW = 99 };
#define CHARGEN_BYTES (256u * 1024u)
#define GENERATION 5

static uint8_t pattern_byte(size_t i) { return (uint8_t)(i * 31u + (i >> 9)); }

static uint32_t fnv(uint32_t h, const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 16777619u; }
    return h;
}

static void pause_ms(int ms) {
    struct timespec t = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* ---- the deterministic vless server ------------------------------------- */

#define SERVER_CONNS 64

typedef struct {
    int      used;
    uint8_t  atyp;
    uint8_t  address[16];
    uint16_t port;
    int      uuid_ok;
    size_t   received;
    uint32_t hash;
    int      saw_eof;
    int      finished;
} server_conn_t;

static struct {
    int             listen_fd;
    uint16_t        port;
    pthread_mutex_t lock;
    server_conn_t   conns[SERVER_CONNS];
    size_t          accepted;
} server;

static int read_full(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r > 0) { off += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

/* xray buffers the vless response header until the target sends its first
   byte, so a silent target means a silent server */
static int write_reply(int fd, int *header_sent, const uint8_t *buf, size_t n) {
    if (!*header_sent) {
        static const uint8_t response[2] = { 0, 0 };
        if (write_full(fd, response, sizeof response) != 0) return -1;
        *header_sent = 1;
    }
    return write_full(fd, buf, n);
}

static void *serve_one(void *arg) {
    int fd = (int)(intptr_t)arg;
    int header_sent = 0;
    uint8_t head[18];
    server_conn_t *record = NULL;
    if (read_full(fd, head, sizeof head) != 0) goto done;
    uint8_t addons[256];
    if (head[17] && read_full(fd, addons, head[17]) != 0) goto done;
    uint8_t cmd[4];
    if (read_full(fd, cmd, sizeof cmd) != 0) goto done;

    pthread_mutex_lock(&server.lock);
    for (size_t i = 0; i < SERVER_CONNS; ++i) {
        if (server.conns[i].used) continue;
        record = &server.conns[i];
        memset(record, 0, sizeof *record);
        record->used = 1;
        break;
    }
    pthread_mutex_unlock(&server.lock);
    if (!record) goto done;

    record->uuid_ok = head[0] == 0 && memcmp(head + 1, UUID, 16) == 0 && cmd[0] == 1;
    record->port = (uint16_t)(cmd[1] << 8 | cmd[2]);
    record->atyp = cmd[3];
    size_t alen = cmd[3] == 1 ? 4 : cmd[3] == 3 ? 16 : 0;
    if (!alen || read_full(fd, record->address, alen) != 0) goto done;

    uint8_t buf[16384];
    record->hash = 2166136261u;
    if (record->port == PORT_RESET) {
        struct linger hard = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &hard, sizeof hard);
        goto done;
    }
    if (record->port == PORT_CHARGEN) {
        for (size_t sent = 0; sent < CHARGEN_BYTES; ) {
            size_t n = CHARGEN_BYTES - sent < sizeof buf ? CHARGEN_BYTES - sent : sizeof buf;
            for (size_t i = 0; i < n; ++i) buf[i] = pattern_byte(sent + i);
            if (write_reply(fd, &header_sent, buf, n) != 0) goto done;
            sent += n;
        }
        shutdown(fd, SHUT_WR);
    }
    for (;;) {
        if (record->port == PORT_SLOW) pause_ms(20);
        ssize_t r = read(fd, buf, record->port == PORT_SLOW ? 1024 : sizeof buf);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            record->saw_eof = r == 0;
            break;
        }
        record->received += (size_t)r;
        record->hash = fnv(record->hash, buf, (size_t)r);
        if (record->port == PORT_ECHO &&
            write_reply(fd, &header_sent, buf, (size_t)r) != 0) break;
    }
    /* the app's half close reached us; echo answers with its own */
    if (record->port == PORT_ECHO) shutdown(fd, SHUT_WR);
done:
    if (record) record->finished = 1;
    close(fd);
    return NULL;
}

static void *server_main(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(server.listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return NULL;
        }
        pthread_mutex_lock(&server.lock);
        ++server.accepted;
        pthread_mutex_unlock(&server.lock);
        pthread_t t;
        pthread_create(&t, NULL, serve_one, (void *)(intptr_t)fd);
        pthread_detach(t);
    }
}

static void server_start(void) {
    pthread_mutex_init(&server.lock, NULL);
    server.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(server.listen_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t len = sizeof a;
    getsockname(server.listen_fd, (struct sockaddr *)&a, &len);
    server.port = ntohs(a.sin_port);
    listen(server.listen_fd, 64);
    pthread_t t;
    pthread_create(&t, NULL, server_main, NULL);
    pthread_detach(t);
}

static server_conn_t *server_find(uint16_t port, const uint8_t *address, size_t alen,
                                  int wait_finished, int wait_ms) {
    for (int waited = 0; waited <= wait_ms; waited += 5) {
        pthread_mutex_lock(&server.lock);
        server_conn_t *hit = NULL;
        for (size_t i = 0; i < SERVER_CONNS; ++i) {
            server_conn_t *c = &server.conns[i];
            if (!c->used || c->port != port || memcmp(c->address, address, alen) != 0) continue;
            if (wait_finished && !c->finished) continue;
            hit = c;
        }
        pthread_mutex_unlock(&server.lock);
        if (hit) return hit;
        pause_ms(5);
    }
    return NULL;
}

static void server_forget(void) {
    pthread_mutex_lock(&server.lock);
    memset(server.conns, 0, sizeof server.conns);
    pthread_mutex_unlock(&server.lock);
}

/* ---- dialing, with a gate the cancellation test can hold shut ------------ */

static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static int gate_closed;
static int dial_fails;

static int dial_server(void *ctx, char *error, size_t cap) {
    (void)ctx;
    pthread_mutex_lock(&gate_lock);
    while (gate_closed) pthread_cond_wait(&gate_cond, &gate_lock);
    int fail = dial_fails;
    pthread_mutex_unlock(&gate_lock);
    if (fail) {
        snprintf(error, cap, "the test refused the connection on purpose");
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(server.port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        snprintf(error, cap, "connect to the test server failed");
        close(fd);
        return -1;
    }
    return fd;
}

static void set_gate(int closed) {
    pthread_mutex_lock(&gate_lock);
    gate_closed = closed;
    pthread_cond_broadcast(&gate_cond);
    pthread_mutex_unlock(&gate_lock);
}

/* ---- the tunnel under test ---------------------------------------------- */

static struct {
    tun_loop_t     *loop;
    tun_tcp_t      *tcp;
    utun_device_t   device;
    int             peer;
    pthread_t       thread;
    tun_loop_result_t result;
} tunnel;

static void *run_tunnel(void *arg) {
    (void)arg;
    tun_loop_run(tunnel.loop, &tunnel.result);
    return NULL;
}

/* rules for the policy checks: one address blocked, loopback sent direct */
static ruleset_t tunnel_rules;
static tun_policy_t tunnel_policy;
static const uint8_t DEST_BLOCKED[4] = { 203, 0, 113, 99 };
static const uint8_t LOOPBACK4[4] = { 127, 0, 0, 1 };

static int plain_socket(void *ctx, int family, int type, char *error, size_t cap) {
    (void)ctx; (void)error; (void)cap;
    int fd = socket(family, type, 0);
    if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

/* a site the rules send direct: echoes, then ends its side after the app's */
static int direct_listen_fd = -1;
static uint16_t direct_port;
static void *direct_echo(void *arg) {
    (void)arg;
    int fd = accept(direct_listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        if (write_full(fd, buf, (size_t)n) != 0) break;
    }
    shutdown(fd, SHUT_WR);
    close(fd);
    return NULL;
}

static void tunnel_start(void) {
    int fds[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
    int big = 1 << 20;
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    tunnel.peer = fds[1];
    utun_device_init(&tunnel.device);
    utun_device_adopt(&tunnel.device, fds[0], "utun7");

    tun_loop_config_t config;
    memset(&config, 0, sizeof config);
    config.generation = GENERATION;
    tun_stack_config_t *s = &config.stack;
    s->mtu = 1500;
    s->have_ipv4 = 1;
    memcpy(s->address4, LOCAL4, 4);
    memcpy(s->synthetic4, SYNTH4, 4);
    s->netmask4[0] = s->netmask4[1] = s->netmask4[2] = s->netmask4[3] = 255;
    s->have_ipv6 = 1;
    memcpy(s->address6, LOCAL6, 16);
    memcpy(s->synthetic6, SYNTH6, 16);
    s->queue_max_packets = 16;
    s->pending_max_ms = 3000;

    tun_tcp_config_t tcp;
    memset(&tcp, 0, sizeof tcp);
    tcp.vt = &transport_tcp;
    tcp.proto = VL_PROTO_VLESS;
    memcpy(tcp.uuid, UUID, 16);
    tcp.dial = dial_server;
    tcp.opener_threads = 4;
    tcp.dns_upstream[0] = 192;
    tcp.dns_upstream[1] = 0;
    tcp.dns_upstream[2] = 2;
    tcp.dns_upstream[3] = 53;
    tcp.dns_upstream_len = 4;
    ruleset_init(&tunnel_rules);
    static const char *const rule_texts[] = { "block ip-cidr 203.0.113.99/32",
                                              "direct ip-cidr 127.0.0.1/32" };
    for (size_t i = 0; i < 2; ++i)
        ruleset_add_text(&tunnel_rules, rule_texts[i], strlen(rule_texts[i]), NULL);
    tun_policy_init(&tunnel_policy, &tunnel_rules);
    tcp.policy = &tunnel_policy;
    tcp.direct_socket = plain_socket;

    tunnel.tcp = malloc(tun_tcp_size());
    tun_tcp_init(tunnel.tcp, &tcp, &config);
    tunnel.loop = malloc(tun_loop_size());
    tun_loop_init(tunnel.loop, &config, &tunnel.device);
    tun_tcp_bind(tunnel.tcp, tunnel.loop, GENERATION);
    pthread_create(&tunnel.thread, NULL, run_tunnel, NULL);
}

static void tunnel_stop(void) {
    tun_loop_command_t stop = { TUN_LOOP_CMD_STOP, GENERATION, 0 };
    tun_loop_post(tunnel.loop, &stop);
    pthread_join(tunnel.thread, NULL);
    tun_loop_destroy(tunnel.loop);
    close(tunnel.peer);
}

/* ---- an app speaking tcp by hand ---------------------------------------- */

#define APP_RX_MAX (512u * 1024u)
#define MSS 1300

typedef struct {
    int      v6;
    uint8_t  src[16];
    uint8_t  dst[16];
    uint16_t sport;
    uint16_t dport;
    uint32_t snd_nxt;
    uint32_t snd_una;
    uint32_t rcv_nxt;
    uint32_t peer_window;
    uint16_t window;      /* what this app advertises */
    int      established;
    int      got_fin;
    int      got_rst;
    int      syn_acked;
    size_t   rx_len;      /* bytes received in order */
    uint32_t rx_hash;
    int      keep_rx;
    uint8_t *rx;          /* the bytes themselves, when keep_rx */
} app_t;

#define APPS_MAX (TUN_TCP_DEFAULT_MAX_FLOWS + 2)
static app_t *apps[APPS_MAX];
static size_t app_count;

static size_t build(const app_t *a, uint8_t *p, uint8_t flags, const uint8_t *data,
                    size_t len) {
    size_t total;
    if (a->v6) {
        total = pkt_ip6(p, a->src, a->dst, 6, 20 + len, 0, 0);
    } else {
        total = pkt_ip4(p, a->src, a->dst, 6, 20 + len);
    }
    uint8_t *t = p + pkt_l4(p, total);
    pkt_tcp_fields(t, a->sport, a->dport, flags, a->snd_nxt, a->rcv_nxt, 0);
    pkt_wr16(t + 14, a->window);
    if (len) memcpy(t + 20, data, len);
    pkt_fill_l4(p, total, 16);
    return total;
}

static void app_send_raw(app_t *a, uint8_t flags, const uint8_t *data, size_t len) {
    uint8_t p[1600], frame[1604];
    size_t n = build(a, p, flags, data, len);
    size_t f = pkt_frame(frame, p, n);
    send(tunnel.peer, frame, f, 0);
}

static void app_ack(app_t *a) { app_send_raw(a, PKT_ACK, NULL, 0); }

static app_t *match(const uint8_t *p, size_t len) {
    size_t l4 = pkt_l4(p, len);
    int v6 = !pkt_is_v4(p);
    size_t alen = v6 ? 16 : 4;
    uint16_t sport = pkt_rd16(p + l4), dport = pkt_rd16(p + l4 + 2);
    for (size_t i = 0; i < app_count; ++i) {
        app_t *a = apps[i];
        if (!a || a->v6 != v6 || a->sport != dport || a->dport != sport) continue;
        if (memcmp(pkt_src(p), a->dst, alen) != 0) continue;
        return a;
    }
    return NULL;
}

/* read every frame that is there, or wait up to wait_ms for the first one */
static int pump(int wait_ms) {
    int seen = 0;
    for (;;) {
        struct pollfd pfd = { tunnel.peer, POLLIN, 0 };
        if (poll(&pfd, 1, seen ? 0 : wait_ms) <= 0) return seen;
        uint8_t frame[2048];
        ssize_t got = recv(tunnel.peer, frame, sizeof frame, 0);
        if (got <= 4) return seen;
        ++seen;
        const uint8_t *p = frame + 4;
        size_t len = (size_t)got - 4;
        if (pkt_proto(p, len) != 6 || !pkt_l4_valid(p, len)) continue;
        app_t *a = match(p, len);
        if (!a) continue;
        const uint8_t *t = p + pkt_l4(p, len);
        uint8_t flags = t[13];
        uint32_t seq = pkt_rd32(t + 4), ack = pkt_rd32(t + 8);
        size_t hl = (size_t)(t[12] >> 4) * 4;
        size_t data = len - pkt_l4(p, len) - hl;
        if (flags & PKT_RST) { a->got_rst = 1; continue; }
        if ((flags & PKT_SYN) && (flags & PKT_ACK)) {
            a->rcv_nxt = seq + 1;
            a->snd_una = ack;
            a->peer_window = pkt_rd16(t + 14);
            a->syn_acked = 1;
            continue;
        }
        if (flags & PKT_ACK) {
            if ((int32_t)(ack - a->snd_una) > 0) a->snd_una = ack;
            a->peer_window = pkt_rd16(t + 14);
        }
        int advanced = 0;
        if (data && seq == a->rcv_nxt) {
            /* an app with a small window only takes what it advertised */
            size_t take = data;
            if (a->keep_rx && a->rx_len + take > APP_RX_MAX) take = APP_RX_MAX - a->rx_len;
            if (a->keep_rx) memcpy(a->rx + a->rx_len, t + hl, take);
            a->rx_hash = fnv(a->rx_hash, t + hl, take);
            a->rx_len += take;
            a->rcv_nxt += (uint32_t)take;
            advanced = 1;
        }
        if ((flags & PKT_FIN) && seq + (uint32_t)data == a->rcv_nxt) {
            a->rcv_nxt += 1;
            a->got_fin = 1;
            advanced = 1;
        }
        if (advanced || data) app_ack(a);
    }
}

static int wait_until(int *flag, int wait_ms) {
    for (int waited = 0; !*flag && waited < wait_ms; waited += 10) pump(10);
    return *flag;
}

static void app_init(app_t *a, int v6, const uint8_t *dst, uint16_t dport, uint16_t sport) {
    memset(a, 0, sizeof *a);
    a->v6 = v6;
    memcpy(a->src, v6 ? APP6 : APP4, v6 ? 16 : 4);
    memcpy(a->dst, dst, v6 ? 16 : 4);
    a->dport = dport;
    a->sport = sport;
    a->snd_nxt = 1000u * sport;
    a->window = 65535;
    a->rx_hash = 2166136261u;
    for (size_t i = 0; i < APPS_MAX; ++i)
        if (!apps[i]) { apps[i] = a; if (i + 1 > app_count) app_count = i + 1; break; }
}

static void app_forget(app_t *a) {
    for (size_t i = 0; i < APPS_MAX; ++i) if (apps[i] == a) apps[i] = NULL;
    free(a->rx);
    a->rx = NULL;
}

static int app_connect(app_t *a, const uint8_t *early, size_t early_len) {
    app_send_raw(a, PKT_SYN, NULL, 0);
    a->snd_nxt += 1;
    if (!wait_until(&a->syn_acked, 3000)) return 0;
    if (early_len) {
        app_send_raw(a, PKT_ACK | 0x08, early, early_len);
        a->snd_nxt += (uint32_t)early_len;
    } else {
        app_ack(a);
    }
    a->established = 1;
    return 1;
}

/* send len bytes of the pattern starting at offset, respecting the window */
static int app_send(app_t *a, size_t offset, size_t len, int wait_ms) {
    uint8_t chunk[MSS];
    size_t sent = 0;
    int idle = 0;
    while (sent < len) {
        uint32_t in_flight = a->snd_nxt - a->snd_una;
        if (in_flight >= a->peer_window) {
            if (!pump(20)) idle += 20;
            if (idle > wait_ms) return 0;
            continue;
        }
        idle = 0;
        size_t room = a->peer_window - in_flight;
        size_t n = len - sent;
        if (n > MSS) n = MSS;
        if (n > room) n = room;
        for (size_t i = 0; i < n; ++i) chunk[i] = pattern_byte(offset + sent + i);
        app_send_raw(a, PKT_ACK | 0x08, chunk, n);
        a->snd_nxt += (uint32_t)n;
        sent += n;
        pump(0);
    }
    /* wait for everything to be acknowledged */
    for (int waited = 0; a->snd_una != a->snd_nxt && waited < wait_ms; waited += 10) pump(10);
    return a->snd_una == a->snd_nxt;
}

static void app_fin(app_t *a) {
    app_send_raw(a, PKT_FIN | PKT_ACK, NULL, 0);
    a->snd_nxt += 1;
}

static uint32_t pattern_hash(size_t offset, size_t len) {
    uint32_t h = 2166136261u;
    uint8_t chunk[4096];
    for (size_t done = 0; done < len; ) {
        size_t n = len - done < sizeof chunk ? len - done : sizeof chunk;
        for (size_t i = 0; i < n; ++i) chunk[i] = pattern_byte(offset + done + i);
        h = fnv(h, chunk, n);
        done += n;
    }
    return h;
}

int main(void) {
    /* senkod ignores SIGPIPE in main.c; a write to a server that already hung
       up must fail with EPIPE here too instead of killing the process */
    signal(SIGPIPE, SIG_IGN);
    server_start();
    tunnel_start();
    static app_t a, b;

    /* ---- one flow to the echo server, a request and its answer ---- */
    app_init(&a, 0, DEST_A, PORT_ECHO, 40001);
    a.keep_rx = 1;
    a.rx = malloc(APP_RX_MAX);
    ok("an app connects to an address on the internet", app_connect(&a, NULL, 0));
    server_conn_t *seen = server_find(PORT_ECHO, DEST_A, 4, 0, 2000);
    ok("the server receives a vless request for the original destination",
       seen && seen->atyp == 1 && seen->uuid_ok);
    ok("upload through the tunnel", app_send(&a, 0, 5000, 3000));
    for (int w = 0; a.rx_len < 5000 && w < 3000; w += 10) pump(10);
    ok("the echo comes back whole",
       a.rx_len == 5000 && a.rx_hash == pattern_hash(0, 5000));
    app_fin(&a);
    ok("the app's fin reaches the server and the server's fin comes back",
       wait_until(&a.got_fin, 3000));
    seen = server_find(PORT_ECHO, DEST_A, 4, 1, 2000);
    ok("the server saw a clean end after every byte",
       seen && seen->saw_eof && seen->received == 5000 &&
       seen->hash == pattern_hash(0, 5000));
    app_forget(&a);
    server_forget();

    /* the app may have chosen a local resolver that only exists on its own
       network, so TCP DNS uses the same reachable upstream as packet DNS */
    static const uint8_t dns_target[4] = { 192, 0, 2, 53 };
    app_init(&a, 0, DEST_A, 53, 40011);
    ok("tcp dns connects through the tunnel", app_connect(&a, NULL, 0));
    seen = server_find(53, dns_target, 4, 0, 2000);
    ok("tcp dns goes to the configured upstream", seen && seen->uuid_ok);
    app_fin(&a);
    app_forget(&a);
    server_forget();

    /* ---- two flows at once, same port, different addresses ---- */
    app_init(&a, 0, DEST_A, PORT_SINK, 40002);
    app_init(&b, 0, DEST_B, PORT_SINK, 40002);
    ok("two flows to the same port open", app_connect(&a, NULL, 0) && app_connect(&b, NULL, 0));
    ok("they carry different streams", app_send(&a, 0, 30000, 3000) &&
       app_send(&b, 777, 20000, 3000));
    app_fin(&a);
    app_fin(&b);
    pump(50);
    server_conn_t *sa = server_find(PORT_SINK, DEST_A, 4, 1, 3000);
    server_conn_t *sb = server_find(PORT_SINK, DEST_B, 4, 1, 3000);
    ok("each server connection got its own flow's bytes and only those",
       sa && sb && sa->received == 30000 && sa->hash == pattern_hash(0, 30000) &&
       sb->received == 20000 && sb->hash == pattern_hash(777, 20000));
    app_forget(&a);
    app_forget(&b);
    server_forget();

    /* ---- bytes right behind the handshake ---- */
    app_init(&a, 0, DEST_A, PORT_SINK, 40003);
    uint8_t early[600];
    for (size_t i = 0; i < sizeof early; ++i) early[i] = pattern_byte(i);
    ok("an app sends its first bytes with the handshake's ack",
       app_connect(&a, early, sizeof early));
    ok("and more right after", app_send(&a, sizeof early, 4000, 3000));
    app_fin(&a);
    pump(50);
    seen = server_find(PORT_SINK, DEST_A, 4, 1, 3000);
    ok("early bytes arrive first and in order",
       seen && seen->received == sizeof early + 4000 &&
       seen->hash == pattern_hash(0, sizeof early + 4000));
    app_forget(&a);
    server_forget();

    /* ---- a slow server: the app's upload waits, nothing is lost ---- */
    app_init(&a, 0, DEST_A, PORT_SLOW, 40004);
    ok("a flow to a slow server opens", app_connect(&a, NULL, 0));
    ok("a large upload to a slow server finishes", app_send(&a, 0, 300000, 20000));
    app_fin(&a);
    seen = server_find(PORT_SLOW, DEST_A, 4, 1, 20000);
    ok("the slow server got every byte in order",
       seen && seen->received == 300000 && seen->hash == pattern_hash(0, 300000));
    app_forget(&a);
    server_forget();

    /* ---- a fast server and a slow app: the download waits, nothing lost ---- */
    app_init(&a, 0, DEST_A, PORT_CHARGEN, 40005);
    a.window = 2048;
    ok("a flow to a fast server opens", app_connect(&a, NULL, 0));
    for (int w = 0; !a.got_fin && w < 20000; w += 10) {
        pump(10);
        if (w % 100 == 0) app_ack(&a); /* a slow reader opens its window now and then */
    }
    ok("the whole download arrives through a small window",
       a.rx_len == CHARGEN_BYTES && a.rx_hash == pattern_hash(0, CHARGEN_BYTES));
    ok("the server's fin arrives after its last byte", a.got_fin);
    app_fin(&a);
    pump(50);
    app_forget(&a);
    server_forget();

    /* ---- v6 end to end ---- */
    app_init(&a, 1, DEST6, PORT_ECHO, 40006);
    a.keep_rx = 1;
    a.rx = malloc(APP_RX_MAX);
    ok("a v6 app connects", app_connect(&a, NULL, 0));
    seen = server_find(PORT_ECHO, DEST6, 16, 0, 2000);
    ok("the server gets a v6 destination", seen && seen->atyp == 3);
    ok("v6 upload", app_send(&a, 0, 3000, 3000));
    for (int w = 0; a.rx_len < 3000 && w < 3000; w += 10) pump(10);
    ok("v6 echo comes back whole", a.rx_len == 3000 && a.rx_hash == pattern_hash(0, 3000));
    app_fin(&a);
    wait_until(&a.got_fin, 3000);
    app_forget(&a);
    server_forget();

    /* ---- resets both ways ---- */
    app_init(&a, 0, DEST_A, PORT_RESET, 40007);
    ok("a flow to a server that resets opens", app_connect(&a, NULL, 0));
    ok("the server's reset reaches the app as a reset", wait_until(&a.got_rst, 3000));
    app_forget(&a);
    server_forget();

    app_init(&a, 0, DEST_A, PORT_SINK, 40008);
    ok("a flow opens before the app resets it", app_connect(&a, NULL, 0));
    app_send(&a, 0, 1000, 3000);
    app_send_raw(&a, PKT_RST, NULL, 0);
    seen = server_find(PORT_SINK, DEST_A, 4, 1, 3000);
    ok("the app's reset closes the server connection", seen && seen->finished);
    app_forget(&a);
    server_forget();

    /* ---- no false success: an unreachable server means a reset, and no
       handshake is answered before the server is reachable ---- */
    pthread_mutex_lock(&gate_lock);
    dial_fails = 1;
    pthread_mutex_unlock(&gate_lock);
    app_init(&a, 0, DEST_A, PORT_ECHO, 40009);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    ok("an unreachable server answers the app with a reset", wait_until(&a.got_rst, 3000));
    ok("and never with a handshake", !a.syn_acked);
    pthread_mutex_lock(&gate_lock);
    dial_fails = 0;
    pthread_mutex_unlock(&gate_lock);
    app_forget(&a);

    set_gate(1);
    app_init(&a, 0, DEST_A, PORT_ECHO, 40010);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    pump(300);
    ok("while the server connection is still opening the app hears nothing",
       !a.syn_acked && !a.got_rst);
    set_gate(0);
    ok("once it opens the handshake completes", wait_until(&a.syn_acked, 3000));
    a.snd_nxt += 1; /* the raw syn took one sequence number */
    app_send_raw(&a, PKT_RST, NULL, 0);
    app_forget(&a);

    /* a client-speaks-first target: the server stays silent until the app
       sends, so waiting for its response before the handshake would never end */
    app_init(&a, 0, DEST_A, PORT_SINK, 40012);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    ok("the app connects while the vless server has sent nothing yet",
       wait_until(&a.syn_acked, 3000));
    ok("the server got the request for the silent target",
       server_find(PORT_SINK, DEST_A, 4, 0, 2000) != NULL);
    a.snd_nxt += 1;
    app_send_raw(&a, PKT_RST, NULL, 0);
    app_forget(&a);
    server_forget();

    /* ---- over the flow limit a syn waits for a slot, never a reset ---- */
    {
        app_t held[TUN_TCP_DEFAULT_MAX_FLOWS];
        int filled = 1;
        for (int i = 0; i < TUN_TCP_DEFAULT_MAX_FLOWS; ++i) {
            app_init(&held[i], 0, DEST_A, PORT_SINK, (uint16_t)(40100 + i));
            if (!app_connect(&held[i], NULL, 0)) filled = 0;
        }
        ok("the tunnel fills its flow limit", filled);
        app_t extra;
        app_init(&extra, 0, DEST_A, PORT_SINK, 40200);
        app_send_raw(&extra, PKT_SYN, NULL, 0);
        extra.snd_nxt += 1;
        pump(300);
        ok("a flow over the limit is held, not reset", !extra.syn_acked && !extra.got_rst);
        app_send_raw(&held[0], PKT_RST, NULL, 0);
        ok("the held flow connects once a slot frees", wait_until(&extra.syn_acked, 3000));
        for (int i = 1; i < TUN_TCP_DEFAULT_MAX_FLOWS; ++i) {
            app_send_raw(&held[i], PKT_RST, NULL, 0);
            app_forget(&held[i]);
        }
        app_forget(&held[0]);
        app_send_raw(&extra, PKT_RST, NULL, 0);
        app_forget(&extra);
        pump(200);
        server_forget();
    }

    /* ---- rules: a blocked address gets a reset, a direct one skips the server ---- */
    app_init(&a, 0, DEST_BLOCKED, PORT_ECHO, 40300);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    ok("a blocked destination is answered with a reset", wait_until(&a.got_rst, 2000));
    ok("and the server never hears of it", server_find(PORT_ECHO, DEST_BLOCKED, 4, 0, 300) == NULL);
    app_forget(&a);

    direct_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in loop_address;
    memset(&loop_address, 0, sizeof loop_address);
    loop_address.sin_family = AF_INET;
    loop_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(direct_listen_fd, (struct sockaddr *)&loop_address, sizeof loop_address);
    socklen_t loop_len = sizeof loop_address;
    getsockname(direct_listen_fd, (struct sockaddr *)&loop_address, &loop_len);
    direct_port = ntohs(loop_address.sin_port);
    listen(direct_listen_fd, 1);
    pthread_t echo_thread;
    pthread_create(&echo_thread, NULL, direct_echo, NULL);
    app_init(&a, 0, LOOPBACK4, direct_port, 40301);
    a.keep_rx = 1;
    a.rx = malloc(APP_RX_MAX);
    ok("a direct destination connects without the server", app_connect(&a, NULL, 0) &&
       server_find(direct_port, LOOPBACK4, 4, 0, 300) == NULL);
    ok("upload straight to the direct destination", app_send(&a, 0, 60000, 3000));
    for (int w = 0; a.rx_len < 60000 && w < 3000; w += 10) pump(10);
    ok("its echo comes back whole",
       a.rx_len == 60000 && a.rx_hash == pattern_hash(0, 60000));
    app_fin(&a);
    ok("the app's fin reaches the direct destination and its fin comes back",
       wait_until(&a.got_fin, 3000));
    pthread_join(echo_thread, NULL);
    close(direct_listen_fd);
    app_forget(&a);
    ok("the relay counted one direct and one blocked flow",
       tun_tcp_stats(tunnel.tcp)->direct == 1 && tun_tcp_stats(tunnel.tcp)->blocked == 1);

    /* ---- cancellation while the server connection is opening ---- */
    set_gate(1);
    app_init(&a, 0, DEST_A, PORT_SINK, 40011);
    app_send_raw(&a, PKT_SYN, NULL, 0);
    pump(100);
    app_send_raw(&a, PKT_RST, NULL, 0); /* the app gives up; the flow waits out its hold */
    pause_ms(3200);                      /* past pending_max_ms, so the held syn expires */
    set_gate(0);
    pause_ms(300);
    pump(100);
    ok("a flow abandoned while opening never gets a handshake", !a.syn_acked);
    app_forget(&a);

    tunnel_stop();
    const tun_tcp_stats_t *stats = tun_tcp_stats(tunnel.tcp);
    ok("every opened flow was accounted for",
       stats->opened >= 10 && stats->refused >= 1);
    ok("the relay counted the traffic",
       stats->bytes_to_server >= 300000 && stats->bytes_to_app >= CHARGEN_BYTES);
    pause_ms(200);
    pthread_mutex_lock(&server.lock);
    size_t lingering = 0;
    for (size_t i = 0; i < SERVER_CONNS; ++i)
        if (server.conns[i].used && !server.conns[i].finished) ++lingering;
    pthread_mutex_unlock(&server.lock);
    ok("no server connection outlives the tunnel", lingering == 0);
    free(tunnel.tcp);
    free(tunnel.loop);
    tun_policy_free(&tunnel_policy);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_tcp checks passed");
    return 0;
}
