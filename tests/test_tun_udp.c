#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/dns_msg.h"
#include "packet_fixture.h"
#include "tun_loop.h"
#include "tun_udp.h"

static int failures;
static const uint8_t APP4[4] = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t DEST4[4] = { 203, 0, 113, 7 };
static const uint8_t DNS4[4] = { 192, 0, 2, 53 };
static const uint8_t UPSTREAM4[4] = { 1, 1, 1, 1 };
static const uint8_t APP6[16] = { 0xfd,0,0x5e,0x4b,0,0,0,0,0,0,0,0,0,0,0,1 };
static const uint8_t LOCAL6[16] = { 0xfd,0,0x5e,0x4b,0,0,0,0,0,0,0,0,0,0,0,2 };
static const uint8_t SYNTH6[16] = { 0xfd,0,0x5e,0x4b,0,0,0,0,0,0,0,0,0,0,0,3 };
static const uint8_t DEST6[16] = { 0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,7 };
static const uint8_t UUID[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
#define GENERATION 19

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static int read_full(int fd, uint8_t *out, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

#define SERVER_CONNS 8

static struct {
    int listen_fd;
    uint16_t port;
    pthread_t thread;
    pthread_mutex_t lock;
    int accepted;
    int handled;
    int invalid;
    int datagrams[SERVER_CONNS];
    uint8_t destinations[SERVER_CONNS][16];
    uint8_t address_lens[SERVER_CONNS];
    uint16_t ports[SERVER_CONNS];
} server;

/* answers every datagram of one association until the relay closes it; the
   response header rides on the first answer, as xray sends it */
static int serve_one(int fd, int index) {
    uint8_t head[18];
    if (read_full(fd, head, sizeof head) != 0 || head[0] != 0 ||
        memcmp(head + 1, UUID, sizeof UUID) != 0) return -1;
    uint8_t addons[255];
    if (head[17] && read_full(fd, addons, head[17]) != 0) return -1;
    uint8_t request[4];
    if (read_full(fd, request, sizeof request) != 0 || request[0] != VLESS_CMD_UDP)
        return -1;
    uint16_t port = pkt_rd16(request + 1);
    size_t addr_len = request[3] == 1 ? 4u : request[3] == 3 ? 16u : 0u;
    if (!addr_len || read_full(fd, server.destinations[index], addr_len) != 0)
        return -1;
    server.address_lens[index] = (uint8_t)addr_len;
    server.ports[index] = port;
    int header_sent = 0;
    for (;;) {
        uint8_t length[2];
        ssize_t got = read(fd, length, 1);
        if (got == 0) return 0;
        if (got != 1 || read_full(fd, length + 1, 1) != 0) return -1;
        size_t payload_len = pkt_rd16(length);
        if (payload_len == 0 || payload_len > 1500) return -1;
        uint8_t payload[1500];
        if (read_full(fd, payload, payload_len) != 0) return -1;
        uint8_t answer[1500];
        size_t answer_len = payload_len;
        if (port == 53) {
            if (dns_msg_build_block(payload, payload_len, DNS_BLOCK_NXDOMAIN,
                                    answer, sizeof answer, &answer_len) != DNS_MSG_OK)
                return -1;
        } else {
            memcpy(answer, payload, payload_len);
        }
        uint8_t response[4] = { 0, 0, (uint8_t)(answer_len >> 8), (uint8_t)answer_len };
        const uint8_t *head = header_sent ? response + 2 : response;
        size_t head_len = header_sent ? 2u : 4u;
        if (write_full(fd, head, head_len) != 0 ||
            write_full(fd, answer, answer_len) != 0) return -1;
        header_sent = 1;
        pthread_mutex_lock(&server.lock);
        ++server.datagrams[index];
        pthread_mutex_unlock(&server.lock);
    }
}

static int conn_fds[SERVER_CONNS];

static void *serve_thread(void *ctx) {
    int index = (int)(intptr_t)ctx;
    int good = serve_one(conn_fds[index], index) == 0;
    close(conn_fds[index]);
    pthread_mutex_lock(&server.lock);
    ++server.handled;
    if (!good) ++server.invalid;
    pthread_mutex_unlock(&server.lock);
    return NULL;
}

static void *server_main(void *ctx) {
    (void)ctx;
    pthread_t threads[SERVER_CONNS];
    int count = 0;
    for (;;) {
        int fd = accept(server.listen_fd, NULL, NULL);
        if (fd < 0) break;
        if (count == SERVER_CONNS) {
            close(fd);
            pthread_mutex_lock(&server.lock);
            ++server.invalid;
            pthread_mutex_unlock(&server.lock);
            continue;
        }
        conn_fds[count] = fd;
        pthread_mutex_lock(&server.lock);
        ++server.accepted;
        pthread_mutex_unlock(&server.lock);
        pthread_create(&threads[count], NULL, serve_thread, (void *)(intptr_t)count);
        ++count;
    }
    for (int i = 0; i < count; ++i) pthread_join(threads[i], NULL);
    return NULL;
}

static int dial_server(void *ctx, char *error, size_t error_cap) {
    (void)ctx;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(server.port);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) == 0)
        return fd;
    snprintf(error, error_cap, "local VLESS test server refused connect");
    close(fd);
    return -1;
}

static struct {
    tun_loop_t *loop;
    tun_udp_t *udp;
    utun_device_t device;
    int peer;
    pthread_t thread;
    tun_loop_result_t result;
} tunnel;

static void *run_loop(void *ctx) {
    (void)ctx;
    (void)tun_loop_run(tunnel.loop, &tunnel.result);
    return NULL;
}

static size_t query(uint8_t *out, uint16_t id) {
    static const uint8_t name[] = { 3,'w','w','w',7,'e','x','a','m','p','l','e',0 };
    memset(out, 0, 64);
    pkt_wr16(out, id); out[2] = 1; out[5] = 1;
    memcpy(out + 12, name, sizeof name);
    size_t n = 12 + sizeof name;
    out[n++] = 0; out[n++] = 1;
    out[n++] = 0; out[n++] = 1;
    return n;
}

static size_t exchange(const uint8_t *packet, size_t packet_len,
                       uint8_t *answer, size_t cap) {
    uint8_t frame[TUN_STACK_FRAME_MAX];
    size_t len = pkt_frame(frame, packet, packet_len);
    if (send(tunnel.peer, frame, len, 0) != (ssize_t)len) return 0;
    struct pollfd pfd = { tunnel.peer, POLLIN, 0 };
    if (poll(&pfd, 1, 3000) <= 0) return 0;
    ssize_t got = recv(tunnel.peer, answer, cap, 0);
    return got > 0 ? (size_t)got : 0;
}

int main(void) {
    memset(&server, 0, sizeof server);
    pthread_mutex_init(&server.lock, NULL);
    server.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok("server bind", bind(server.listen_fd, (struct sockaddr *)&address,
                           sizeof address) == 0);
    socklen_t address_len = sizeof address;
    getsockname(server.listen_fd, (struct sockaddr *)&address, &address_len);
    server.port = ntohs(address.sin_port);
    listen(server.listen_fd, 4);
    pthread_create(&server.thread, NULL, server_main, NULL);

    int fds[2];
    ok("device socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    tunnel.peer = fds[1];
    utun_device_init(&tunnel.device);
    ok("device adopted", utun_device_adopt(&tunnel.device, fds[0], "utun8") ==
                         UTUN_DEVICE_OK);
    tun_loop_config_t config;
    memset(&config, 0, sizeof config);
    config.generation = GENERATION;
    config.stack.mtu = 1500;
    config.stack.have_ipv4 = 1;
    memcpy(config.stack.address4, LOCAL4, 4);
    memcpy(config.stack.synthetic4, SYNTH4, 4);
    memset(config.stack.netmask4, 255, 4);
    config.stack.have_ipv6 = 1;
    memcpy(config.stack.address6, LOCAL6, 16);
    memcpy(config.stack.synthetic6, SYNTH6, 16);
    tun_udp_config_t udp;
    memset(&udp, 0, sizeof udp);
    udp.vt = &transport_tcp;
    memcpy(udp.uuid, UUID, sizeof UUID);
    udp.dial = dial_server;
    udp.opener_threads = 1;
    memcpy(udp.dns_upstream, UPSTREAM4, 4);
    udp.dns_upstream_len = 4;
    udp.block_response = DNS_BLOCK_NXDOMAIN;
    tunnel.udp = malloc(tun_udp_size());
    ok("udp relay configured", tun_udp_init(tunnel.udp, &udp, &config) == 0);
    tunnel.loop = malloc(tun_loop_size());
    ok("tunnel initialized", tun_loop_init(tunnel.loop, &config,
                                           &tunnel.device) == TUN_LOOP_OK);
    tun_udp_bind(tunnel.udp, tunnel.loop, GENERATION);
    pthread_create(&tunnel.thread, NULL, run_loop, NULL);

    uint8_t packet[1600], frame[TUN_STACK_FRAME_MAX];
    const uint8_t hello[] = { 'h','e','l','l','o' };
    size_t len = pkt_udp4(packet, APP4, 51001, DEST4, 9999,
                          hello, sizeof hello);
    size_t got = exchange(packet, len, frame, sizeof frame);
    ok("udp4 response arrived", got == 4 + 20 + 8 + sizeof hello);
    ok("udp4 original tuple and checksum", got &&
       memcmp(frame + 4 + 12, DEST4, 4) == 0 &&
       pkt_rd16(frame + 4 + 20) == 9999 &&
       pkt_l4_valid(frame + 4, got - 4) &&
       memcmp(frame + 4 + 28, hello, sizeof hello) == 0);

    len = pkt_udp6(packet, APP6, 51002, DEST6, 9999, hello, sizeof hello);
    got = exchange(packet, len, frame, sizeof frame);
    ok("udp6 response arrived", got == 4 + 40 + 8 + sizeof hello);
    ok("udp6 original tuple and checksum", got && frame[3] == 30 &&
       memcmp(frame + 4 + 8, DEST6, 16) == 0 &&
       pkt_l4_valid(frame + 4, got - 4));

    uint8_t dns_query[64];
    size_t dns_len = query(dns_query, 0x1234);
    len = pkt_udp4(packet, APP4, 51003, DNS4, 53, dns_query, dns_len);
    got = exchange(packet, len, frame, sizeof frame);
    ok("dns proxy response arrived", got > 4 + 28 + dns_len);
    ok("dns response uses original resolver tuple", got &&
       memcmp(frame + 4 + 12, DNS4, 4) == 0 &&
       pkt_rd16(frame + 4 + 20) == 53 &&
       pkt_l4_valid(frame + 4, got - 4) &&
       frame[4 + 28 + 3] % 16 == 3);

    /* each lookup comes from its own port, as resolvers send them */
    enum { BURST = 12 };
    for (int i = 0; i < BURST; ++i) {
        dns_len = query(dns_query, (uint16_t)(0x2000 + i));
        len = pkt_udp4(packet, APP4, (uint16_t)(52000 + i), DNS4, 53,
                       dns_query, dns_len);
        size_t frame_len = pkt_frame(frame, packet, len);
        send(tunnel.peer, frame, frame_len, 0);
    }
    int answered[BURST] = {0};
    int matched = 0;
    for (int n = 0; n < BURST; ++n) {
        struct pollfd pfd = { tunnel.peer, POLLIN, 0 };
        if (poll(&pfd, 1, 3000) <= 0) break;
        ssize_t r = recv(tunnel.peer, frame, sizeof frame, 0);
        if (r < 4 + 28 + 2) continue;
        int port_index = (int)pkt_rd16(frame + 4 + 22) - 52000;
        int id_index = (int)pkt_rd16(frame + 4 + 28) - 0x2000;
        if (port_index >= 0 && port_index < BURST && port_index == id_index &&
            !answered[port_index] && pkt_l4_valid(frame + 4, (size_t)r - 4)) {
            answered[port_index] = 1;
            ++matched;
        }
    }
    ok("every lookup from its own port gets its own answer", matched == BURST);

    tun_loop_command_t stop = { TUN_LOOP_CMD_STOP, GENERATION, 0 };
    tun_loop_post(tunnel.loop, &stop);
    pthread_join(tunnel.thread, NULL);
    shutdown(server.listen_fd, SHUT_RDWR);
    pthread_join(server.thread, NULL);
    ok("server saw three associations and no bad frame",
       server.accepted == 3 && server.handled == 3 && server.invalid == 0);
    ok("all lookups shared one server connection", server.datagrams[2] == 1 + BURST);
    ok("server saw DNS upstream, not local resolver", server.ports[2] == 53 &&
       server.address_lens[2] == 4 &&
       memcmp(server.destinations[2], UPSTREAM4, 4) == 0);
    ok("server saw ipv6 destination", server.address_lens[1] == 16 &&
       memcmp(server.destinations[1], DEST6, 16) == 0);
    ok("loop stopped cleanly", tunnel.result.end == TUN_LOOP_ENDED_STOP);
    tun_loop_destroy(tunnel.loop);
    free(tunnel.loop);
    free(tunnel.udp);
    close(tunnel.peer);
    close(server.listen_fd);

    if (failures) {
        fprintf(stderr, "%d tun_udp check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_udp checks passed");
    return 0;
}
