#define _DEFAULT_SOURCE
#include "../daemon/direct_dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct { int fd; int malformed; } server_t;

static void *reply_once(void *arg) {
    server_t *server = arg;
    uint8_t query[512], reply[512];
    struct sockaddr_in client;
    socklen_t size = sizeof client;
    ssize_t n = recvfrom(server->fd, query, sizeof query, 0,
                         (struct sockaddr *)&client, &size);
    assert(n > 18 && n < (ssize_t)sizeof reply - 16);
    memcpy(reply, query, (size_t)n);
    reply[2] = 0x81; reply[3] = 0x80;
    reply[6] = 0; reply[7] = 1;
    size_t at = (size_t)n;
    const uint8_t answer[] = {0xc0,0x0c, 0,1, 0,1, 0,0,0,30, 0,4, 1,1,1,1};
    memcpy(reply + at, answer, sizeof answer);
    at += sizeof answer;
    if (server->malformed) reply[0] ^= 1;
    assert(sendto(server->fd, reply, at, 0, (struct sockaddr *)&client, size) ==
           (ssize_t)at);
    return NULL;
}

static void check_lookup(int malformed, const char *host) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof listen_addr);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr *)&listen_addr, sizeof listen_addr) == 0);
    socklen_t size = sizeof listen_addr;
    assert(getsockname(fd, (struct sockaddr *)&listen_addr, &size) == 0);
    server_t server = { fd, malformed };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, reply_once, &server) == 0);
    direct_socket_iface_t iface;
    memset(&iface, 0, sizeof iface);
    iface.ifindex = 1;
    uint32_t addresses[2] = {0, 0};
    size_t count = 9;
    int rc = direct_dns_ipv4(&iface, "127.0.0.1", ntohs(listen_addr.sin_port),
                             host, 500,
                             addresses, 2, &count);
    assert(pthread_join(thread, NULL) == 0);
    assert(rc == (malformed ? -1 : 0));
    assert(count == (malformed ? 0u : 1u));
    if (!malformed) assert(addresses[0] == htonl(0x01010101u));
    close(fd);
}

int main(void) {
    check_lookup(0, "connect.alpha-network.org");
    check_lookup(1, "connect.alpha-network.org");
    uint32_t addresses[1];
    size_t count = 9;
    direct_socket_iface_t iface;
    memset(&iface, 0, sizeof iface);
    iface.ifindex = 1;
    assert(direct_dns_ipv4(&iface, "127.0.0.1", 53, "bad..name", 50,
                           addresses, 1, &count) == -1);
    assert(count == 0);
    char many_labels[254];
    for (size_t i = 0; i < sizeof many_labels - 1; ++i)
        many_labels[i] = i % 2 ? '.' : 'a';
    many_labels[sizeof many_labels - 1] = '\0';
    check_lookup(0, many_labels);
    puts("direct dns ok");
    return 0;
}
