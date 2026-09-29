#define _DEFAULT_SOURCE
#include "direct_dns.h"
#include "core/dns_msg.h"
#include "core/net_safe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}

static int wait_socket(int fd, short events, long deadline) {
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) return -1;
        struct pollfd pfd = { fd, events, 0 };
        int r = poll(&pfd, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) return -1;
        if (pfd.revents & events) return 0;
    }
}

static int make_query(const char *host, uint16_t id, uint8_t *out,
                      size_t cap, size_t *length) {
    size_t pos = 12;
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len > 253 || cap < 18) return -1;
    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8); out[1] = (uint8_t)id;
    out[2] = 1; out[5] = 1;
    const char *part = host;
    for (const char *p = host;; ++p) {
        if (*p != '.' && *p != '\0') continue;
        size_t n = (size_t)(p - part);
        if (n == 0 || n > 63 || pos > cap || cap - pos < n + 6) return -1;
        out[pos++] = (uint8_t)n;
        memcpy(out + pos, part, n);
        pos += n;
        if (!*p) break;
        part = p + 1;
    }
    out[pos++] = 0;
    out[pos++] = 0; out[pos++] = 1;
    out[pos++] = 0; out[pos++] = 1;
    *length = pos;
    return 0;
}

int direct_dns_ipv4(const direct_socket_iface_t *iface, const char *resolver,
                    uint16_t resolver_port, const char *host, int timeout_ms,
                    uint32_t *addresses, size_t capacity, size_t *count) {
    if (count) *count = 0;
    if (!iface || !resolver || !host || !addresses || !count || !capacity ||
        !resolver_port || timeout_ms <= 0 || !net_hostname_safe(host)) return -1;
    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_port = htons(resolver_port);
    if (inet_pton(AF_INET, resolver, &server.sin_addr) != 1) return -1;

    uint8_t query[272], reply[2048];
    size_t query_len = 0;
    uint16_t id = (uint16_t)(now_ms() ^ (long)getpid());
    if (make_query(host, id, query, sizeof query, &query_len) != 0) return -1;
    int fd = direct_socket_bound((void *)iface, AF_INET, SOCK_DGRAM, NULL, 0);
    if (fd < 0) return -1;
    long deadline = now_ms() + timeout_ms;
    int result = -1;
    if (connect(fd, (struct sockaddr *)&server, sizeof server) != 0 &&
        errno != EINPROGRESS) goto done;
    if (wait_socket(fd, POLLOUT, deadline) != 0) goto done;
    if (send(fd, query, query_len, 0) != (ssize_t)query_len) goto done;
    for (;;) {
        if (wait_socket(fd, POLLIN, deadline) != 0) break;
        ssize_t n = recv(fd, reply, sizeof reply, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 12) break;
        if (reply[0] != query[0] || reply[1] != query[1]) continue;
        if (!(reply[2] & 0x80) || (reply[2] & 0x02) ||
            (reply[3] & 0x0f) != 0 || reply[4] != 0 || reply[5] != 1) break;
        dns_question_t question;
        dns_response_info_t info;
        if (dns_msg_parse_response_question(reply, (size_t)n, &question) != DNS_MSG_OK ||
            question.type != 1 || question.class_code != 1 ||
            strcasecmp(question.name, host) != 0 ||
            dns_msg_response_info(reply, (size_t)n, &info) != DNS_MSG_OK) break;
        for (size_t i = 0; i < info.ipv4_count && *count < capacity; ++i) {
            struct sockaddr_in address;
            memset(&address, 0, sizeof address);
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(info.ipv4[i]);
            if (net_addr_allowed((struct sockaddr *)&address))
                addresses[(*count)++] = address.sin_addr.s_addr;
        }
        if (*count) result = 0;
        break;
    }
done:
    close(fd);
    return result;
}
