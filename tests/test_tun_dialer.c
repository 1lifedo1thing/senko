#define _DEFAULT_SOURCE

#include "tun_dialer.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int condition) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL %s\n", name);
    }
}

int main(void) {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    check("server socket", server >= 0);
    if (server < 0) return 1;
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check("bind", bind(server, (struct sockaddr *)&address, sizeof address) == 0);
    socklen_t address_len = sizeof address;
    check("server address", getsockname(server, (struct sockaddr *)&address,
                                        &address_len) == 0);
    check("listen", listen(server, 2) == 0);

    uint8_t endpoints[2][16] = {{127, 0, 0, 2}, {127, 0, 0, 1}};
    uint8_t lens[2] = {4, 4};
    tun_dialer_t dialer;
    check("init pinned endpoints",
          tun_dialer_init(&dialer, endpoints, lens, 2,
                          ntohs(address.sin_port), 2000) == 0);
    char error[192];
    int first = tun_dialer_connect(&dialer, error, sizeof error);
    check("second endpoint connects after first refusal", first >= 0);
    if (first >= 0) {
        int accepted = accept(server, NULL, NULL);
        check("first accepted", accepted >= 0);
        if (accepted >= 0) close(accepted);
        close(first);
    }
    check("failed endpoint cooled down", dialer.pool.entries[0].failures == 1);
    check("working endpoint remembered", dialer.pool.last_good == 1);

    int second = tun_dialer_connect(&dialer, error, sizeof error);
    check("remembered endpoint connects", second >= 0);
    if (second >= 0) {
        int accepted = accept(server, NULL, NULL);
        check("second accepted", accepted >= 0);
        if (accepted >= 0) close(accepted);
        close(second);
    }
    check("cooling endpoint not retried", dialer.pool.entries[0].failures == 1);
    tun_dialer_cancel(&dialer);
    check("cancel prevents a new connect",
          tun_dialer_connect(&dialer, error, sizeof error) < 0 &&
          strstr(error, "cancelled") != NULL);
    tun_dialer_destroy(&dialer);

    /* the listener is gone: the message names the address, port and errno */
    uint16_t closed_port = ntohs(address.sin_port);
    close(server);
    uint8_t lone[1][16] = {{127, 0, 0, 1}};
    uint8_t lone_len[1] = {4};
    check("init single endpoint",
          tun_dialer_init(&dialer, lone, lone_len, 1, closed_port, 2000) == 0);
    char expected[64];
    snprintf(expected, sizeof expected, "127.0.0.1 port %u", (unsigned)closed_port);
    check("refused connect explains itself",
          tun_dialer_connect(&dialer, error, sizeof error) < 0 &&
          strstr(error, expected) != NULL && strstr(error, "ECONNREFUSED") != NULL);
    tun_dialer_destroy(&dialer);

    check("empty endpoint list rejected",
          tun_dialer_init(&dialer, endpoints, lens, 0, 443, 2000) != 0);
    if (failures) return 1;
    puts("all tun dialer checks passed");
    return 0;
}
