#define _DEFAULT_SOURCE

#include "transport.h"

#include <fcntl.h>
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

static int open_pair(const transport_tls_cfg_t *cfg) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return -1;
    int flags = fcntl(pair[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pair[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    void *handle = transport_tls.open(pair[0], cfg);
    if (handle) transport_tls.close(handle);
    close(pair[0]);
    close(pair[1]);
    return handle ? 1 : 0;
}

int main(void) {
    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.peer_host = "example.test";
    transport_tls_shared_t *shared = transport_tls_shared_create(&cfg);
    check("shared trust context", shared != NULL);
    cfg.shared_ctx = shared;
    if (shared) {
        check("first verified connection", open_pair(&cfg) == 1);
        check("second verified connection", open_pair(&cfg) == 1);
        cfg.sni = "203.0.113.7";
        check("ip identity", open_pair(&cfg) == 1);
        cfg.sni = NULL;
        cfg.peer_host = NULL;
        check("missing verified identity rejected", open_pair(&cfg) == 0);
    }
    transport_tls_shared_destroy(shared);
    cfg.shared_ctx = NULL;
    cfg.insecure = 1;
    check("explicit insecure setting remains explicit", open_pair(&cfg) == 1);
    if (failures) return 1;
    puts("all shared tls checks passed");
    return 0;
}
