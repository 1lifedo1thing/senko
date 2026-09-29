#include "app_proxy.h"

#include "route_socket.h"
#include "../common/senko_paths.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* senkotlsfix reads this exact path and first word */
#define APP_PROXY_STATE "/var/run/senko-c-proxy"

int app_proxy_available(void) {
    return access(SENKO_SUBSTRATE_DIR "/senkotlsfix.dylib", R_OK) == 0;
}

int app_proxy_start(app_proxy_t *proxy, int socks_port, char *reason, size_t reason_cap) {
    if (reason && reason_cap) reason[0] = '\0';
    if (!proxy || socks_port <= 0 || socks_port > 65535) return -1;
    if (!app_proxy_available()) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "the connect hook is not installed (%s)",
                     SENKO_SUBSTRATE_DIR "/senkotlsfix.dylib");
        return -1;
    }
    char tmp[128];
    int n = snprintf(tmp, sizeof tmp, "%s.%ld", APP_PROXY_STATE, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    char value[64];
    n = snprintf(value, sizeof value, "SENKO-C-PROXY-V1 %d\n", socks_port);
    int ok = fd >= 0 && n > 0 && (size_t)n < sizeof value &&
             fchmod(fd, 0644) == 0 && write(fd, value, (size_t)n) == n && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = 0;
    if (ok) ok = rename(tmp, APP_PROXY_STATE) == 0;
    if (!ok) {
        int saved = errno;
        (void)unlink(tmp);
        if (reason && reason_cap) {
            snprintf(reason, reason_cap, "cannot publish the socks port in %s",
                     APP_PROXY_STATE);
            route_errno_append(reason, reason_cap, saved);
        }
        return -1;
    }
    proxy->active = 1;
    proxy->socks_port = socks_port;
    fprintf(stderr, "senkod: connect hook sends hooked apps to 127.0.0.1:%d\n", socks_port);
    return 0;
}

void app_proxy_stop(app_proxy_t *proxy) {
    if (!proxy || !proxy->active) return;
    if (unlink(APP_PROXY_STATE) != 0 && errno != ENOENT)
        fprintf(stderr, "senkod: cannot remove %s (errno %d %s)\n", APP_PROXY_STATE,
                errno, strerror(errno));
    memset(proxy, 0, sizeof *proxy);
}
