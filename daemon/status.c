#include "status.h"

#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
#include <fcntl.h>
#include <notify.h>
#include <unistd.h>

static const char k_state_path[] =
    "/var/mobile/Library/Preferences/com.senko.status.state";
static const char k_notify_name[] = "com.senko.status.changed";
#endif

static void write_state(const char *body) {
#if defined(__APPLE__)
    int fd = open(k_state_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        (void)write(fd, body, strlen(body));
        close(fd);
    }
    (void)notify_post(k_notify_name);
#else
    (void)body;
#endif
}

void status_set(int enabled) {
    write_state(enabled ? "1\n" : "0\n");
}

void status_set_on(const char *physical_ifname) {
    char body[32];
    if (!physical_ifname || !physical_ifname[0] || strlen(physical_ifname) > 16) {
        write_state("1\n");
        return;
    }
    snprintf(body, sizeof body, "1 %s\n", physical_ifname);
    write_state(body);
}
