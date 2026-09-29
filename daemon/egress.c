#define _DEFAULT_SOURCE

#include "egress.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int egress_snapshot(char *name, size_t name_cap, char *ip, size_t ip_cap) {
    struct ifaddrs *ifa = NULL;
    if (name && name_cap) name[0] = '\0';
    if (ip && ip_cap) ip[0] = '\0';
    if (!name || name_cap < 2 || !ip || ip_cap < INET_ADDRSTRLEN) return -1;
    if (getifaddrs(&ifa) != 0) return -1;

    int best = 0; /* 2 is wifi, 1 is cellular */
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_name || !p->ifa_addr) continue;
        if (p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        int rank = 0;
        if (strncmp(p->ifa_name, "en", 2) == 0) rank = 2;
        else if (strncmp(p->ifa_name, "pdp_ip", 6) == 0) rank = 1;
        if (rank <= best) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
        char addr[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof addr)) continue;
        /* a self-assigned address means the interface is up without a usable route */
        if (strncmp(addr, "169.254.", 8) == 0) continue;
        snprintf(name, name_cap, "%s", p->ifa_name);
        snprintf(ip, ip_cap, "%s", addr);
        best = rank;
    }
    freeifaddrs(ifa);
    return best ? 0 : -1;
}
