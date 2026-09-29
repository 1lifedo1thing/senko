#ifndef SENKO_EGRESS_H
#define SENKO_EGRESS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the physical interface traffic leaves by and its ipv4 address: wifi first,
   then cellular, the order the kernel installs the default route in. probes
   bind to it so they measure the network, not the tunnel. 0 when found */
int egress_snapshot(char *name, size_t name_cap, char *ip, size_t ip_cap);

#ifdef __cplusplus
}
#endif

#endif
