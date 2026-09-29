#ifndef SENKO_DIRECT_DNS_H
#define SENKO_DIRECT_DNS_H

#include "direct_socket.h"
#include <stddef.h>
#include <stdint.h>

/* resolve over the selected physical interface after the system resolver has
   become unreachable through a failed tunnel */
int direct_dns_ipv4(const direct_socket_iface_t *iface, const char *resolver,
                    uint16_t resolver_port, const char *host, int timeout_ms,
                    uint32_t *addresses, size_t capacity, size_t *count);

#endif
