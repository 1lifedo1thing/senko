#ifndef SENKO_CORE_CONFIG_H
#define SENKO_CORE_CONFIG_H

#include "core/config.h"

#include <stddef.h>

/* render the selected profile without exposing its secrets to argv or logs */
int senko_core_config_render(const vl_server_t *server, const char *endpoint_ip,
                     const char *ifname,
                     char *out, size_t out_cap);

int senko_core_config_render_rules(const vl_server_t *server, const char *endpoint_ip,
                           const char *ifname, const ruleset_t *rules,
                           char *out, size_t out_cap);

#endif
