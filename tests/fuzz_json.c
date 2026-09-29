#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1024 * 1024) return 0;
    vl_server_t servers[64];
    size_t count = 0;
    (void)cfg_parse_subscription((const char *)data, size, servers,
                                 64, &count);
    /* the same bytes as the first part of a feed the fetch cut */
    char *cut = malloc(size ? size : 1);
    size_t len = size;
    if (!cut) return 0;
    memcpy(cut, data, size);
    if (cfg_subscription_prefix(cut, &len) == 0 && len <= size)
        (void)cfg_parse_subscription(cut, len, servers, 64, &count);
    free(cut);
    return 0;
}
