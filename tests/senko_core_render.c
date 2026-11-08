/* prints the senko-core json for one link, for the host check that the pinned
   core reads what senkod would hand it. usage: senko_core_render <link> <endpoint ip> */
#include <stdio.h>

#include "senko_core_config.h"

int main(int argc, char **argv) {
    static char json[2 * 1024 * 1024];
    vl_server_t s;
    if (argc < 3) return 2;
    if (cfg_parse_link(argv[1], &s) != CFG_OK) {
        fprintf(stderr, "link does not parse\n");
        return 1;
    }
    if (senko_core_config_render(&s, argv[2], "utun12", json, sizeof json) != 0) {
        fprintf(stderr, "render failed\n");
        return 1;
    }
    puts(json);
    return 0;
}
