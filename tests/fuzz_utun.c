#include "utun_frame.h"

#include <stdint.h>
#include <string.h>

/* the utun read path takes whatever the kernel hands it, so the framing and
   the ip header bounds are fed raw bytes here */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *packet = NULL;
    size_t packet_len = 0;
    uint8_t address_len = 0;

    if (utun_frame_parse(data, size, &packet, &packet_len, &address_len) !=
        UTUN_FRAME_OK)
        return 0;

    /* whatever parsed has to survive the outbound header and parse again to
       the same bytes */
    static uint8_t rebuilt[UTUN_FRAME_MAX];
    if (utun_frame_header(packet[0], rebuilt) != UTUN_FRAME_OK) __builtin_trap();
    memcpy(rebuilt + UTUN_FRAME_HEADER_LEN, packet, packet_len);

    const uint8_t *again = NULL;
    size_t again_len = 0;
    uint8_t again_family = 0;
    if (utun_frame_parse(rebuilt, packet_len + UTUN_FRAME_HEADER_LEN, &again,
                         &again_len, &again_family) != UTUN_FRAME_OK ||
        again_len != packet_len || again_family != address_len ||
        memcmp(again, packet, packet_len) != 0)
        __builtin_trap();
    return 0;
}
