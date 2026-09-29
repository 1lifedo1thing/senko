#include <stdio.h>
#include <string.h>

#include "vless_udp.h"

static int failures;

static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static vless_dest_t target(void) {
    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV4;
    dest.host_addr[0] = 203;
    dest.host_addr[1] = 0;
    dest.host_addr[2] = 113;
    dest.host_addr[3] = 7;
    dest.port = 53;
    return dest;
}

int main(void) {
    vless_dest_t dest = target(), source;
    vless_udp_t writer, reader;
    uint8_t frame[1600];
    size_t frame_len = 0, consumed = 0, payload_len = 0;
    const uint8_t *payload = NULL;
    const uint8_t query[] = { 0x12, 0x34, 0x01, 0x00 };
    vless_request_t request;
    memset(&request, 0, sizeof request);
    request.dest = dest;
    request.cmd = VLESS_CMD_UDP;
    check("vless udp header", vless_build_request(&request, frame,
          sizeof frame, &frame_len) == VLESS_OK && frame_len == 26 &&
          frame[18] == VLESS_CMD_UDP && frame[19] == 0 && frame[20] == 53 &&
          frame[21] == VLESS_ADDR_IPV4);
    request.cmd = VLESS_CMD_MUX;
    check("xudp mux header has no destination", vless_build_request(&request,
          frame, sizeof frame, &frame_len) == VLESS_OK && frame_len == 19 &&
          frame[18] == VLESS_CMD_MUX);
    request.cmd = (vless_cmd_t)0x7f;
    check("unknown command rejected", vless_build_request(&request,
          frame, sizeof frame, &frame_len) == VLESS_ERR_BAD_ARG);
    request.cmd = VLESS_CMD_TCP;
    char oversized_flow[255];
    memset(oversized_flow, 'x', sizeof oversized_flow - 1);
    oversized_flow[sizeof oversized_flow - 1] = '\0';
    request.flow = oversized_flow;
    check("addon length cannot wrap", vless_build_request(&request,
          frame, sizeof frame, &frame_len) == VLESS_ERR_BAD_ARG);

    check("length writer init", vless_udp_init(&writer, VLESS_UDP_LENGTH,
                                                &dest) == VLESS_UDP_OK);
    check("length reader init", vless_udp_init(&reader, VLESS_UDP_LENGTH,
                                                &dest) == VLESS_UDP_OK);
    check("length frame", vless_udp_encode(&writer, query, sizeof query,
          frame, sizeof frame, &frame_len) == VLESS_UDP_OK &&
          frame_len == 6 && frame[0] == 0 && frame[1] == 4);
    check("length split header", vless_udp_feed(&reader, frame, 1, &consumed,
          &payload, &payload_len, &source) == VLESS_UDP_NEED_MORE && consumed == 1);
    check("length split body", vless_udp_feed(&reader, frame + 1, frame_len - 1,
          &consumed, &payload, &payload_len, &source) == VLESS_UDP_OK &&
          consumed == frame_len - 1 && payload_len == sizeof query &&
          memcmp(payload, query, sizeof query) == 0 && source.port == 53);
    uint8_t two[12];
    memcpy(two, frame, frame_len);
    memcpy(two + frame_len, frame, frame_len);
    check("first of coalesced frames", vless_udp_feed(&reader, two, sizeof two,
          &consumed, &payload, &payload_len, &source) == VLESS_UDP_OK &&
          consumed == frame_len);
    check("second of coalesced frames", vless_udp_feed(&reader, two + consumed,
          sizeof two - consumed, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_OK && consumed == frame_len);
    check("empty datagram rejected", vless_udp_encode(&writer, query, 0,
          frame, sizeof frame, &frame_len) == VLESS_UDP_ERR_ARG);
    check("short output does not consume first frame", vless_udp_encode(&writer,
          query, sizeof query, frame, 5, &frame_len) == VLESS_UDP_ERR_SPACE &&
          frame_len == 0);

    check("xudp writer init", vless_udp_init(&writer, VLESS_UDP_XUDP,
                                              &dest) == VLESS_UDP_OK);
    check("short xudp output preserves new session", vless_udp_encode(&writer,
          query, sizeof query, frame, 10, &frame_len) == VLESS_UDP_ERR_SPACE &&
          frame_len == 0 && writer.sent_first == 0);
    check("xudp new frame", vless_udp_encode(&writer, query, sizeof query,
          frame, sizeof frame, &frame_len) == VLESS_UDP_OK &&
          frame_len == 28 && frame[0] == 0 && frame[1] == 20 &&
          frame[4] == 1 && frame[5] == 1 && frame[6] == 2 &&
          frame[7] == 0 && frame[8] == 53 && frame[9] == 1 &&
          memcmp(frame + 10, dest.host_addr, 4) == 0 &&
          frame[22] == 0 && frame[23] == 4);
    check("xudp keep frame", vless_udp_encode(&writer, query, sizeof query,
          frame, sizeof frame, &frame_len) == VLESS_UDP_OK &&
          frame_len == 12 && frame[1] == 4 && frame[4] == 2 &&
          frame[5] == 1 && frame[6] == 0 && frame[7] == 4);

    check("xudp reader init", vless_udp_init(&reader, VLESS_UDP_XUDP,
                                              &dest) == VLESS_UDP_OK);
    check("xudp split meta", vless_udp_feed(&reader, frame, 5, &consumed,
          &payload, &payload_len, &source) == VLESS_UDP_NEED_MORE && consumed == 5);
    check("xudp split payload", vless_udp_feed(&reader, frame + 5, 7,
          &consumed, &payload, &payload_len, &source) == VLESS_UDP_OK &&
          consumed == 7 && payload_len == sizeof query &&
          memcmp(payload, query, sizeof query) == 0 && source.port == 53);

    uint8_t addressed[] = {
        0, 12, 0, 0, 2, 1, 2, 0x01, 0xbb, 1, 192, 0, 2, 9,
        0, 2, 0xab, 0xcd
    };
    check("xudp answer names its source", vless_udp_feed(&reader, addressed,
          sizeof addressed, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_OK && consumed == sizeof addressed &&
          source.port == 443 && source.atyp == VLESS_ADDR_IPV4 &&
          source.host_addr[0] == 192 && source.host_addr[3] == 9 &&
          payload_len == 2 && payload[0] == 0xab);
    addressed[4] = 1;
    check("xudp new command from server rejected", vless_udp_feed(&reader,
          addressed, sizeof addressed, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_ERR_FRAME);
    vless_udp_init(&reader, VLESS_UDP_XUDP, &dest);
    const uint8_t keepalive_frame[] = { 0, 4, 0, 0, 4, 0 };
    check("xudp keepalive control is consumed", vless_udp_feed(&reader,
          keepalive_frame, sizeof keepalive_frame, &consumed, &payload,
          &payload_len, &source) == VLESS_UDP_SKIPPED &&
          consumed == sizeof keepalive_frame);
    const uint8_t end_frame[] = { 0, 4, 0, 0, 3, 0 };
    check("xudp end closes the association", vless_udp_feed(&reader, end_frame,
          sizeof end_frame, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_END && consumed == sizeof end_frame);
    vless_udp_init(&reader, VLESS_UDP_XUDP, &dest);
    const uint8_t error_end[] = { 0, 4, 0, 0, 3, 2 };
    check("xudp end with the error flag closes too", vless_udp_feed(&reader,
          error_end, sizeof error_end, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_END && consumed == sizeof error_end);
    vless_udp_init(&reader, VLESS_UDP_XUDP, &dest);
    const uint8_t empty_frame[] = { 0, 4, 0, 0, 2, 1, 0, 0 };
    check("xudp empty keep is consumed", vless_udp_feed(&reader, empty_frame,
          sizeof empty_frame, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_SKIPPED && consumed == sizeof empty_frame);

    vless_dest_t dest6;
    memset(&dest6, 0, sizeof dest6);
    dest6.atyp = VLESS_ADDR_IPV6;
    dest6.host_addr[0] = 0x20;
    dest6.host_addr[1] = 0x01;
    dest6.host_addr[2] = 0x0d;
    dest6.host_addr[3] = 0xb8;
    dest6.host_addr[15] = 7;
    dest6.port = 5353;
    check("xudp ipv6 init", vless_udp_init(&writer, VLESS_UDP_XUDP,
                                            &dest6) == VLESS_UDP_OK);
    check("xudp ipv6 metadata", vless_udp_encode(&writer, query, sizeof query,
          frame, sizeof frame, &frame_len) == VLESS_UDP_OK &&
          frame_len == 40 && frame[1] == 32 && frame[7] == 0x14 &&
          frame[8] == 0xe9 && frame[9] == 3 &&
          memcmp(frame + 10, dest6.host_addr, 16) == 0);

    vless_udp_init(&reader, VLESS_UDP_LENGTH, &dest);
    const uint8_t zero[] = { 0, 0 };
    check("zero length is malformed", vless_udp_feed(&reader, zero, sizeof zero,
          &consumed, &payload, &payload_len, &source) == VLESS_UDP_ERR_FRAME);
    vless_udp_init(&reader, VLESS_UDP_LENGTH, &dest);
    const uint8_t huge[] = { 0x05, 0xdd };
    check("oversized length is malformed", vless_udp_feed(&reader, huge,
          sizeof huge, &consumed, &payload, &payload_len,
          &source) == VLESS_UDP_ERR_FRAME);

    if (failures) {
        fprintf(stderr, "%d vless udp check(s) failed\n", failures);
        return 1;
    }
    puts("all vless udp checks passed");
    return 0;
}
