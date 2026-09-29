#define _DEFAULT_SOURCE

#include "session.h"
#include "socks5.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

typedef struct {
    const uint8_t *rx;
    size_t rx_len;
    int rx_done;
    int write_calls;
    int raw_calls;
    int mark_calls;
    uint8_t write_buf[2048];
    size_t write_len;
    uint8_t raw_buf[64];
    size_t raw_len;
    uint8_t last_write[64];
    size_t last_len;
} fake_transport_t;

static void *fake_open(int fd, const transport_tls_cfg_t *cfg) {
    (void)fd;
    (void)cfg;
    return NULL;
}

static int fake_read(void *h, uint8_t *buf, size_t len) {
    fake_transport_t *ft = (fake_transport_t *)h;
    if (ft->rx_done) return TRANSPORT_WANT_READ;
    size_t n = ft->rx_len < len ? ft->rx_len : len;
    memcpy(buf, ft->rx, n);
    ft->rx_done = 1;
    return (int)n;
}

static int fake_write(void *h, const uint8_t *buf, size_t len) {
    fake_transport_t *ft = (fake_transport_t *)h;
    /* len 0 is a flush probe (reality wpend); not a real app write */
    if (len == 0) return 0;
    if (len <= sizeof ft->write_buf - ft->write_len) {
        memcpy(ft->write_buf + ft->write_len, buf, len);
        ft->write_len += len;
    }
    ft->last_len = len < sizeof ft->last_write ? len : sizeof ft->last_write;
    memcpy(ft->last_write, buf, ft->last_len);
    ft->write_calls++;
    return (int)len;
}

static int fake_raw_write(void *h, const uint8_t *buf, size_t len) {
    fake_transport_t *ft = (fake_transport_t *)h;
    if (len == 0) {
        ft->mark_calls++;
        return 0;
    }
    ft->raw_calls++;
    if (len > sizeof ft->raw_buf) len = sizeof ft->raw_buf;
    memcpy(ft->raw_buf, buf, len);
    ft->raw_len = len;
    return (int)len;
}

static void fake_close(void *h) {
    (void)h;
}

static const transport_vt_t fake_vt = {
    fake_open, fake_read, fake_write, fake_raw_write, fake_close, NULL, NULL
};

/* trojan and shadowsocks carry no distinct response header, so the local
   socks client only learns the tunnel is up from the connect reply below */
static void check_socks_connect_ack(vl_proto_t proto, const char *user,
                                    const char *pass, const char *what) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;

    session_t s;
    ok(what, session_init(&s, &fake_vt, &ft, proto, NULL, NULL, user, pass) == SESS_OK);

    uint8_t greet[] = {0x05, 0x01, 0x00};
    size_t consumed = 0;
    ok(what, session_feed_client(&s, greet, sizeof greet, &consumed) == SESS_OK);
    ok(what, consumed == sizeof greet);

    uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb};
    ok(what, session_feed_client(&s, req, sizeof req, &consumed) == SESS_OK);
    ok(what, s.state == SESS_RELAY);

    uint8_t out[32];
    size_t got = session_take_client(&s, out, sizeof out);
    uint8_t expect[12] = {0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    ok(what, got == sizeof expect && memcmp(out, expect, sizeof expect) == 0);

    printf("ok %s\n", what);
}

static void check_transparent(vl_proto_t proto, const char *user,
                              const char *pass, const char *what) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;
    session_t s;
    ok(what, session_init(&s, &fake_vt, &ft, proto, NULL, NULL,
                          user, pass) == SESS_OK);
    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV4;
    dest.host_addr[0] = 203;
    dest.host_addr[1] = 0;
    dest.host_addr[2] = 113;
    dest.host_addr[3] = 7;
    dest.port = 443;
    size_t used = 0;
    ok(what, session_start_from_transparent_dest(&s, &dest, NULL, 0,
                                                  &used) == SESS_OK);
    ok(what, used == 0 && ft.write_len > 0 && s.transparent_client);
    uint8_t out[16];
    ok(what, session_take_client(&s, out, sizeof out) == 0);

    if (proto == VL_PROTO_SOCKS5 || proto == VL_PROTO_HTTP) {
        size_t before = ft.write_len;
        ok(what, session_feed_client(&s, (const uint8_t *)"EARLY", 5,
                                      &used) == SESS_OK && used == 5);
        ok(what, ft.write_len == before);
        if (proto == VL_PROTO_SOCKS5) {
            static const uint8_t greeting[] = { 5, 0 };
            ft.rx = greeting;
            ft.rx_len = 1;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
            ok(what, ft.write_len == before);
            ft.rx = greeting + 1;
            ft.rx_len = 1;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
            static const uint8_t reply[] = { 5, 0, 0, 3, 1, 'x', 0, 0, 'T' };
            ft.rx = reply;
            ft.rx_len = 4;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
            ft.rx = reply + 4;
            ft.rx_len = 1;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
            ft.rx = reply + 5;
            ft.rx_len = sizeof reply - 5;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
        } else {
            static const uint8_t reply[] = "HTTP/1.1 200 Connection established\r\n\r\n";
            ft.rx = reply;
            ft.rx_len = sizeof reply - 1;
            ft.rx_done = 0;
            ok(what, session_pump_remote(&s) == SESS_OK);
        }
        ok(what, s.state == SESS_RELAY);
        ok(what, ft.write_len == before + (proto == VL_PROTO_SOCKS5 ? 10 : 0) + 5);
        ok(what, memcmp(ft.write_buf + ft.write_len - 5, "EARLY", 5) == 0);
        size_t got = session_take_client(&s, out, sizeof out);
        ok(what, proto == VL_PROTO_SOCKS5
                     ? got == 1 && out[0] == 'T' : got == 0);
    } else {
        ok(what, s.state == SESS_RELAY);
    }
    printf("ok %s\n", what);
}

static void check_transparent_udp(const uint8_t uuid[VLESS_UUID_LEN],
                                  const char *flow, uint8_t expected_command) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;
    session_t s;
    ok("udp session init", session_init(&s, &fake_vt, &ft, VL_PROTO_VLESS,
                                        uuid, flow, NULL, NULL) == SESS_OK);
    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV4;
    dest.host_addr[0] = 203;
    dest.host_addr[1] = 0;
    dest.host_addr[2] = 113;
    dest.host_addr[3] = 7;
    dest.port = 53;
    uint8_t datagram[] = { 0, 2, 0x12, 0x34 };
    size_t used = 0;
    ok("udp transparent request", session_start_from_transparent_udp(
       &s, &dest, datagram, sizeof datagram, &used) == SESS_OK &&
       used == sizeof datagram && s.transparent_client);
    size_t cmd = 1 + VLESS_UUID_LEN + 1 + ft.write_buf[17];
    ok("udp command in request", ft.write_len > cmd &&
       ft.write_buf[cmd] == expected_command);
    if (expected_command == VLESS_CMD_MUX) return;
    uint8_t response[] = { 0, 0, 0, 2, 0xab, 0xcd };
    ft.rx = response;
    ft.rx_len = sizeof response;
    ft.rx_done = 0;
    ok("udp response header", session_pump_remote(&s) == SESS_OK &&
       s.state == SESS_RELAY);
    uint8_t out[16];
    size_t got = session_take_client(&s, out, sizeof out);
    ok("udp response payload preserved", got == 4 &&
       memcmp(out, response + 2, got) == 0);
}

/* plain, non-tls app bytes end vision padding with END; xray keeps reading
   tls records after END, so the bytes must stay inside the outer tls */
static void check_vision_end_stays_encrypted(const uint8_t *uuid) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;
    session_t s;
    ok("end session init", session_init(&s, &fake_vt, &ft, VL_PROTO_VLESS,
                                        uuid, "xtls-rprx-vision", NULL, NULL) == SESS_OK);
    s.state = SESS_RELAY;
    s.u.vc.state = VC_ST_OPEN;
    static const uint8_t line[] = "ping over plain ssh-like stream\n";
    int fed = 1;
    for (int i = 0; i < 12; ++i) {
        size_t consumed = 0;
        if (session_feed_client(&s, line, sizeof line - 1, &consumed) != SESS_OK ||
            consumed != sizeof line - 1)
            fed = 0;
    }
    ok("plain stream fed through vision", fed);
    ok("vision sent END for the plain stream", s.vwrap.end_sent && !s.vwrap.direct_sent);
    ok("END never switches the upstream to bare socket writes",
       ft.raw_calls == 0 && ft.mark_calls == 0 && s.vision_upstream_direct == 0);
    ok("bytes after END go through the tls writer unframed",
       ft.last_len == sizeof line - 1 && memcmp(ft.last_write, line, ft.last_len) == 0);
}

int main(void) {
    uint8_t uuid[VLESS_UUID_LEN];
    for (size_t i = 0; i < sizeof uuid; ++i) uuid[i] = (uint8_t)(i + 1);

    uint8_t direct[16 + 5 + 3];
    memcpy(direct, uuid, 16);
    direct[16] = VISION_CMD_DIRECT;
    direct[17] = 0;
    direct[18] = 0;
    direct[19] = 0;
    direct[20] = 0;
    memcpy(direct + 21, "RAW", 3);

    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx = direct;
    ft.rx_len = sizeof direct;

    session_t s;
    ok("session init", session_init(&s, &fake_vt, &ft, VL_PROTO_VLESS,
                                    uuid, "xtls-rprx-vision", NULL, NULL) == SESS_OK);
    s.state = SESS_RELAY;
    s.u.vc.state = VC_ST_OPEN;

    ok("pump direct", session_pump_remote(&s) == SESS_OK);
    ok("downstream direct latched", s.vision_downstream_direct == 1);
    ok("upstream direct stays framed", s.vision_upstream_direct == 0);
    ok("transport raw stays framed", ft.mark_calls == 0);

    uint8_t out[8];
    size_t got = session_take_client(&s, out, sizeof out);
    ok("direct payload delivered", got == 3 && memcmp(out, "RAW", 3) == 0);

    size_t consumed = 0;
    ok("feed raw client", session_feed_client(&s, (const uint8_t *)"GET", 3, &consumed) == SESS_OK);
    ok("client consumed", consumed == 3);
    ok("framed write used", ft.write_calls == 1);
    ok("raw write not used", ft.raw_calls == 0);

    check_vision_end_stays_encrypted(uuid);
    check_socks_connect_ack(VL_PROTO_TROJAN, NULL, "secret", "trojan socks connect ack");
    check_socks_connect_ack(VL_PROTO_SHADOWSOCKS, "aes-256-gcm", "secret", "shadowsocks socks connect ack");
    check_transparent(VL_PROTO_SOCKS5, NULL, NULL, "transparent socks5");
    check_transparent(VL_PROTO_HTTP, NULL, NULL, "transparent http");
    check_transparent(VL_PROTO_TROJAN, NULL, "secret", "transparent trojan");
    check_transparent(VL_PROTO_SHADOWSOCKS, "aes-256-gcm", "secret", "transparent shadowsocks");
    check_transparent_udp(uuid, NULL, VLESS_CMD_UDP);
    check_transparent_udp(uuid, "xtls-rprx-vision", VLESS_CMD_MUX);

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all session direct checks passed\n");
    return 0;
}
