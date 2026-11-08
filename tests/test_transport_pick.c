/* transport_for_server must match cfg_validate for every common combo*/
#include "../daemon/core/config.h"
#include "../daemon/core/transport_pick.h"
#include "../daemon/core/reality_handshake.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(const char *name, int cond) {
    if (cond) printf("  ok  %s\n", name);
    else { printf(" FAIL %s\n", name); fails++; }
}

static void check_link(const char *link, int expect_vt) {
    vl_server_t s;
    char reason[128];
    ok(link, cfg_parse_link(link, &s) == CFG_OK);
    int valid = cfg_validate_server(&s, reason, sizeof reason);
    const transport_vt_t *vt = transport_for_server(&s);
    if (expect_vt) {
        ok("valid", valid);
        ok("has vt", vt != NULL);
    } else {
        ok("no vt or invalid", !valid || vt == NULL);
    }
}

/* vless encryption wraps whatever transport the node picked, once per combination */
static void check_enc(const char *query, int expect_vt) {
    char link[3000];
    snprintf(link, sizeof link,
             "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?%s"
             "&encryption=mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#t", query);
    vl_server_t s, plain;
    char reason[128];
    ok(link, cfg_parse_link(link, &s) == CFG_OK && s.venc != 0);
    ok("valid", cfg_validate_server(&s, reason, sizeof reason));
    const transport_vt_t *vt = transport_for_server(&s);
    plain = s;
    plain.venc = 0;
    const transport_vt_t *inner = transport_for_server(&plain);
    ok("the wrapper is a transport of its own", expect_vt ? (vt != NULL && vt != inner) : vt == NULL);
    ok("it has the full interface", !expect_vt || (vt->read && vt->write && vt->raw_write && vt->close && vt->want_write && vt->peer_direct));
    ok("another profile on the same transport picks the same wrapper", !expect_vt || (transport_for_server(&s) == vt));
}

int main(void) {
    fails = 0;
    check_enc("security=none&type=tcp", 1);
    check_enc("security=tls&type=tcp&sni=ex.com&flow=xtls-rprx-vision", 1);
    check_enc("security=reality&type=tcp&flow=xtls-rprx-vision&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome", 1);
    check_enc("security=none&type=ws&path=%2F", 1);
    check_enc("security=tls&type=ws&sni=ex.com&path=%2F", 1);
    check_enc("security=reality&type=ws&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome", 1);
    check_enc("security=none&type=xhttp&path=%2Fxh", 1);
    check_enc("security=tls&type=xhttp&path=%2Fxh&sni=ex.com", 1);
    check_enc("security=reality&type=xhttp&path=%2Fxh&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome", 1);
    check_enc("security=tls&type=grpc&serviceName=Tun&sni=ex.com", 1);
    {
        /* a profile on a protocol that has no such layer never gets a transport */
        vl_server_t t;
        ok("trojan parses", cfg_parse_link("trojan://pw@1.2.3.4:443?security=tls&type=tcp&sni=ex.com#t", &t) == CFG_OK);
        t.venc = 1;
        ok("a profile on trojan picks nothing", transport_for_server(&t) == NULL);
    }

    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=none&type=tcp#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=tls&type=tcp&sni=ex.com&flow=xtls-rprx-vision#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=tls&type=ws&sni=ex.com&path=%2F#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=reality&type=ws"
               "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=none&type=xhttp&path=%2Fxh#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=reality&type=xhttp&path=%2Fxh"
               "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=none&type=xhttp&path=%2Fxh&mode=packet-up#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=tls&type=xhttp&path=%2Fxh&mode=stream-up&sni=ex.com#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=reality&type=grpc&serviceName=Tun&pbk="
               "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=&fp=chrome#t", 1);
    check_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
               "?security=none&type=grpc&serviceName=Tun#t", 1);
    check_link("trojan://password@1.2.3.4:443?security=tls&type=tcp&sni=ex.com#t", 1);
    check_link("trojan://password@1.2.3.4:443?security=tls&type=ws&sni=ex.com&path=%2F#t", 1);
    check_link("socks5://u:p@1.2.3.4:1080#s", 1);
    check_link("http://1.2.3.4:8080#h", 1);
/* quic only: the link is valid and connectable, but only senko-core's own
   bundled client speaks it, so no senko transport_vt_t exists for it */
    check_link("hysteria2://pw@1.2.3.4:443?sni=ex.com#h", 0);
    check_link("hy2://pw@1.2.3.4:443?sni=ex.com#h", 0);

    {
        vl_server_t s;
        char reason[128];
        ok("hysteria2 parses", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:443?sni=ex.com&pinSHA256=AA:BB#h", &s) == CFG_OK);
        ok("hysteria2 proto", s.proto == VL_PROTO_HYSTERIA2);
        ok("hysteria2 auth", strcmp(s.pass, "pw") == 0);
        ok("hysteria2 sni", strcmp(s.sni, "ex.com") == 0);
        ok("hysteria2 pin", strcmp(s.pin_sha256, "AA:BB") == 0);
        ok("hysteria2 valid", cfg_validate_server(&s, reason, sizeof reason));

        ok("hysteria2 requires auth", cfg_parse_link(
            "hysteria2://1.2.3.4:443#h", &s) != CFG_OK);

        ok("hysteria2 obfs parses", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:443?obfs=salamander", &s) == CFG_OK);
        ok("hysteria2 obfs without password rejected",
           !cfg_validate_server(&s, reason, sizeof reason));

        ok("hysteria2 obfs+password parses", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:443?obfs=salamander&obfs-password=zap", &s) == CFG_OK);
        ok("hysteria2 obfs stored", strcmp(s.obfs, "salamander") == 0);
        ok("hysteria2 obfs password stored", strcmp(s.obfs_password, "zap") == 0);
        ok("hysteria2 obfs+password valid", cfg_validate_server(&s, reason, sizeof reason));

        ok("hysteria2 unknown obfs parses", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:443?obfs=unknown&obfs-password=zap", &s) == CFG_OK);
        ok("hysteria2 unknown obfs rejected",
           !cfg_validate_server(&s, reason, sizeof reason));

        ok("hysteria2 port hop parses", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:123,5000-6000?sni=ex.com#h", &s) == CFG_OK);
        ok("hysteria2 port hop first port", s.port == 123);
        ok("hysteria2 port hop stored",
           strcmp(s.port_hop, "123,5000-6000") == 0);
        ok("hysteria2 port hop valid", cfg_validate_server(&s, reason, sizeof reason));

        ok("hysteria2 malformed port hop rejected", cfg_parse_link(
            "hysteria2://pw@1.2.3.4:123,abc#h", &s) != CFG_OK);
    }

    if (fails) {
        printf("%d transport_pick checks failed\n", fails);
        return 1;
    }
    printf("all transport_pick checks passed\n");
    return 0;
}
