/* trojan over every stream layer the daemon can run: what validates, what is
   refused and why, and that the saved catalog keeps each field */
#include "config.h"
#include "store.h"

#include <stdio.h>
#include <string.h>

#define PBK "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static int failed;

static void ok(const char *name, int cond) {
    if (!cond) {
        printf("FAIL %s\n", name);
        failed++;
    }
}

/* 1 when the link parses and validates, else 0 with why filled */
static int check(const char *link, vl_server_t *out, char *why, size_t cap) {
    why[0] = '\0';
    if (cfg_parse_link(link, out) != CFG_OK) {
        snprintf(why, cap, "does not parse");
        return 0;
    }
    return cfg_validate_server(out, why, cap);
}

static void accepted(const char *name, const char *link) {
    vl_server_t s;
    char why[96];
    if (!check(link, &s, why, sizeof why)) {
        printf("FAIL %s (%s)\n", name, why);
        failed++;
    }
}

static void refused(const char *name, const char *link, const char *reason) {
    vl_server_t s;
    char why[96];
    if (check(link, &s, why, sizeof why) || strcmp(why, reason) != 0) {
        printf("FAIL %s (got \"%s\")\n", name, why);
        failed++;
    }
}

static void test_matrix(void) {
    const char *base = "trojan://pw@example.com:443?";
    static const struct { const char *name, *query; } good[] = {
        { "tcp plain, written out", "security=none&type=tcp" },
        { "tcp tls", "security=tls&type=tcp&sni=a.example" },
        { "tcp reality", "security=reality&type=tcp&pbk=" PBK "&sid=ab12&fp=chrome&sni=a.example" },
        { "tcp reality without short id", "security=reality&type=tcp&pbk=" PBK },
        { "ws plain", "security=none&type=ws&path=%2Fw" },
        { "ws tls", "security=tls&type=ws&path=%2Fw&host=h.example" },
        { "grpc plain", "security=none&type=grpc&serviceName=svc" },
        { "grpc tls", "security=tls&type=grpc&serviceName=svc" },
        { "grpc reality", "security=reality&type=grpc&serviceName=svc&pbk=" PBK "&sid=ab12" },
        { "xhttp plain", "security=none&type=xhttp&path=%2Fx" },
        { "xhttp tls", "security=tls&type=xhttp&path=%2Fx&mode=stream-one" },
        { "xhttp reality", "security=reality&type=xhttp&path=%2Fx&mode=packet-up&pbk=" PBK "&sid=ab12" },
    };
    char link[512];
    for (size_t i = 0; i < sizeof good / sizeof good[0]; ++i) {
        snprintf(link, sizeof link, "%s%s#n", base, good[i].query);
        accepted(good[i].name, link);
    }
    refused("ws over reality", "trojan://pw@example.com:443?security=reality&type=ws&pbk=" PBK "#n",
            "trojan ws over reality");
    refused("h2", "trojan://pw@example.com:443?security=tls&type=http#n",
            "unsupported trojan transport");
    refused("flow", "trojan://pw@example.com:443?security=tls&flow=xtls-rprx-vision#n",
            "trojan does not use flow");
    refused("reality key too short", "trojan://pw@example.com:443?security=reality&pbk=AAAA#n",
            "reality requires valid pbk");
    refused("reality key missing", "trojan://pw@example.com:443?security=reality#n",
            "reality requires valid pbk");
    refused("reality short id not hex",
            "trojan://pw@example.com:443?security=reality&pbk=" PBK "&sid=zz#n",
            "reality sid must be hex <= 8 bytes");
    refused("reality short id too long",
            "trojan://pw@example.com:443?security=reality&pbk=" PBK "&sid=0123456789abcdef01#n",
            "reality sid must be hex <= 8 bytes");
    refused("reality key missing on grpc",
            "trojan://pw@example.com:443?security=reality&type=grpc#n",
            "reality requires valid pbk");
    refused("xhttp mode unknown", "trojan://pw@example.com:443?security=tls&type=xhttp&mode=nope#n",
            "unsupported xhttp mode");
    {
        /* a profile source can hand over a row with no password at all */
        vl_server_t s;
        char why[96];
        ok("parse for the empty password case",
           cfg_parse_link("trojan://pw@example.com:443?security=tls#n", &s) == CFG_OK);
        s.pass[0] = '\0';
        ok("empty password is refused",
           !cfg_validate_server(&s, why, sizeof why) && !strcmp(why, "trojan requires password"));
    }
}

static void test_default_and_explicit_security(void) {
    vl_server_t s;
    ok("no security means tls",
       cfg_parse_link("trojan://pw@example.com:443#n", &s) == CFG_OK && s.security == VL_SEC_TLS);
    ok("explicit none stays none",
       cfg_parse_link("trojan://pw@example.com:443?security=none#n", &s) == CFG_OK &&
       s.security == VL_SEC_NONE);
    ok("explicit tls stays tls",
       cfg_parse_link("trojan://pw@example.com:443?security=tls#n", &s) == CFG_OK &&
       s.security == VL_SEC_TLS);
}

/* every field a trojan row carries has to come back after a restart */
static void test_catalog_round_trip(void) {
    static const char *const links[] = {
        "trojan://p%40ss%3Aword@a.example:443?security=reality&type=tcp&pbk=" PBK
            "&sid=ab12&fp=firefox&sni=front.example#reality%20tcp",
        "trojan://pw@b.example:8443?security=tls&type=ws&path=%2Fws&host=h.example"
            "&sni=s.example&allowInsecure=1#ws",
        "trojan://pw@c.example:443?security=none&type=grpc&serviceName=svc#grpc%20plain",
        "trojan://pw@d.example:443?security=tls&type=grpc&serviceName=svc&mode=multi&sni=d.example#grpc%20multi",
        "trojan://pw@e.example:443?security=reality&type=xhttp&path=%2Fx&mode=stream-up"
            "&host=h.example&pbk=" PBK "&sid=ab12#xhttp%20reality",
        "trojan://pw@f.example:443?security=none&type=tcp#plain",
    };
    static store_t st, back;
    static char saved[65536];
    size_t saved_len = 0, i;

    store_init(&st);
    for (i = 0; i < sizeof links / sizeof links[0]; ++i) {
        vl_server_t s;
        if (cfg_parse_link(links[i], &s) != CFG_OK ||
            store_add_manual_server(&st, &s, NULL) != STORE_OK) {
            printf("FAIL add row %zu\n", i);
            failed++;
        }
    }
    ok("rows added", st.n == sizeof links / sizeof links[0]);
    ok("serialize", store_serialize(&st, saved, sizeof saved, &saved_len) == STORE_OK);
    store_init(&back);
    ok("deserialize", store_deserialize(&back, saved, saved_len) == STORE_OK && back.n == st.n);

    for (i = 0; i < st.n && i < back.n; ++i) {
        const vl_server_t *a = &st.servers[i], *b = &back.servers[i];
        char name[64];
        snprintf(name, sizeof name, "row %zu survives a restart", i);
        ok(name, a->proto == b->proto && a->port == b->port && a->net == b->net &&
                 a->security == b->security && a->insecure == b->insecure &&
                 a->grpc_multi == b->grpc_multi &&
                 !strcmp(a->host, b->host) && !strcmp(a->pass, b->pass) &&
                 !strcmp(a->sni, b->sni) && !strcmp(a->fp, b->fp) && !strcmp(a->pbk, b->pbk) &&
                 !strcmp(a->sid, b->sid) && !strcmp(a->path, b->path) &&
                 !strcmp(a->mode, b->mode) && !strcmp(a->ws_host, b->ws_host) &&
                 !strcmp(a->remark, b->remark));
    }
    ok("password with @ and : survives", back.n > 0 && !strcmp(back.servers[0].pass, "p@ss:word"));
    ok("explicit none survives", back.n == sizeof links / sizeof links[0] &&
                                 back.servers[5].security == VL_SEC_NONE &&
                                 back.servers[2].security == VL_SEC_NONE);
    ok("grpc multi survives", back.n > 3 && back.servers[3].grpc_multi == 1 &&
                              back.servers[2].grpc_multi == 0);

    /* link text a client edits and sends back must parse to the same row */
    {
        char link[2048];
        vl_server_t again;
        ok("a saved row's link parses back to the same node",
           store_link_at(&st, 4, link, sizeof link) == 0 &&
           cfg_parse_link(link, &again) == CFG_OK &&
           again.security == VL_SEC_REALITY && again.net == VL_NET_XHTTP &&
           !strcmp(again.pbk, PBK) && !strcmp(again.sid, "ab12") &&
           !strcmp(again.mode, "stream-up") && !strcmp(again.ws_host, "h.example"));
    }
}

/* nodes that differ in one wire field must not collapse into one row */
static void test_catalog_identity(void) {
    static store_t st;
    vl_server_t a, b;
    const char *base = "trojan://pw@x.example:443?security=reality&type=tcp&pbk=" PBK;
    char link[512];

    store_init(&st);
    snprintf(link, sizeof link, "%s&sid=ab12#one", base);
    ok("first parses", cfg_parse_link(link, &a) == CFG_OK);
    snprintf(link, sizeof link, "%s&sid=cd34#one", base);
    ok("second parses", cfg_parse_link(link, &b) == CFG_OK);
    ok("first added", store_add_manual_server(&st, &a, NULL) == STORE_OK);
    ok("another short id is another node", store_add_manual_server(&st, &b, NULL) == STORE_OK);
    ok("the same node twice is one row", store_add_manual_server(&st, &a, NULL) == STORE_ERR_EXISTS);
    ok("two rows", st.n == 2);
}

int main(void) {
    test_matrix();
    test_default_and_explicit_security();
    test_catalog_round_trip();
    test_catalog_identity();
    if (failed) {
        printf("%d check(s) failed\n", failed);
        return 1;
    }
    printf("trojan combos ok\n");
    return 0;
}
