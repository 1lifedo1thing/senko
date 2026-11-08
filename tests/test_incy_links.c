/* incy:// links: add, import and crypt1 against the published format, and the
   path from a link to a subscription source */
#include "config.h"
#include "incy.h"
#include "store.h"

#include <stdio.h>
#include <string.h>

static int failed;

static void ok(const char *name, int cond) {
    if (!cond) {
        printf("FAIL %s\n", name);
        failed++;
    }
}

/* generated with the published key and a fixed iv; json keys sorted as the
   @incy/link-encoder package writes them */
#define CRYPT1_DOC \
    "incy://crypt1/FZEVXuV39UEX1yHB3nkrgdPdrJ3syVxcQm_Y-lY0oKWAT5yRn00xe6ohg06aVWjWRrGJ7BAeEzuoFzv8XBosLnqnqqCMbnAJmR7EN2hII4Yyql1FtWlLlLs"
#define CRYPT1_NAMED \
    "incy://crypt1/AAECAwQFBgcICQoLNyILfyzDtk0iuywc98LBArSa3vEmL2ifUDqJII-WVnkr6vsYGgwI08RePaGrQX3NRqed-C2RO_JfY6e8GS2M9raAy5XQhpuSX3N57ftdk60vxiT5Kw"
#define CRYPT1_UTF \
    "incy://crypt1/AAECAwQFBgcICQoLNyILfyzDK5XSXo7OURF12ebs2O9KIWbIVyTHOJfcSnkv6bINGlAOxIgVILinXGHEDP3etmzWK_sacaqCdG9-O_rfmSBpeXF-oSA"
#define CRYPT1_LONGNAME \
    "incy://crypt1/AAECAwQFBgcICQoLNyILfyzDKrvTZI_8UCR06Bc1WS65gpUy9Mc0jWQ774KOFVmt5KyqKXf_iVYbo9wu8gctFZ8v2E76gx1WpoBxWxEtICt82R-Txkl1naiJ9s_OMtFA5ICZ550cXZ0mzCtXKIRBXpt-8B4OEpgqSrmowm46VOjf8QCbQ_ciQE9oXNe59TTM12mGhZoTf1iKorQQ7SaMuqJJEimg2ZncPcO5sVyLiVyFv49OxuktUU0gEDV4ceCljQvtECPNjGZqkozk-xQ61Dp4qu-GT0ddFQ8qiJDn1cyvNxTqj51cOgTbOOABzpV3Ao5UbZJuJhlA9KUL2nynx_Kc8zQLqWbwaii1QvPnMEQ"
#define CRYPT1_CTLNAME \
    "incy://crypt1/AAECAwQFBgcICQoLNyILfyzDmmhsiXxfo97XC-SAqskceTTOH2fKccDWEGgn--VSWUZUxYRceq_oFjzc1mgjlSqyXYMeRMkhFfaCRg"
#define CRYPT1_V2 \
    "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALcOWEi8puLIQSHBTKYvWR5vXpEzlHq16lRc"
#define CRYPT1_NOURL \
    "incy://crypt1/AAECAwQFBgcICQoLNyITfyzQhpSeRSR95qsymGHD-AS_-q8"
#define CRYPT1_EMPTYURL \
    "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRYgx3wFo5GUGkOt-DPnLriTIelRY5EjKcQ"
#define CRYPT1_FTP \
    "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZkny5JroTWEqSU7dkJYDTRQGedIJmWSC9lq_WE4rjBSlvPY-eXrrZU-lRl"
#define CRYPT1_SPACEURL \
    "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALdSUXC9zuP4ADxIGBSIPiBf-MpxqUzSZMrazXA"
#define CRYPT1_NOTJSON \
    "incy://crypt1/AAECAwQFBgcICQoLJHQRLWXb1Btxnjxd5NPECrbW7Y4Q1lmbEXmi33zLRk1AsSq0wQ"
#define CRYPT1_ARRAY \
    "incy://crypt1/AAECAwQFBgcICQoLFyINKWKRiA4txC0G44XAH6fX-M0NIjyfeNvX3Pl1qp3-22qva6rsbz4"

static incy_status_t unwrap(const char *link, char *out, size_t cap, char *name, size_t ncap) {
    return incy_unwrap(link, out, cap, name, ncap);
}

static int source(const char *link, char *url, char *name) {
    return cfg_subscription_source(link, strlen(link), url, 512, name, 64);
}

int main(void) {
    char out[512], name[64], url[512];
    size_t i;

    /* crypt1 */
    ok("doc sample opens",
       unwrap(CRYPT1_DOC, out, sizeof out, name, sizeof name) == INCY_OK &&
       strcmp(out, "https://incsub.myincteam.org/vTyt0xVE-aAjHv8T") == 0 &&
       name[0] == '\0');
    ok("crypt1 carries the provider name",
       unwrap(CRYPT1_NAMED, out, sizeof out, name, sizeof name) == INCY_OK &&
       strcmp(out, "https://sub.example/abc123token") == 0 &&
       strcmp(name, "My Provider VPN") == 0);
    ok("crypt1 name keeps utf-8",
       unwrap(CRYPT1_UTF, out, sizeof out, name, sizeof name) == INCY_OK &&
       strcmp(name, "\xD0\xA1\xD0\xB5\xD0\xBD\xD0\xBA\xD0\xBE VPN") == 0);
    ok("a trailing slash is ignored",
       unwrap(CRYPT1_NAMED "/", out, sizeof out, name, sizeof name) == INCY_OK);
    {
        char upper[sizeof CRYPT1_NAMED];
        memcpy(upper, CRYPT1_NAMED, sizeof upper);
        memcpy(upper, "INCY://CRYPT1/", 14);
        ok("uppercase scheme and host are accepted",
           unwrap(upper, out, sizeof out, name, sizeof name) == INCY_OK);
    }

    /* a long name is cut on a character boundary, never in the middle of one */
    ok("long name is cut at a utf-8 boundary",
       unwrap(CRYPT1_LONGNAME, out, sizeof out, name, sizeof name) == INCY_OK &&
       strlen(name) == 62 && (unsigned char)name[0] == 0xD1);
    ok("name buffer of one byte stays terminated",
       unwrap(CRYPT1_NAMED, out, sizeof out, name, 1) == INCY_OK && name[0] == '\0');
    ok("name may be omitted",
       unwrap(CRYPT1_NAMED, out, sizeof out, NULL, 0) == INCY_OK);

    /* crypt1 failures leave nothing behind */
    strcpy(out, "stale");
    strcpy(name, "stale");
    ok("control character in the name is refused",
       unwrap(CRYPT1_CTLNAME, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED &&
       out[0] == '\0' && name[0] == '\0');
    ok("schema newer than 1 is refused",
       unwrap(CRYPT1_V2, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("missing url is refused",
       unwrap(CRYPT1_NOURL, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("empty url is refused",
       unwrap(CRYPT1_EMPTYURL, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("non-http scheme is refused",
       unwrap(CRYPT1_FTP, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("url with a space is refused",
       unwrap(CRYPT1_SPACEURL, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("plaintext that is not json is refused",
       unwrap(CRYPT1_NOTJSON, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("json that is not an object is refused",
       unwrap(CRYPT1_ARRAY, out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);
    ok("out buffer too small is reported",
       unwrap(CRYPT1_NAMED, out, 10, name, sizeof name) == INCY_ERR_TOO_LONG);

    {
        char bad[sizeof CRYPT1_NAMED];
        /* any flipped bit in iv, ciphertext or tag must fail the tag check */
        const char *swap = "ABCD";
        for (i = 14; i < sizeof CRYPT1_NAMED - 1; i += 7) {
            memcpy(bad, CRYPT1_NAMED, sizeof bad);
            bad[i] = bad[i] == swap[0] ? swap[1] : swap[0];
            if (unwrap(bad, out, sizeof out, name, sizeof name) == INCY_OK) {
                printf("FAIL tampered byte %zu accepted\n", i);
                failed++;
            }
        }
        memcpy(bad, CRYPT1_NAMED, sizeof bad);
        bad[sizeof bad - 2] = '\0';
        ok("truncated payload fails",
           unwrap(bad, out, sizeof out, name, sizeof name) != INCY_OK);
    }
    ok("payload shorter than iv and tag",
       unwrap("incy://crypt1/AAECAwQFBgcICQoL", out, sizeof out, name, sizeof name) ==
           INCY_ERR_MALFORMED);
    ok("standard base64 alphabet is refused",
       unwrap("incy://crypt1/AA+/AwQFBgcICQoLNyIL", out, sizeof out, name, sizeof name) ==
           INCY_ERR_MALFORMED);
    ok("percent sign in the payload is refused",
       unwrap("incy://crypt1/AAECAwQF%20gcICQoL", out, sizeof out, name, sizeof name) ==
           INCY_ERR_MALFORMED);
    ok("empty crypt1 payload", unwrap("incy://crypt1/", out, sizeof out, name, sizeof name) ==
                                   INCY_ERR_MALFORMED);
    ok("crypt1 payload of only slashes",
       unwrap("incy://crypt1///", out, sizeof out, name, sizeof name) == INCY_ERR_MALFORMED);

    /* add and import */
    ok("import of a subscription url",
       unwrap("incy://import/https://example.com/api/subscription/abc123", out, sizeof out,
              name, sizeof name) == INCY_OK &&
       strcmp(out, "https://example.com/api/subscription/abc123") == 0 && name[0] == '\0');
    ok("add of a node link keeps the remark",
       unwrap("incy://add/vless://uuid@server:443?security=tls#MyServer", out, sizeof out,
              name, sizeof name) == INCY_OK &&
       strcmp(out, "vless://uuid@server:443?security=tls#MyServer") == 0 &&
       name[0] == '\0');
    ok("fragment of a url is the name, percent-decoded",
       unwrap("incy://add/https://example.com/s/abc#My%20Panel%20%D0%A1", out, sizeof out,
              name, sizeof name) == INCY_OK &&
       strcmp(name, "My Panel \xD0\xA1") == 0);
    ok("a percent-encoded line break in the name is refused",
       unwrap("incy://add/https://example.com/s/abc#a%0Ab", out, sizeof out, name,
              sizeof name) == INCY_ERR_MALFORMED);
    ok("a space in a url is refused",
       unwrap("incy://add/https://example.com/a b", out, sizeof out, name, sizeof name) ==
           INCY_ERR_MALFORMED);
    ok("empty add payload", unwrap("incy://add/", out, sizeof out, name, sizeof name) ==
                                INCY_ERR_MALFORMED);
    ok("empty import payload", unwrap("incy://import/", out, sizeof out, name, sizeof name) ==
                                   INCY_ERR_MALFORMED);

    /* actions that are not a source */
    ok("connect is not a source",
       unwrap("incy://connect", out, sizeof out, name, sizeof name) == INCY_ERR_UNSUPPORTED);
    ok("status is not a source",
       unwrap("incy://status", out, sizeof out, name, sizeof name) == INCY_ERR_UNSUPPORTED);
    ok("routing is not a source",
       unwrap("incy://routing/add/AAAA", out, sizeof out, name, sizeof name) ==
           INCY_ERR_UNSUPPORTED);
    ok("autorouting is not a source",
       unwrap("incy://autorouting/onadd/https://x.example/r", out, sizeof out, name,
              sizeof name) == INCY_ERR_UNSUPPORTED);
    ok("a foreign scheme is not incy",
       unwrap("happ://add/AAAA", out, sizeof out, name, sizeof name) == INCY_ERR_SCHEME);
    ok("empty input is not incy",
       unwrap("", out, sizeof out, name, sizeof name) == INCY_ERR_SCHEME);

    {
        static char big[9000];
        memcpy(big, "incy://import/https://example.com/", 34);
        memset(big + 34, 'a', sizeof big - 35);
        big[sizeof big - 1] = '\0';
        ok("link over the length cap",
           unwrap(big, out, sizeof out, name, sizeof name) == INCY_ERR_TOO_LONG);
    }

    /* from a link to a subscription source */
    ok("crypt1 becomes a source with its name",
       source(CRYPT1_NAMED, url, name) == 0 &&
       strcmp(url, "https://sub.example/abc123token") == 0 &&
       strcmp(name, "My Provider VPN") == 0);
    ok("import of a url becomes a source",
       source("incy://import/https://example.com/api/subscription/abc123", url, name) == 0 &&
       strcmp(url, "https://example.com/api/subscription/abc123") == 0 && name[0] == '\0');
    ok("url fragment is the name and not part of the fetched address",
       source("incy://add/https://example.com/s/abc123#Panel", url, name) == 0 &&
       strcmp(url, "https://example.com/s/abc123") == 0 && strcmp(name, "Panel") == 0);
    ok("surrounding whitespace is ignored",
       source("  incy://add/https://example.com/s/abc123\r\n", url, name) == 0);
    ok("a node link is not a source",
       source("incy://add/vless://uuid@server:443?security=tls#n", url, name) != 0);
    ok("a dialable https proxy is not a source",
       source("incy://add/https://user:pass@proxy.example:8443#node", url, name) != 0);
    ok("an unsupported action is not a source",
       source("incy://connect", url, name) != 0);
    ok("a source name that does not fit is refused",
       cfg_subscription_source(CRYPT1_NAMED, strlen(CRYPT1_NAMED), url, sizeof url, name, 8) != 0);
    ok("cfg_subscription_url takes incy links too",
       cfg_subscription_url(CRYPT1_NAMED, strlen(CRYPT1_NAMED), url, sizeof url) == 0 &&
       strcmp(url, "https://sub.example/abc123token") == 0);

    /* content kind and the node path */
    ok("content kind is incy", cfg_content_kind(CRYPT1_NAMED, strlen(CRYPT1_NAMED)) ==
                                   CFG_CONTENT_INCY);
    {
        const char *link =
            "incy://add/vless://11111111-2222-3333-4444-555555555555@node.example:443"
            "?security=tls&sni=node.example&type=tcp#one";
        vl_server_t servers[4];
        size_t count = 0;
        ok("add of a node link parses into a server",
           cfg_parse_subscription(link, strlen(link), servers, 4, &count) == CFG_OK &&
           count == 1 && strcmp(servers[0].host, "node.example") == 0);
        count = 0;
        ok("a link that does not open yields no server and no crash",
           cfg_parse_subscription("incy://crypt1/AAAA", 19, servers, 4, &count) == CFG_OK &&
           count == 0);
        count = 0;
        ok("a crypt1 link is a source, never a server",
           cfg_parse_subscription(CRYPT1_NAMED, strlen(CRYPT1_NAMED), servers, 4, &count) ==
               CFG_OK && count == 0);
    }

    /* the source becomes an ordinary subscription: a repeated link reuses it
       and the name and address survive a restart */
    {
        static store_t st, back;
        char saved[8192];
        size_t saved_len = 0, first = 99, second = 98;
        store_init(&st);
        source(CRYPT1_NAMED, url, name);
        ok("subscription is added",
           store_add_sub(&st, name, url, &first) == STORE_OK && first == 0);
        source(CRYPT1_NAMED, url, name);
        ok("the same link twice is one subscription",
           store_add_sub(&st, name, url, &second) == STORE_OK && second == first);
        ok("serialize",
           store_serialize(&st, saved, sizeof saved, &saved_len) == STORE_OK);
        store_init(&back);
        ok("subscription survives a restart",
           store_deserialize(&back, saved, saved_len) == STORE_OK && back.subs[0].used &&
           strcmp(back.subs[0].name, "My Provider VPN") == 0 &&
           strcmp(back.subs[0].url, "https://sub.example/abc123token") == 0 &&
           !back.subs[1].used);
    }

    if (failed) {
        printf("%d check(s) failed\n", failed);
        return 1;
    }
    printf("incy links ok\n");
    return 0;
}
