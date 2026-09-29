/* edge profiles need their own wire shape, not chrome with a different name */
#include "../daemon/core/tls_clienthello.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(const char *name, int pass) {
    if (pass) printf("  ok  %s\n", name);
    else { printf(" FAIL %s\n", name); failures++; }
}

static size_t read_u16(const uint8_t *p) {
    return ((size_t)p[0] << 8) | p[1];
}

static const uint8_t *find_extension(const uint8_t *hello, size_t hello_len,
                                     uint16_t want, size_t *data_len) {
    size_t pos = 4 + 2 + TLS_CH_RANDOM_LEN;
    if (hello_len < pos + 1) return NULL;
    size_t sid_len = hello[pos++];
    if (sid_len > hello_len - pos || hello_len - pos - sid_len < 2) return NULL;
    pos += sid_len;
    size_t cipher_len = read_u16(hello + pos); pos += 2;
    if (cipher_len > hello_len - pos || hello_len - pos - cipher_len < 1) return NULL;
    pos += cipher_len;
    size_t compression_len = hello[pos++];
    if (compression_len > hello_len - pos || hello_len - pos - compression_len < 2) return NULL;
    pos += compression_len;
    size_t exts_len = read_u16(hello + pos); pos += 2;
    if (exts_len > hello_len - pos) return NULL;
    size_t end = pos + exts_len;
    while (pos + 4 <= end) {
        uint16_t type = (uint16_t)read_u16(hello + pos);
        size_t len = read_u16(hello + pos + 2);
        pos += 4;
        if (len > end - pos) return NULL;
        if (type == want) {
            if (data_len) *data_len = len;
            return hello + pos;
        }
        pos += len;
    }
    return NULL;
}

/* reality_handshake.c rides a sha-256 only key schedule and accepts exactly
   TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256. a fronted server
   mirrors whichever suite its dest picked, so offering any other tls 1.3
   suite hands it a way to end the handshake in "suite (-5)" */
static int offers_only_supported_tls13(const uint8_t *hello, size_t hello_len) {
    size_t pos = 4 + 2 + TLS_CH_RANDOM_LEN;
    if (hello_len < pos + 1) return 0;
    size_t sid_len = hello[pos++];
    if (sid_len > hello_len - pos || hello_len - pos - sid_len < 2) return 0;
    pos += sid_len;
    size_t cipher_len = read_u16(hello + pos); pos += 2;
    if (cipher_len % 2 || cipher_len > hello_len - pos) return 0;
    for (size_t i = 0; i < cipher_len; i += 2) {
        uint16_t suite = (uint16_t)read_u16(hello + pos + i);
        if ((suite & 0xff00) != 0x1300) continue;
        if (suite != 0x1301 && suite != 0x1303) return 0;
    }
    return 1;
}

static void check_fp_suites(const char *name, tls_fp_t fp) {
    tls_ch_params_t p;
    uint8_t hello[2048];
    size_t hello_len = 0;
    memset(&p, 0, sizeof p);
    memset(p.random, 0x41, sizeof p.random);
    memset(p.x25519_pub, 0x42, sizeof p.x25519_pub);
    p.sni = "front.example";
    p.fp = fp;
    if (tls_build_clienthello(&p, hello, sizeof hello, &hello_len) != TLS_CH_OK) {
        check(name, 0);
        return;
    }
    check(name, offers_only_supported_tls13(hello, hello_len));
}

/* go's tls server, reality's included, refuses a hello whose extension list
   repeats a type. the grease pair is drawn per connection, so walk many */
static int has_repeated_extension(const uint8_t *hello, size_t hello_len) {
    size_t pos = 4 + 2 + TLS_CH_RANDOM_LEN;
    if (hello_len < pos + 1) return 1;
    size_t sid_len = hello[pos++];
    if (sid_len > hello_len - pos || hello_len - pos - sid_len < 2) return 1;
    pos += sid_len;
    size_t cipher_len = read_u16(hello + pos); pos += 2;
    if (cipher_len > hello_len - pos || hello_len - pos - cipher_len < 1) return 1;
    pos += cipher_len;
    size_t compression_len = hello[pos++];
    if (compression_len > hello_len - pos || hello_len - pos - compression_len < 2) return 1;
    pos += compression_len;
    size_t exts_len = read_u16(hello + pos); pos += 2;
    if (exts_len > hello_len - pos) return 1;
    size_t end = pos + exts_len;
    uint16_t seen[64];
    size_t count = 0;
    while (pos + 4 <= end) {
        uint16_t type = (uint16_t)read_u16(hello + pos);
        size_t len = read_u16(hello + pos + 2);
        pos += 4;
        if (len > end - pos || count == 64) return 1;
        for (size_t i = 0; i < count; ++i)
            if (seen[i] == type) return 1;
        seen[count++] = type;
        pos += len;
    }
    return pos != end;
}

static void check_no_repeated_extension(const char *name, tls_fp_t fp) {
    tls_ch_params_t p;
    uint8_t hello[2048];
    size_t hello_len = 0;
    memset(&p, 0, sizeof p);
    memset(p.x25519_pub, 0x42, sizeof p.x25519_pub);
    p.sni = "front.example";
    p.fp = fp;
    int clean = 1;
    for (uint32_t seed = 1; seed <= 4096 && clean; ++seed) {
        p.random[0] = (uint8_t)(seed >> 24);
        p.random[1] = (uint8_t)(seed >> 16);
        p.random[2] = (uint8_t)(seed >> 8);
        p.random[3] = (uint8_t)seed;
        if (tls_build_clienthello(&p, hello, sizeof hello, &hello_len) != TLS_CH_OK ||
            has_repeated_extension(hello, hello_len))
            clean = 0;
    }
    check(name, clean);
}

int main(void) {
    tls_ch_params_t p;
    uint8_t hello[2048];
    size_t hello_len = 0, ext_len = 0;
    memset(&p, 0, sizeof p);
    memset(p.random, 0x41, sizeof p.random);
    memset(p.x25519_pub, 0x42, sizeof p.x25519_pub);
    p.sni = "front.example";
    p.fp = TLS_FP_EDGE;

    check_no_repeated_extension("chrome never repeats an extension", TLS_FP_CHROME);
    check_no_repeated_extension("edge never repeats an extension", TLS_FP_EDGE);
    check_no_repeated_extension("firefox never repeats an extension", TLS_FP_FIREFOX);

    check("build edge", tls_build_clienthello(&p, hello, sizeof hello, &hello_len) == TLS_CH_OK);
    const uint8_t *versions = find_extension(hello, hello_len, 0x002b, &ext_len);
    check("edge has supported versions", versions && ext_len == 11);
    check("edge offers tls 1.1 and 1.0", versions && ext_len == 11 &&
          versions[7] == 0x03 && versions[8] == 0x02 &&
          versions[9] == 0x03 && versions[10] == 0x01);
    check("edge omits chrome alps", !find_extension(hello, hello_len, 0x4469, NULL));

    check_fp_suites("chrome offers only suites we can finish", TLS_FP_CHROME);
    check_fp_suites("edge offers only suites we can finish", TLS_FP_EDGE);
    check_fp_suites("firefox offers only suites we can finish", TLS_FP_FIREFOX);
    check_fp_suites("qq offers only suites we can finish", TLS_FP_QQ);
    check_fp_suites("randomized offers only suites we can finish", TLS_FP_RANDOMIZED);

    if (failures) {
        printf("%d tls_clienthello checks failed\n", failures);
        return 1;
    }
    printf("all tls_clienthello checks passed\n");
    return 0;
}
