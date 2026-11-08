#include "amnezia_bundle.h"
#include "awg_config.h"
#include "b64.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "amnezia_fixture.inc"

static int failed;

static void expect(int condition, const char *what) {
    if (condition) return;
    fprintf(stderr, "failed: %s\n", what);
    failed = 1;
}

static void extract_ok(const char *body, const char *what) {
    char conf[8192];
    char reason[160];
    size_t len = 0;
    amz_status_t r = amz_bundle_extract_conf(body, strlen(body), conf, sizeof conf,
                                             &len, reason, sizeof reason);
    if (r != AMZ_OK) {
        fprintf(stderr, "failed: %s (%d: %s)\n", what, (int)r, reason);
        failed = 1;
        return;
    }
    expect(len == strlen(conf), "extracted length matches");
    expect(conf[len - 1] == '\n', "extracted config ends with a newline");
    expect(strstr(conf, "[Interface]") != NULL, "extracted config has an interface");

    /* the point of the decoder is a profile the tunnel can actually use */
    awg_config_t cfg;
    char why[160];
    awg_cfg_status_t p = awg_config_parse(conf, len, &cfg, why, sizeof why);
    if (p != AWG_CFG_OK) {
        fprintf(stderr, "failed: %s parses as awg (%d: %s)\n", what, (int)p, why);
        failed = 1;
        return;
    }
    expect(strcmp(cfg.endpoint_host, "203.0.113.7") == 0, "endpoint host");
    expect(cfg.endpoint_port == 51820, "endpoint port");
    expect(cfg.address_count == 1 && cfg.dns_count == 2, "network fields");
    expect(cfg.has_preshared_key, "preshared key");
}

static void extract_fails(const char *body, amz_status_t want, const char *what) {
    char conf[1024];
    char reason[160];
    size_t len = 0;
    amz_status_t r = amz_bundle_extract_conf(body, strlen(body), conf, sizeof conf,
                                             &len, reason, sizeof reason);
    if (r == want) return;
    fprintf(stderr, "failed: %s wanted %d got %d (%s)\n", what, (int)want, (int)r, reason);
    failed = 1;
}

int main(void) {
    static const char premium[] =
        "{\"config_version\":2,\"api_config\":{\"service_type\":\"premium\","
        "\"service_protocol\":\"awg\",\"user_country_code\":\"US\"},"
        "\"auth_data\":{\"api_key\":\"test-key\"}}";
    amz_premium_key_t premium_key;
    char premium_reason[160];
    expect(amz_premium_parse_key(premium, strlen(premium), &premium_key,
                                 premium_reason, sizeof premium_reason) == AMZ_OK &&
           strcmp(premium_key.api_key, "test-key") == 0 &&
           strcmp(premium_key.service_protocol, "awg") == 0, "premium key fields");
    {
        unsigned char compressed[1024];
        size_t input_len = strlen(premium);
        uLongf compressed_len = sizeof compressed - 4;
        compressed[0] = (unsigned char)(input_len >> 24);
        compressed[1] = (unsigned char)(input_len >> 16);
        compressed[2] = (unsigned char)(input_len >> 8);
        compressed[3] = (unsigned char)input_len;
        int z = compress(compressed + 4, &compressed_len, (const Bytef *)premium, input_len);
        char link[2048] = "vpn://";
        size_t encoded_len = 0;
        int encoded = z == Z_OK ? b64_encode(compressed, compressed_len + 4, link + 6,
                                              sizeof link - 6, &encoded_len) : -1;
        expect(encoded == 0 && amz_premium_parse_key(link, encoded_len + 6, &premium_key,
                                                      premium_reason, sizeof premium_reason) == AMZ_OK &&
               strcmp(premium_key.api_key, "test-key") == 0, "compressed premium link");
    }
    /* the key of a real subscription declares 255 bytes and inflates to 262, and
       Qt accepts that: the declared size is a buffer hint, not a limit */
    {
        static const char wide[] =
            "{\"name\": \"Amnezia Premium\", \"description\": \"Amnezia Premium\", "
            "\"config_version\": 2, \"api_config\": {\"service_type\": \"amnezia-premium\", "
            "\"service_protocol\": \"awg\", \"user_country_code\": \"ru\"}, "
            "\"auth_data\": {\"api_key\": \"short-declared\"}}";
        static const uint32_t declared[] = { 7, 100, 255, 1, 100000 };
        for (size_t i = 0; i < sizeof declared / sizeof declared[0]; ++i) {
            unsigned char z[1024];
            uLongf zl = sizeof z - 4;
            z[0] = (unsigned char)(declared[i] >> 24); z[1] = (unsigned char)(declared[i] >> 16);
            z[2] = (unsigned char)(declared[i] >> 8); z[3] = (unsigned char)declared[i];
            compress(z + 4, &zl, (const Bytef *)wide, strlen(wide));
            char lk[2048] = "vpn://";
            size_t ln = 0;
            b64_encode(z, zl + 4, lk + 6, sizeof lk - 6, &ln);
            expect(amz_premium_parse_key(lk, ln + 6, &premium_key, premium_reason,
                                         sizeof premium_reason) == AMZ_OK &&
                   strcmp(premium_key.api_key, "short-declared") == 0,
                   "premium key whose declared size is wrong");
        }
        /* a small declared size must not let a large inflate through */
        static unsigned char bomb_in[2 * 1024 * 1024];
        static unsigned char bomb_z[8192];
        memset(bomb_in, ' ', sizeof bomb_in);
        uLongf bl = sizeof bomb_z - 4;
        bomb_z[0] = bomb_z[1] = bomb_z[2] = 0;
        bomb_z[3] = 16;
        compress(bomb_z + 4, &bl, bomb_in, sizeof bomb_in);
        static char bomb_link[16384] = "vpn://";
        size_t bn = 0;
        b64_encode(bomb_z, bl + 4, bomb_link + 6, sizeof bomb_link - 6, &bn);
        expect(amz_premium_parse_key(bomb_link, bn + 6, &premium_key, premium_reason,
                                     sizeof premium_reason) != AMZ_OK, "inflate stays under the json cap");
        /* a cut stream is not a bundle */
        unsigned char cut[64] = { 0, 0, 0, 40, 0x78, 0x9c, 0x4b, 0x4c };
        char cut_link[128] = "vpn://";
        size_t cn = 0;
        b64_encode(cut, 8, cut_link + 6, sizeof cut_link - 6, &cn);
        expect(amz_premium_parse_key(cut_link, cn + 6, &premium_key, premium_reason,
                                     sizeof premium_reason) != AMZ_OK, "truncated deflate stream");
    }
    static const char bad_premium[] =
        "{\"config_version\":2,\"api_config\":{},\"auth_data\":{\"api_key\":\"secret\"}}";
    expect(amz_premium_parse_key(bad_premium, strlen(bad_premium), &premium_key,
                                 premium_reason, sizeof premium_reason) == AMZ_ERR_JSON &&
           premium_key.api_key[0] == '\0', "invalid premium key clears output");
    /* a ready bundle carries no auth data, so it is left for the config decoder */
    expect(amz_premium_parse_key(k_plain_bundle, strlen(k_plain_bundle), &premium_key,
                                 premium_reason, sizeof premium_reason) == AMZ_ERR_NOT_BUNDLE &&
           amz_premium_parse_key(k_vpn_link, strlen(k_vpn_link), &premium_key,
                                 premium_reason, sizeof premium_reason) == AMZ_ERR_NOT_BUNDLE,
           "a ready bundle is not a premium key");
    expect(amz_premium_parse_key(bad_premium, strlen(bad_premium), &premium_key,
                                 premium_reason, sizeof premium_reason) == AMZ_ERR_JSON &&
           strcmp(premium_reason, AMZ_PREMIUM_INVALID_REASON) == 0,
           "an unusable premium key says so");
    static const char country_json[] =
        "{\"api_config\":{\"available_countries\":["
        "{\"server_country_code\":\"FI-1\",\"server_country_name\":\"Finland\","
        "\"server_country_code_l10n\":\"FI\"},"
        "{\"server_country_code\":\"NL\",\"server_country_name\":\"Netherlands\"}]}}";
    amz_premium_country_t countries[2];
    size_t country_count = 0;
    expect(amz_premium_parse_countries(country_json, strlen(country_json), countries, 2,
                                       &country_count, premium_reason, sizeof premium_reason) == AMZ_OK &&
           country_count == 2 && strcmp(countries[0].code, "FI-1") == 0 &&
           strcmp(countries[0].flag_code, "FI") == 0 && !countries[1].flag_code[0],
           "premium countries");
    expect(amz_premium_parse_countries(country_json, strlen(country_json), countries, 1,
                                       &country_count, premium_reason, sizeof premium_reason) == AMZ_ERR_SPACE &&
           country_count == 0 && !countries[0].code[0], "country capacity clears output");
    static const char invalid_countries[] =
        "{\"api_config\":{\"available_countries\":[{\"server_country_code\":1}]}}";
    expect(amz_premium_parse_countries(invalid_countries, strlen(invalid_countries), countries, 2,
                                       &country_count, premium_reason, sizeof premium_reason) == AMZ_ERR_JSON &&
           country_count == 0, "malformed country rejected");
    expect(amz_bundle_looks_like(k_vpn_link, strlen(k_vpn_link)), "vpn link classified");
    expect(amz_bundle_looks_like(k_plain_bundle, strlen(k_plain_bundle)),
           "plain bundle classified");
    expect(!amz_bundle_looks_like("vless://x@1.2.3.4:443#a", 22), "vless is not a bundle");
    expect(!amz_bundle_looks_like("{\"outbounds\":[]}", 16), "xray json is not a bundle");
    expect(!amz_bundle_looks_like("", 0), "empty is not a bundle");

    extract_ok(k_vpn_link, "compressed vpn link");
    extract_ok(k_plain_bundle, "plain wireguard bundle");

    /* the share sheet hands over the link with a newline and a byte order mark */
    char padded[8192];
    snprintf(padded, sizeof padded, "\xEF\xBB\xBF  %s \n", k_vpn_link);
    extract_ok(padded, "vpn link with bom and whitespace");

    extract_fails("[Interface]\nPrivateKey = x\n", AMZ_ERR_NOT_BUNDLE, "native conf");
    extract_fails("vpn://????", AMZ_ERR_DECODE, "vpn link that is not base64");
    extract_fails("{\"containers\":[{\"container\":\"amnezia-openvpn\","
                  "\"openvpn\":{\"last_config\":\"{}\"}}]}",
                  AMZ_ERR_UNSUPPORTED, "bundle without a wireguard container");
    extract_fails("{\"containers\":[{\"container\":\"amnezia-awg\",\"awg\":{}}]}",
                  AMZ_ERR_JSON, "container without a config");
    extract_fails("{\"last_config\":\"", AMZ_ERR_JSON, "truncated json");

    /* a valid bundle must still refuse to overflow a caller buffer */
    {
        char small[32];
        char reason[160];
        size_t len = 0;
        amz_status_t r = amz_bundle_extract_conf(k_vpn_link, strlen(k_vpn_link),
                                                 small, sizeof small, &len,
                                                 reason, sizeof reason);
        expect(r == AMZ_ERR_SPACE && len == 0, "small output buffer");
    }

    if (failed) return 1;
    puts("all amnezia bundle checks passed");
    return 0;
}
