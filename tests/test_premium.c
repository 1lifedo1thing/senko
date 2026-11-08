#define _POSIX_C_SOURCE 200809L

/* the daemon side of premium: state and profile files, country changes, and a
   gateway that fails. the request callback stands in for the sealed round trip,
   which test_amnezia_gateway covers */
#include "premium.h"
#include "amnezia_bundle.h"
#include "awg_config.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "premium_fixture.inc"

static int failed;

static void expect(int pass, const char *what) {
    if (pass) return;
    fprintf(stderr, "FAIL %s\n", what);
    failed++;
}

static const char *k_priv_seen;
static char g_last_payload[4096];
static int g_calls;
static amz_gw_status_t g_result;
static int g_with_countries = 1;

static char g_last_path[64];
static amz_gw_status_t g_revoke_result;
static int g_revoke_status;
static int g_revokes;

static amz_gw_status_t fake_request(void *ctx, const char *path, const char *payload, size_t len,
                                    char *answer, size_t cap, size_t *n, int *api_status,
                                    char *reason, size_t rcap) {
    (void)ctx;
    ++g_calls;
    snprintf(g_last_path, sizeof g_last_path, "%s", path);
    snprintf(g_last_payload, sizeof g_last_payload, "%.*s", (int)len, payload);
    if (strcmp(path, AMZ_GW_PATH_REVOKE) == 0) {
        ++g_revokes;
        if (api_status) *api_status = g_revoke_status;
        if (g_revoke_result != AMZ_GW_OK) snprintf(reason, rcap, "gateway down");
        return g_revoke_result;
    }
    if (g_result != AMZ_GW_OK) {
        snprintf(reason, rcap, "the premium subscription is not active");
        return g_result;
    }
    char *a = premium_answer(g_with_countries);
    size_t al = strlen(a);
    if (al >= cap) { free(a); return AMZ_GW_ERR_SPACE; }
    memcpy(answer, a, al + 1);
    *n = al;
    free(a);
    return AMZ_GW_OK;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = (char *)calloc(1, 65536);
    size_t n = fread(buf, 1, 65535, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static int count_files(const char *dir) {
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)))
        if (e->d_name[0] != '.') ++n;
    if (d) closedir(d);
    return n;
}

int main(void) {
    (void)k_priv_seen;
    char dir[] = "/tmp/senko-premium-test-XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char state[256], conf[256];
    snprintf(state, sizeof state, "%s/state.json", dir);
    snprintf(conf, sizeof conf, "%s/amneziawg.conf", dir);
    premium_env_t env = { state, conf, fake_request, NULL };

    /* the key from the real FI.conf has this shape */
    static const char key[] =
        "{\"name\":\"Amnezia Premium\",\"config_version\":2,"
        "\"api_config\":{\"service_type\":\"amnezia-premium\",\"service_protocol\":\"awg\","
        "\"user_country_code\":\"ru\"},\"auth_data\":{\"api_key\":\"SECRETKEY\"}}";
    char out[4096];

    expect(premium_run(&env, "STATE", NULL, out, sizeof out) != 0 && strstr(out, "ERR no premium key"),
           "state before any key");
    expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) != 0, "refresh before any key");
    expect(premium_run(&env, "COUNTRY", "at", out, sizeof out) != 0, "country before any key");

    g_result = AMZ_GW_ERR_API;
    expect(premium_run(&env, "KEY", key, out, sizeof out) != 0 && strstr(out, "not active") &&
           access(conf, F_OK) != 0 && access(state, F_OK) != 0 && count_files(dir) == 0,
           "a failed first import leaves nothing behind");
    g_result = AMZ_GW_OK;
    expect(premium_run(&env, "KEY", "{\"config_version\":2}", out, sizeof out) != 0 &&
           strncmp(out, "ERR ", 4) == 0, "a key without auth data");
    expect(g_calls == 1, "a bad key never reaches the gateway");

    expect(premium_run(&env, "KEY", key, out, sizeof out) == 0, "import");
    expect(strstr(out, "PREMIUM STATE at ") != NULL && strstr(out, "OK premium profile added\n") != NULL,
           "import reply");
    expect(strstr(out, "PREMIUM COUNTRY hk hk Hong Kong\n") && strstr(out, "PREMIUM COUNTRY at at Austria\n") &&
           strstr(out, "PREMIUM COUNTRY us-east us USA East\n") && !strstr(out, "Vless Only"),
           "only awg countries are offered, with the flag to draw");
    expect(strcmp(g_last_path, AMZ_GW_PATH_CONFIG) == 0, "profiles come from v1/config");
    {
        char *line = strstr(out, "PREMIUM STATE at ");
        long exp = line ? atol(line + 17) : 0;
        expect(exp == premium_parse_expiry("2026-11-06 13:51:03.573146+00:00") && exp > 1700000000L,
               "expiry as epoch");
    }
    expect(strstr(g_last_payload, "\"public_key\"") && !strstr(g_last_payload, "server_country_code") &&
           strstr(g_last_payload, "SECRETKEY") && strstr(g_last_payload, "installation_uuid"),
           "first request asks for the gateway's own country");
    char *c1 = slurp(conf);
    awg_config_t cfg;
    char why[160];
    expect(c1 && awg_config_parse(c1, strlen(c1), &cfg, why, sizeof why) == AWG_CFG_OK,
           "stored profile is a valid awg config");
    expect(c1 && !strstr(c1, "$WIREGUARD") && strstr(c1, "PrivateKey = ") != NULL, "private key filled in");
    struct stat sb;
    expect(stat(conf, &sb) == 0 && (sb.st_mode & 077) == 0, "profile is private");
    expect(stat(state, &sb) == 0 && (sb.st_mode & 077) == 0, "state is private");
    expect(count_files(dir) == 2, "no temp files left");

    /* the private key is fresh per request, and the install id is not */
    char *u1 = strstr(slurp(state), "installation_uuid");
    char uuid1[48] = "";
    if (u1) sscanf(u1, "installation_uuid\":\"%47[^\"]", uuid1);
    expect(strlen(uuid1) == 36, "install id is a uuid");
    expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) == 0 &&
           strstr(g_last_payload, "\"server_country_code\":\"at\"") != NULL,
           "refresh asks for the current country");
    char *c2 = slurp(conf);
    expect(c1 && c2 && strcmp(c1, c2) != 0, "each profile gets a new private key");
    char *s2 = slurp(state);
    char uuid2[48] = "";
    char *u2 = strstr(s2, "installation_uuid");
    if (u2) sscanf(u2, "installation_uuid\":\"%47[^\"]", uuid2);
    expect(strcmp(uuid1, uuid2) == 0, "install id survives a refresh");

    expect(premium_run(&env, "COUNTRY", "hk", out, sizeof out) == 0 &&
           strstr(g_last_payload, "\"server_country_code\":\"hk\"") != NULL, "country change");
    expect(premium_run(&env, "COUNTRY", "xx", out, sizeof out) != 0 &&
           strstr(out, "not available"), "a vless-only country is refused");
    expect(premium_run(&env, "COUNTRY", "us-east", out, sizeof out) == 0 &&
           strstr(g_last_payload, "\"server_country_code\":\"us-east\"") != NULL,
           "a region code goes to the gateway as listed");
    expect(premium_run(&env, "COUNTRY", "zz", out, sizeof out) != 0, "an unknown country is refused");
    expect(premium_run(&env, "COUNTRY", NULL, out, sizeof out) != 0, "no country given");

    /* a gateway failure keeps the working profile byte for byte */
    char *before_conf = slurp(conf);
    char *before_state = slurp(state);
    g_result = AMZ_GW_ERR_NETWORK;
    expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) != 0 && strstr(out, "ERR "), "failed refresh");
    g_result = AMZ_GW_OK;
    g_with_countries = 0;
    expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) != 0, "answer without countries is refused");
    g_with_countries = 1;
    char *after_conf = slurp(conf);
    char *after_state = slurp(state);
    expect(before_conf && after_conf && strcmp(before_conf, after_conf) == 0 &&
           strcmp(before_state, after_state) == 0 && count_files(dir) == 2,
           "failures keep the saved profile and state");

    /* a replacement key keeps the install id */
    expect(premium_run(&env, "KEY", key, out, sizeof out) == 0, "second import");
    char *s3 = slurp(state);
    char uuid3[48] = "";
    char *u3 = strstr(s3, "installation_uuid");
    if (u3) sscanf(u3, "installation_uuid\":\"%47[^\"]", uuid3);
    expect(strcmp(uuid1, uuid3) == 0, "a new key on the same phone keeps the install id");

    expect(premium_run(&env, "STATE", NULL, out, sizeof out) == 0 && strstr(out, "OK premium state\n"),
           "state");
    g_revoke_result = AMZ_GW_OK;
    g_revokes = 0;
    expect(premium_run(&env, "FORGET", NULL, out, sizeof out) == 0 && access(state, F_OK) != 0 &&
           strcmp(out, "OK premium key removed\n") == 0, "forget removes the key");
    expect(g_revokes == 1 && strcmp(g_last_path, AMZ_GW_PATH_REVOKE) == 0 &&
           strstr(g_last_payload, "\"installation_uuid\":\"") != NULL &&
           strstr(g_last_payload, "SECRETKEY") != NULL && !strstr(g_last_payload, "public_key"),
           "forget releases the device slot");
    expect(access(conf, F_OK) == 0, "forget leaves the profile to the app");
    expect(premium_run(&env, "FORGET", NULL, out, sizeof out) == 0 && g_revokes == 1,
           "forget twice asks the gateway once");
    /* a gateway that cannot be reached still lets the key go, and says so */
    expect(premium_run(&env, "KEY", key, out, sizeof out) == 0, "import again");
    g_revoke_result = AMZ_GW_ERR_NETWORK;
    expect(premium_run(&env, "FORGET", NULL, out, sizeof out) == 0 && access(state, F_OK) != 0 &&
           strstr(out, "device slot not released: gateway down"), "forget reports a slot it could not release");
    expect(premium_run(&env, "KEY", key, out, sizeof out) == 0, "import a third time");
    g_revoke_result = AMZ_GW_ERR_API;
    g_revoke_status = 404;
    expect(premium_run(&env, "FORGET", NULL, out, sizeof out) == 0 &&
           strcmp(out, "OK premium key removed\n") == 0, "a slot the gateway lost is released");
    g_revoke_result = AMZ_GW_OK;
    expect(premium_run(&env, "NOPE", NULL, out, sizeof out) != 0, "unknown op");

    /* a country code from the gateway cannot split a line or start a new one */
    premium_hostile = 1;
    expect(premium_run(&env, "KEY", key, out, sizeof out) == 0, "import with a hostile country");
    expect(!strstr(out, "pwned") && !strstr(out, "bad"), "a code with a break or space is not offered");
    premium_hostile = 0;

    /* the state is not left describing a profile that was never stored */
    {
        char *before = slurp(state);
        unlink(conf);
        expect(mkdir(conf, 0700) == 0, "conf path blocked by a directory");
        expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) != 0 &&
               strstr(out, "could not save") != NULL, "a profile that cannot be stored is an error");
        char *after = slurp(state);
        expect(before && after && strcmp(before, after) == 0, "state kept after a failed profile write");
        expect(count_files(dir) == 2, "no temp or backup files left");
        rmdir(conf);
        free(before);
        free(after);
    }

    /* a damaged state file is reported, not guessed at */
    {
        FILE *f = fopen(state, "wb");
        fputs("{not json", f);
        fclose(f);
        expect(premium_run(&env, "REFRESH", NULL, out, sizeof out) != 0 && strstr(out, "unreadable"),
               "damaged state");
    }

    expect(premium_parse_expiry("2026-11-06 13:51:03.573146+00:00") == 1793973063L, "expiry value");
    expect(premium_parse_expiry("2026-11-06T13:51:03Z") == 1793973063L, "expiry with T and Z");
    expect(premium_parse_expiry("2026-11-06 18:51:03+05:00") == 1793973063L, "expiry with offset");
    expect(premium_parse_expiry("") == 0 && premium_parse_expiry("tomorrow") == 0 &&
           premium_parse_expiry("2026-13-06 13:51:03+00:00") == 0 && premium_parse_expiry(NULL) == 0,
           "unreadable expiry");

    unlink(conf);
    unlink(state);
    rmdir(dir);
    if (!failed) printf("all premium checks passed\n");
    return failed;
}
