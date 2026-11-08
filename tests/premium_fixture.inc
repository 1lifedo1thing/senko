/* a gateway answer shaped like the real one: a vpn:// bundle with the
   $WIREGUARD_CLIENT_PRIVATE_KEY placeholder, a country list that mixes awg and
   vless-only entries, and a key expiry */
#include "third_party/cJSON.h"
#include <zlib.h>
#include "b64.h"

/* set to add a country whose code carries a space and a line break */
static int premium_hostile;

static char *premium_answer(int with_countries) {
    static const char conf[] =
        "[Interface]\nAddress = 100.64.0.2/32\nDNS = 1.1.1.1, 1.0.0.1\n"
        "PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\nJc = 4\nJmin = 10\nJmax = 80\n"
        "S1 = 40\nS2 = 42\nH1 = 1148903\nH2 = 1229103\nH3 = 1900303\nH4 = 1990303\n\n"
        "[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\n"
        "PresharedKey = QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:51820\nPersistentKeepalive = 25\n";
    cJSON *inner = cJSON_CreateObject();
    cJSON_AddStringToObject(inner, "config", conf);
    char *inner_text = cJSON_PrintUnformatted(inner);
    cJSON_Delete(inner);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "server_country_code", "at");
    cJSON_AddStringToObject(root, "server_country_name", "Austria");
    cJSON *api = cJSON_AddObjectToObject(root, "api_config");
    cJSON *pk = cJSON_AddObjectToObject(api, "public_key");
    cJSON_AddStringToObject(pk, "expires_at", "2026-11-06 13:51:03.573146+00:00");
    if (with_countries) {
        cJSON *list = cJSON_AddArrayToObject(api, "available_countries");
        /* the real list has us-east and us-west next to a flag code of just us */
        static const char *rows[][4] = { { "hk", "Hong Kong", "awg,vless", "hk" },
                                         { "at", "Austria", "awg", "at" },
                                         { "us-east", "USA East", "awg,vless", "us" },
                                         { "xx", "Vless Only", "vless", "xx" } };
        for (int i = 0; i < 4; ++i) {
            cJSON *c = cJSON_CreateObject();
            cJSON_AddStringToObject(c, "server_country_code", rows[i][0]);
            cJSON_AddStringToObject(c, "server_country_code_l10n", rows[i][3]);
            cJSON_AddStringToObject(c, "server_country_name", rows[i][1]);
            cJSON *protos = cJSON_AddArrayToObject(c, "available_protocols");
            if (strstr(rows[i][2], "awg")) cJSON_AddItemToArray(protos, cJSON_CreateString("awg"));
            if (strstr(rows[i][2], "vless")) cJSON_AddItemToArray(protos, cJSON_CreateString("vless"));
            cJSON_AddItemToArray(list, c);
        }
        if (premium_hostile) {
            cJSON *c = cJSON_CreateObject();
            cJSON_AddStringToObject(c, "server_country_code", "bad code\nOK pwned");
            cJSON_AddStringToObject(c, "server_country_name", "Bad\nOK pwned");
            cJSON_AddItemToArray(list, c);
        }
    }
    cJSON *containers = cJSON_AddArrayToObject(root, "containers");
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "container", "amnezia-awg");
    cJSON *awg = cJSON_AddObjectToObject(entry, "awg");
    cJSON_AddStringToObject(awg, "last_config", inner_text);
    cJSON_AddItemToArray(containers, entry);
    free(inner_text);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    size_t jl = strlen(json);
    uLongf cl = compressBound((uLong)jl);
    unsigned char *z = (unsigned char *)malloc(cl + 4);
    z[0] = (unsigned char)(jl >> 24); z[1] = (unsigned char)(jl >> 16);
    z[2] = (unsigned char)(jl >> 8); z[3] = (unsigned char)jl;
    compress(z + 4, &cl, (const Bytef *)json, (uLong)jl);
    free(json);
    char *b64 = (char *)malloc(b64_encoded_maxlen(cl + 4) + 8);
    strcpy(b64, "vpn://");
    size_t bn = 0;
    b64_encode(z, cl + 4, b64 + 6, b64_encoded_maxlen(cl + 4), &bn);
    free(z);

    cJSON *answer = cJSON_CreateObject();
    cJSON_AddStringToObject(answer, "config", b64);
    cJSON_AddNumberToObject(answer, "http_status", 201);
    free(b64);
    char *text = cJSON_PrintUnformatted(answer);
    cJSON_Delete(answer);
    return text;
}
