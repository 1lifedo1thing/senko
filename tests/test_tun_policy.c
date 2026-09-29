#include "tun_policy.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static ruleset_t rules;
static tun_policy_t policy;

static size_t query(uint8_t *out, uint16_t id, const char *name) {
    size_t n = 12;
    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8); out[1] = (uint8_t)id; out[2] = 1; out[5] = 1;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        out[n++] = (uint8_t)len;
        memcpy(out + n, p, len);
        n += len;
        p += len;
        if (*p) ++p;
    }
    out[n++] = 0;
    out[n++] = 0; out[n++] = 1; out[n++] = 0; out[n++] = 1;
    return n;
}

/* the query turned into an answer with one A record */
static size_t answer(const uint8_t *q, size_t qlen, const uint8_t a[4], uint32_t ttl,
                     uint8_t *out) {
    memcpy(out, q, qlen);
    out[2] = 0x81; out[3] = 0x80; out[7] = 1;
    size_t n = qlen;
    const uint8_t rr[] = { 0xc0, 0x0c, 0, 1, 0, 1,
                           (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16),
                           (uint8_t)(ttl >> 8), (uint8_t)ttl, 0, 4 };
    memcpy(out + n, rr, sizeof rr);
    n += sizeof rr;
    memcpy(out + n, a, 4);
    return n + 4;
}

static void add(const char *text) {
    if (ruleset_add_text(&rules, text, strlen(text), NULL) != RULES_OK) {
        ++failures;
        fprintf(stderr, "FAIL rule %s\n", text);
    }
}

int main(void) {
    ruleset_init(&rules);
    ok("no rules: everything goes through the server",
       tun_policy_init(&policy, &rules) == TUN_POLICY_OK && !policy.map &&
       tun_policy_domain(&policy, "any.example") == RULE_ACTION_PROXY);
    tun_policy_free(&policy);

    add("direct domain-suffix bank.example");
    add("block domain-suffix ads.example");
    add("block ip-cidr 203.0.113.0/24");
    add("direct ip-cidr 198.51.100.0/24");
    ok("init with a direct domain rule keeps an address table",
       tun_policy_init(&policy, &rules) == TUN_POLICY_OK && policy.map != NULL);

    ok("a block domain rule", tun_policy_domain(&policy, "x.ads.example") == RULE_ACTION_BLOCK);
    ok("a direct domain rule", tun_policy_domain(&policy, "www.bank.example") == RULE_ACTION_DIRECT);
    ok("an unruled domain", tun_policy_domain(&policy, "video.example") == RULE_ACTION_PROXY);

    char why[96];
    const uint8_t blocked[4] = { 203, 0, 113, 7 };
    const uint8_t cidr_direct[4] = { 198, 51, 100, 7 };
    const uint8_t resolved[4] = { 192, 0, 2, 44 };
    ok("an ip block rule", tun_policy_flow(&policy, blocked, 4, 100, why, sizeof why) ==
       RULE_ACTION_BLOCK && strstr(why, "203.0.113.0/24"));
    ok("an ip direct rule", tun_policy_flow(&policy, cidr_direct, 4, 100, why, sizeof why) ==
       RULE_ACTION_DIRECT);
    ok("an address nothing named goes through the server",
       tun_policy_flow(&policy, resolved, 4, 100, why, sizeof why) == RULE_ACTION_PROXY);

    /* the answer for a direct domain sends its address direct */
    uint8_t q[128], a[256], out[512];
    size_t qlen = query(q, 0x1111, "www.bank.example");
    size_t alen = answer(q, qlen, resolved, 600, a);
    dns_question_t question;
    ok("fixture question parses", dns_msg_parse_question(q, qlen, &question) == DNS_MSG_OK);
    tun_policy_answer(&policy, &question, RULE_ACTION_DIRECT, a, alen, 100);
    ok("a direct domain's answer sends its address direct",
       tun_policy_flow(&policy, resolved, 4, 110, why, sizeof why) == RULE_ACTION_DIRECT &&
       strstr(why, "www.bank.example"));
    ok("an ip rule outranks what dns said",
       tun_policy_flow(&policy, blocked, 4, 110, NULL, 0) == RULE_ACTION_BLOCK);

    /* cache: fresh with the new id, then stale only when allowed */
    uint8_t q2[128];
    size_t q2len = query(q2, 0x2222, "www.bank.example");
    size_t outlen = 0;
    ok("a fresh cached answer carries the new query id",
       tun_policy_cached(&policy, q2, q2len, &question, RULE_ACTION_DIRECT, 0, 120,
                         out, sizeof out, &outlen) &&
       outlen == alen && out[0] == 0x22 && out[1] == 0x22);
    ok("a cached answer is not reused under another verdict",
       !tun_policy_cached(&policy, q2, q2len, &question, RULE_ACTION_PROXY, 0, 120,
                          out, sizeof out, &outlen));
    ok("the ttl is clamped to the cache maximum, so it expires by then",
       !tun_policy_cached(&policy, q2, q2len, &question, RULE_ACTION_DIRECT, 0,
                          100 + DNS_CACHE_TTL_MAX + 1, out, sizeof out, &outlen));
    ok("but a slow upstream may still get the stale answer",
       tun_policy_cached(&policy, q2, q2len, &question, RULE_ACTION_DIRECT, 1,
                         100 + DNS_CACHE_TTL_MAX + 1, out, sizeof out, &outlen) &&
       policy.stats.dns_stale_answers == 1 && policy.stats.dns_cache_hits == 1);

    tun_policy_flush_map(&policy);
    ok("flushing the address table sends the address back through the server",
       tun_policy_flow(&policy, resolved, 4, 130, NULL, 0) == RULE_ACTION_PROXY);
    tun_policy_flush_cache(&policy);
    ok("flushing the cache forgets answers",
       !tun_policy_cached(&policy, q2, q2len, &question, RULE_ACTION_DIRECT, 1, 130,
                          out, sizeof out, &outlen));
    ok("flow verdicts are counted",
       policy.stats.flows_blocked == 2 && policy.stats.flows_direct == 2);
    tun_policy_free(&policy);

    if (failures) {
        fprintf(stderr, "%d tun policy check(s) failed\n", failures);
        return 1;
    }
    puts("all tun policy checks passed");
    return 0;
}
