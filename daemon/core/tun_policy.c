#include "tun_policy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int rules_send_domain_direct(const ruleset_t *rules) {
    for (size_t i = 0; rules && i < rules->count; ++i)
        if (rules->entries[i].action == RULE_ACTION_DIRECT &&
            rules->entries[i].type != RULE_TYPE_IP_CIDR)
            return 1;
    return 0;
}

tun_policy_status_t tun_policy_init(tun_policy_t *policy, ruleset_t *rules) {
    if (!policy) return TUN_POLICY_ERR_ARG;
    memset(policy, 0, sizeof *policy);
    policy->rules = rules && rules->count ? rules : NULL;
    policy->cache = malloc(sizeof *policy->cache);
    if (!policy->cache) return TUN_POLICY_ERR_MEMORY;
    dns_cache_init(policy->cache);
    /* the address table only matters when a domain can send a flow direct */
    if (rules_send_domain_direct(policy->rules)) {
        policy->map = malloc(sizeof *policy->map);
        if (!policy->map) {
            tun_policy_free(policy);
            return TUN_POLICY_ERR_MEMORY;
        }
        dns_policy_init(policy->map);
    }
    return TUN_POLICY_OK;
}

void tun_policy_free(tun_policy_t *policy) {
    if (!policy) return;
    free(policy->cache);
    free(policy->map);
    policy->cache = NULL;
    policy->map = NULL;
}

static void log_first(tun_policy_t *policy, size_t index, rule_action_t action,
                      const char *subject) {
    if (index >= RULESET_MAX_RULES) return;
    uint8_t bit = (uint8_t)(1u << (index % 8));
    if (policy->logged[index / 8] & bit) return;
    policy->logged[index / 8] |= bit;
    fprintf(stderr, "senkod: rule %s matched %s\n", rule_action_name(action), subject);
}

rule_action_t tun_policy_domain(tun_policy_t *policy, const char *name) {
    if (!policy || !name || !policy->rules) return RULE_ACTION_PROXY;
    size_t index = SIZE_MAX;
    rule_action_t action = ruleset_match_domain(policy->rules, name, &index);
    if (index != SIZE_MAX) log_first(policy, index, action, name);
    return action;
}

rule_action_t tun_policy_flow(tun_policy_t *policy, const uint8_t *address,
                              uint8_t address_len, uint64_t now,
                              char *why, size_t why_cap) {
    if (why && why_cap) why[0] = '\0';
    if (!policy || !address || (address_len != 4 && address_len != 16))
        return RULE_ACTION_PROXY;
    rule_action_t action = RULE_ACTION_PROXY;
    if (policy->rules) {
        char text[INET6_ADDRSTRLEN];
        if (inet_ntop(address_len == 4 ? AF_INET : AF_INET6, address,
                      text, sizeof text)) {
            size_t index = SIZE_MAX;
            action = ruleset_match_ip(policy->rules, text, &index);
            if (index != SIZE_MAX) {
                log_first(policy, index, action, text);
                if (why && why_cap)
                    snprintf(why, why_cap, "ip rule %s",
                             policy->rules->entries[index].value);
            }
        }
    }
    /* an ip rule decides on its own; dns only speaks for unruled addresses */
    if (action == RULE_ACTION_PROXY && policy->map && address_len == 4 &&
        (!why || !why[0])) {
        char domain[DNS_POLICY_DOMAIN_MAX];
        if (dns_policy_is_direct(policy->map, address, now, domain, sizeof domain)) {
            action = RULE_ACTION_DIRECT;
            if (why && why_cap) snprintf(why, why_cap, "resolved from %s", domain);
        }
    }
    if (action == RULE_ACTION_BLOCK) ++policy->stats.flows_blocked;
    else if (action == RULE_ACTION_DIRECT) ++policy->stats.flows_direct;
    else ++policy->stats.flows_proxy;
    return action;
}

int tun_policy_cached(tun_policy_t *policy, const uint8_t *query, size_t query_len,
                      const dns_question_t *question, rule_action_t action,
                      int allow_stale, uint64_t now,
                      uint8_t *out, size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!policy || !policy->cache || !query || query_len < 2 || !question ||
        !out || !out_len)
        return 0;
    rule_action_t cached_action;
    int stale = 0;
    if (dns_cache_get(policy->cache, question->name, question->type, now,
                      allow_stale, out, cap, out_len, &cached_action, &stale) !=
            DNS_CACHE_OK ||
        cached_action != action || *out_len < 2)
        return 0;
    out[0] = query[0];
    out[1] = query[1];
    if (stale) ++policy->stats.dns_stale_answers;
    else ++policy->stats.dns_cache_hits;
    return 1;
}

void tun_policy_answer(tun_policy_t *policy, const dns_question_t *question,
                       rule_action_t action, uint8_t *response, size_t len,
                       uint64_t now) {
    if (!policy || !question || !response) return;
    dns_response_info_t info;
    if (dns_msg_clamp_ttls(response, len, DNS_CACHE_TTL_MIN, DNS_CACHE_TTL_MAX) !=
            DNS_MSG_OK ||
        dns_msg_response_info(response, len, &info) != DNS_MSG_OK)
        return;
    if (policy->map && info.ipv4_count)
        dns_policy_record(policy->map, question->name, action, info.ipv4,
                          info.ipv4_count, now, info.min_ttl);
    if (policy->cache && info.min_ttl > 0)
        (void)dns_cache_put(policy->cache, question->name, question->type,
                            response, len, now, info.min_ttl, action);
}

void tun_policy_flush_cache(tun_policy_t *policy) {
    if (policy && policy->cache) dns_cache_clear(policy->cache);
}

void tun_policy_flush_map(tun_policy_t *policy) {
    if (policy && policy->map) dns_policy_clear(policy->map);
}
