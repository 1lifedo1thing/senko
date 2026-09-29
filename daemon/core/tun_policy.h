#ifndef SENKO_TUN_POLICY_H
#define SENKO_TUN_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "dns_cache.h"
#include "dns_msg.h"
#include "dns_policy.h"
#include "rules.h"

#ifdef __cplusplus
extern "C" {
#endif

/* times are monotonic seconds, the same clock for every call.

   the routing decisions the utun backend makes where pf rules and the pf dns
   forwarder used to: which captured lookups are answered with a block, which
   answers are cached, and whether a captured flow goes through the server,
   straight out of the physical interface, or nowhere.

   everything here runs on the tunnel's owning thread. the ruleset is borrowed
   and must not change while the tunnel runs; ctl refuses rule edits then */

typedef struct {
    uint64_t dns_queries;
    uint64_t dns_blocked;     /* answered with the block response */
    uint64_t dns_cache_hits;
    uint64_t dns_stale_answers; /* upstream too slow, a stale entry answered */
    uint64_t dns_failed;      /* no answer and nothing cached */
    uint64_t flows_proxy;
    uint64_t flows_direct;
    uint64_t flows_blocked;
} tun_policy_stats_t;

typedef struct {
    ruleset_t     *rules;  /* NULL or empty: everything goes through the server */
    dns_cache_t   *cache;  /* heap, only while the tunnel runs */
    dns_policy_t  *map;    /* heap, only when some rule sends a domain direct */
    uint8_t        logged[RULESET_MAX_RULES / 8];
    tun_policy_stats_t stats;
} tun_policy_t;

typedef enum {
    TUN_POLICY_OK = 0,
    TUN_POLICY_ERR_ARG = -1,
    TUN_POLICY_ERR_MEMORY = -2
} tun_policy_status_t;

tun_policy_status_t tun_policy_init(tun_policy_t *policy, ruleset_t *rules);
void tun_policy_free(tun_policy_t *policy);

/* the rule verdict for a captured lookup. the first match of every rule is
   logged once, as the pf forwarder did */
rule_action_t tun_policy_domain(tun_policy_t *policy, const char *name);

/* the verdict for a captured flow: an ip rule first, then what dns answers
   said about the address. why gets a short reason for the flow log */
rule_action_t tun_policy_flow(tun_policy_t *policy, const uint8_t *address,
                              uint8_t address_len, uint64_t now,
                              char *why, size_t why_cap);

/* a fresh cached answer for this query, with the query's id; 1 when found */
int tun_policy_cached(tun_policy_t *policy, const uint8_t *query, size_t query_len,
                      const dns_question_t *question, rule_action_t action,
                      int allow_stale, uint64_t now,
                      uint8_t *out, size_t cap, size_t *out_len);

/* takes a checked upstream answer: clamps its ttls in place, caches it and
   remembers its addresses for flow decisions */
void tun_policy_answer(tun_policy_t *policy, const dns_question_t *question,
                       rule_action_t action, uint8_t *response, size_t len,
                       uint64_t now);

void tun_policy_flush_cache(tun_policy_t *policy);
void tun_policy_flush_map(tun_policy_t *policy);

#ifdef __cplusplus
}
#endif

#endif
