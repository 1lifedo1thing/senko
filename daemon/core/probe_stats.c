#include "probe_stats.h"

#include <string.h>

void probe_history_init(probe_history_t *history) {
    if (!history) return;
    memset(history, 0, sizeof *history);
}

const char *probe_stage_name(probe_stage_t stage) {
    switch (stage) {
    case PROBE_STAGE_NONE:      return "none";
    case PROBE_STAGE_DNS:       return "dns";
    case PROBE_STAGE_CONNECT:   return "connect";
    case PROBE_STAGE_TRANSPORT: return "transport";
    case PROBE_STAGE_PROTOCOL:  return "protocol";
    case PROBE_STAGE_CARRY:     return "carry";
    }
    return "unknown";
}

uint32_t probe_sample_handshake_ms(const probe_sample_t *sample) {
    if (!sample) return 0;
    uint64_t total = (uint64_t)sample->dns_ms + sample->connect_ms +
        sample->transport_ms + sample->protocol_ms;
    return total > PROBE_LATENCY_UNAVAILABLE - 1
        ? PROBE_LATENCY_UNAVAILABLE - 1 : (uint32_t)total;
}

void probe_history_add(probe_history_t *history, const probe_sample_t *sample) {
    if (!history || !sample) return;
    history->samples[history->next] = *sample;
    history->next = (history->next + 1u) % PROBE_SAMPLE_MAX;
    if (history->count < PROBE_SAMPLE_MAX) ++history->count;

    if (sample->success) {
        ++history->successes;
        history->last_success_ms = sample->at_ms;
    } else {
        ++history->failures;
        history->last_failed_stage = sample->failed_stage;
    }
}

uint32_t probe_history_median_ms(const probe_history_t *history,
                                 uint64_t network_generation) {
    if (!history) return PROBE_LATENCY_UNAVAILABLE;

    uint32_t values[PROBE_SAMPLE_MAX];
    size_t n = 0;
    for (size_t i = 0; i < history->count; ++i) {
        const probe_sample_t *sample = &history->samples[i];
        if (!sample->success) continue;
        if (sample->network_generation != network_generation) continue;
        values[n++] = probe_sample_handshake_ms(sample);
    }
    /* one good sample is luck, the list needs two before it claims a latency */
    if (n < PROBE_MIN_SAMPLES) return PROBE_LATENCY_UNAVAILABLE;

    for (size_t i = 1; i < n; ++i) {
        uint32_t value = values[i];
        size_t j = i;
        while (j > 0 && values[j - 1] > value) {
            values[j] = values[j - 1];
            --j;
        }
        values[j] = value;
    }
    return values[(n - 1u) / 2u];
}

size_t probe_parallel_limit(int arm64) {
    return arm64 ? PROBE_PARALLEL_ARM64 : PROBE_PARALLEL_ARMV7;
}

static int in_cooldown(const failover_candidate_t *candidate, uint64_t now_ms) {
    return candidate->cooldown_until_ms > now_ms;
}

size_t failover_pick(const failover_candidate_t *candidates, size_t count,
                     uint64_t now_ms) {
    if (!candidates || count == 0) return SIZE_MAX;

    size_t user = SIZE_MAX, working = SIZE_MAX;
    size_t measured = SIZE_MAX, unmeasured = SIZE_MAX, cooling = SIZE_MAX;

    for (size_t i = 0; i < count; ++i) {
        const failover_candidate_t *candidate = &candidates[i];
        if (!candidate->in_group) continue;

        if (in_cooldown(candidate, now_ms)) {
            if (cooling == SIZE_MAX ||
                candidate->cooldown_until_ms < candidates[cooling].cooldown_until_ms)
                cooling = i;
            continue;
        }
        if (candidate->user_selected && user == SIZE_MAX) user = i;
        if (candidate->last_working && working == SIZE_MAX) working = i;
        if (candidate->median_ms != PROBE_LATENCY_UNAVAILABLE) {
            if (measured == SIZE_MAX ||
                candidate->median_ms < candidates[measured].median_ms)
                measured = i;
        } else if (unmeasured == SIZE_MAX) {
            unmeasured = i;
        }
    }

    if (user != SIZE_MAX) return user;
    if (working != SIZE_MAX) return working;
    if (measured != SIZE_MAX) return measured;
    if (unmeasured != SIZE_MAX) return unmeasured;
    return cooling;
}

void failover_reset_cooldowns(failover_candidate_t *candidates, size_t count) {
    if (!candidates) return;
    for (size_t i = 0; i < count; ++i) {
        candidates[i].cooldown_until_ms = 0;
        candidates[i].failures = 0;
    }
}
