#include "probe_stats.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static probe_sample_t success_sample(uint32_t dns, uint32_t connect,
                                     uint32_t transport, uint32_t protocol,
                                     uint64_t generation) {
    probe_sample_t sample;
    memset(&sample, 0, sizeof sample);
    sample.dns_ms = dns;
    sample.connect_ms = connect;
    sample.transport_ms = transport;
    sample.protocol_ms = protocol;
    sample.success = 1;
    sample.failed_stage = PROBE_STAGE_NONE;
    sample.network_generation = generation;
    return sample;
}

static probe_sample_t failed_sample(probe_stage_t stage, uint64_t generation) {
    probe_sample_t sample;
    memset(&sample, 0, sizeof sample);
    sample.dns_ms = 5;
    sample.connect_ms = 20;
    sample.success = 0;
    sample.failed_stage = stage;
    sample.network_generation = generation;
    return sample;
}

int main(void) {
    probe_history_t history;
    probe_history_init(&history);

    /* the number is the handshake, not the carry probe on top of it */
    probe_sample_t sample = success_sample(10, 20, 30, 40, 1);
    sample.carry_ms = 500;
    ok("handshake time excludes the carry probe",
       probe_sample_handshake_ms(&sample) == 100);

    /* one sample is not enough to claim a latency */
    probe_history_add(&history, &sample);
    ok("a single sample reports unavailable",
       probe_history_median_ms(&history, 1) == PROBE_LATENCY_UNAVAILABLE);
    ok("the success is counted", history.successes == 1);

    probe_sample_t second = success_sample(10, 20, 30, 40, 1);
    second.protocol_ms = 60; /* handshake 120 */
    probe_history_add(&history, &second);
    ok("two samples give a median",
       probe_history_median_ms(&history, 1) != PROBE_LATENCY_UNAVAILABLE);
    ok("an even count takes a sample that was really measured",
       probe_history_median_ms(&history, 1) == 100);

    probe_sample_t third = success_sample(10, 20, 30, 140, 1); /* handshake 200 */
    probe_history_add(&history, &third);
    ok("the median of three is the middle one",
       probe_history_median_ms(&history, 1) == 120);

    /* an outlier does not drag the median the way an average would */
    probe_sample_t slow = success_sample(10, 20, 30, 9000, 1);
    probe_history_add(&history, &slow);
    ok("one slow sample does not move the median far",
       probe_history_median_ms(&history, 1) == 120);

    /* a failed handshake never contributes a latency */
    probe_history_t failing;
    probe_history_init(&failing);
    probe_sample_t reality_fail = failed_sample(PROBE_STAGE_TRANSPORT, 1);
    probe_history_add(&failing, &reality_fail);
    probe_history_add(&failing, &reality_fail);
    probe_history_add(&failing, &reality_fail);
    ok("failures never produce a latency",
       probe_history_median_ms(&failing, 1) == PROBE_LATENCY_UNAVAILABLE);
    ok("failures are counted", failing.failures == 3);
    ok("the failing stage is kept",
       failing.last_failed_stage == PROBE_STAGE_TRANSPORT);

    /* samples from a superseded network are not mixed into the current number */
    probe_history_t handover;
    probe_history_init(&handover);
    probe_sample_t wifi_a = success_sample(5, 10, 10, 15, 1);  /* 40 */
    probe_sample_t wifi_b = success_sample(5, 10, 10, 15, 1);
    probe_history_add(&handover, &wifi_a);
    probe_history_add(&handover, &wifi_b);
    ok("the wifi generation has a median",
       probe_history_median_ms(&handover, 1) == 40);
    ok("the cellular generation has none yet",
       probe_history_median_ms(&handover, 2) == PROBE_LATENCY_UNAVAILABLE);

    probe_sample_t cell_a = success_sample(20, 80, 60, 40, 2); /* 200 */
    probe_sample_t cell_b = success_sample(20, 80, 60, 40, 2);
    probe_history_add(&handover, &cell_a);
    probe_history_add(&handover, &cell_b);
    ok("the new generation reports its own number",
       probe_history_median_ms(&handover, 2) == 200);
    ok("the old generation is untouched by the new samples",
       probe_history_median_ms(&handover, 1) == 40);

    /* the ring is bounded and keeps the newest samples */
    probe_history_t ring;
    probe_history_init(&ring);
    for (int i = 0; i < PROBE_SAMPLE_MAX * 3; ++i) {
        probe_sample_t s = success_sample(0, 0, 0, (uint32_t)(i + 1), 1);
        probe_history_add(&ring, &s);
    }
    ok("the sample ring stays bounded", ring.count == PROBE_SAMPLE_MAX);
    ok("every sample was still counted", ring.successes == PROBE_SAMPLE_MAX * 3);
    uint32_t median = probe_history_median_ms(&ring, 1);
    ok("the median comes from the newest window",
       median >= PROBE_SAMPLE_MAX * 2 && median <= PROBE_SAMPLE_MAX * 3);

    /* parallel probe limits per slice */
    ok("armv7 runs three probes at once", probe_parallel_limit(0) == 3);
    ok("arm64 runs four", probe_parallel_limit(1) == 4);

    /* every stage has a name for the diagnostics screen */
    int named = 1;
    for (int i = PROBE_STAGE_NONE; i <= PROBE_STAGE_CARRY; ++i)
        if (strcmp(probe_stage_name((probe_stage_t)i), "unknown") == 0) named = 0;
    ok("every probe stage has a name", named);

    /* a sample with absurd stage times saturates instead of wrapping */
    probe_sample_t huge;
    memset(&huge, 0, sizeof huge);
    huge.dns_ms = 0xffffffffu;
    huge.connect_ms = 0xffffffffu;
    huge.success = 1;
    ok("stage sums saturate rather than wrap",
       probe_sample_handshake_ms(&huge) == PROBE_LATENCY_UNAVAILABLE - 1);

    ok("a null history reports unavailable",
       probe_history_median_ms(NULL, 1) == PROBE_LATENCY_UNAVAILABLE);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all handshake latency checks passed");
    return 0;
}
