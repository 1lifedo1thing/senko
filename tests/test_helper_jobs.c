#define _DEFAULT_SOURCE

#include "helper_jobs.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static int failures;
static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static helper_job_done_t last;
static char last_output[HELPER_JOB_OUTPUT_MAX];
static int finished;

static void on_done(void *ctx, const helper_job_done_t *job) {
    (void)ctx;
    last = *job;
    memcpy(last_output, job->output, job->output_len);
    last_output[job->output_len] = '\0';
    last.output = last_output;
    ++finished;
}

/* services the table until a job finishes or wait_ms passes; clock_skew_ms
   pretends that much time went by, to reach a deadline quickly */
static int run_until_done(helper_jobs_t *jobs, int wait_ms, int64_t clock_skew_ms) {
    int before = finished;
    int64_t end = now_ms() + wait_ms;
    while (finished == before && now_ms() < end) {
        int fds[HELPER_JOB_MAX];
        size_t n = helper_jobs_fds(jobs, fds, HELPER_JOB_MAX);
        struct pollfd pfd[HELPER_JOB_MAX];
        for (size_t i = 0; i < n; ++i) { pfd[i].fd = fds[i]; pfd[i].events = POLLIN; pfd[i].revents = 0; }
        (void)poll(pfd, n, 20);
        helper_jobs_service(jobs, now_ms() + clock_skew_ms, on_done, NULL);
    }
    return finished > before;
}

int main(void) {
    helper_jobs_t jobs;
    helper_jobs_init(&jobs);
    char reason[160];

    char *echo[] = { "/bin/sh", "-c", "echo connecting; echo second line; exit 3", NULL };
    ok("a helper starts", helper_jobs_start(&jobs, echo, 2, 77, now_ms(), reason, sizeof reason) == 0);
    ok("its output and exit code come back to the client that asked",
       run_until_done(&jobs, 3000, 0) && last.exit_code == 3 && last.client_slot == 2 &&
       last.client_generation == 77 &&
       strcmp(last_output, "connecting\nsecond line\n") == 0);

    char *stuck[] = { "/bin/sh", "-c", "sleep 30", NULL };
    ok("a helper that hangs starts", helper_jobs_start(&jobs, stuck, 1, 1, now_ms(), reason, sizeof reason) == 0);
    ok("it is killed at its deadline and reported as failed",
       run_until_done(&jobs, 3000, HELPER_JOB_TIMEOUT_MS + 1) && last.exit_code == -1);

    /* a helper that leaves a background child holding its stdout still
       answers */
    char *spawner[] = { "/bin/sh", "-c", "echo started; sleep 20 & exit 0", NULL };
    ok("a helper with a lingering child starts",
       helper_jobs_start(&jobs, spawner, 0, 5, now_ms(), reason, sizeof reason) == 0);
    int64_t t0 = now_ms();
    ok("its answer arrives within the grace period, not with the child",
       run_until_done(&jobs, 5000, 0) && last.exit_code == 0 &&
       strcmp(last_output, "started\n") == 0 && now_ms() - t0 < 3000);

    char *missing[] = { "/nonexistent/senkod", NULL };
    ok("a missing helper is refused with the path in the reason",
       helper_jobs_start(&jobs, missing, 0, 0, now_ms(), reason, sizeof reason) != 0 &&
       strstr(reason, "/nonexistent/senkod") != NULL);

    for (int i = 0; i < HELPER_JOB_MAX; ++i)
        (void)helper_jobs_start(&jobs, stuck, i, 0, now_ms(), reason, sizeof reason);
    ok("the table is bounded",
       helper_jobs_start(&jobs, stuck, 9, 0, now_ms(), reason, sizeof reason) != 0 &&
       strstr(reason, "too many") != NULL);
    helper_jobs_stop(&jobs);
    ok("stop leaves nothing to poll", helper_jobs_fds(&jobs, (int[HELPER_JOB_MAX]){0}, HELPER_JOB_MAX) == 0);

    char log_path[] = "/tmp/senko-helper-test.log";
    char *detached[] = { "/bin/sh", "-c", "sleep 1; echo UPDATE OK done", NULL };
    ok("a detached helper starts and senkod does not wait for it",
       helper_detached_start(detached, log_path, reason, sizeof reason) == 0);
    int seen = 0;
    for (int i = 0; i < 40 && !seen; ++i) {
        usleep(100000);
        FILE *f = fopen(log_path, "r");
        char line[64] = "";
        if (f) { if (!fgets(line, sizeof line, f)) line[0] = '\0'; fclose(f); }
        seen = strcmp(line, "UPDATE OK done\n") == 0;
    }
    ok("it writes its progress to the log on its own", seen);
    unlink(log_path);

    if (failures) {
        fprintf(stderr, "%d helper job check(s) failed\n", failures);
        return 1;
    }
    puts("all helper job checks passed");
    return 0;
}
