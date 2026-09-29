#ifndef SENKO_HELPER_JOBS_H
#define SENKO_HELPER_JOBS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* child processes senkod starts for the app, running senkod's own helper
   modes. output is collected without blocking the control loop, because a
   helper may talk to senkod's control socket while it runs */

#define HELPER_JOB_MAX 4
#define HELPER_JOB_OUTPUT_MAX 1024
#define HELPER_JOB_TIMEOUT_MS 60000

typedef struct {
    int      used;
    pid_t    pid;
    int      fd;          /* the helper's stdout, -1 once it closed */
    int      client_slot; /* who asked, and which connection it was */
    uint64_t client_generation;
    int64_t  started_ms;
    int64_t  deadline_ms;
    int      reaped;      /* the helper exited and was waited for */
    int      status;
    int      timed_out;
    char     output[HELPER_JOB_OUTPUT_MAX];
    size_t   output_len;
} helper_job_t;

typedef struct {
    helper_job_t jobs[HELPER_JOB_MAX];
} helper_jobs_t;

typedef struct {
    int      client_slot;
    uint64_t client_generation;
    int      exit_code;  /* -1 when it was killed or timed out */
    int      timed_out;
    int64_t  elapsed_ms;
    const char *output;  /* valid until the next call */
    size_t   output_len;
} helper_job_done_t;

void helper_jobs_init(helper_jobs_t *jobs);

/* starts argv[0] with argv; 0 on success, -1 with the reason */
int helper_jobs_start(helper_jobs_t *jobs, char *const argv[], int client_slot,
                      uint64_t client_generation, int64_t now_ms,
                      char *reason, size_t reason_cap);

/* fills fds with the descriptors to poll for reading; returns how many */
size_t helper_jobs_fds(const helper_jobs_t *jobs, int *fds, size_t cap);

/* reads what is ready, reaps finished helpers and kills overdue ones. each
   finished job is handed to done once */
void helper_jobs_service(helper_jobs_t *jobs, int64_t now_ms,
                         void (*done)(void *ctx, const helper_job_done_t *job),
                         void *ctx);

/* kills and reaps every job, for shutdown */
void helper_jobs_stop(helper_jobs_t *jobs);

/* starts argv in its own session with stdout and stderr in log_path, so it
   outlives senkod: a package update stops senkod halfway through */
int helper_detached_start(char *const argv[], const char *log_path,
                          char *reason, size_t reason_cap);

#ifdef __cplusplus
}
#endif

#endif
