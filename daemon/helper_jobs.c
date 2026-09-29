#define _DEFAULT_SOURCE

#include "helper_jobs.h"

#include "route_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void helper_jobs_init(helper_jobs_t *jobs) {
    if (!jobs) return;
    memset(jobs, 0, sizeof *jobs);
    for (size_t i = 0; i < HELPER_JOB_MAX; ++i) jobs->jobs[i].fd = -1;
}

/* senkod's descriptors are not all close-on-exec: a helper, and the
   amneziawg daemon it starts, would otherwise keep the utun and the control
   socket open after senkod closed them */
static void close_inherited(void) {
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 4096) max = 4096;
    for (long fd = STDERR_FILENO + 1; fd < max; ++fd) close((int)fd);
}

static void set_reason(char *reason, size_t cap, const char *what, int value) {
    if (!reason || !cap) return;
    snprintf(reason, cap, "%s", what);
    if (value) route_errno_append(reason, cap, value);
}

int helper_jobs_start(helper_jobs_t *jobs, char *const argv[], int client_slot,
                      uint64_t client_generation, int64_t now_ms,
                      char *reason, size_t reason_cap) {
    if (reason && reason_cap) reason[0] = '\0';
    if (!jobs || !argv || !argv[0]) return -1;
    helper_job_t *job = NULL;
    for (size_t i = 0; i < HELPER_JOB_MAX && !job; ++i)
        if (!jobs->jobs[i].used) job = &jobs->jobs[i];
    if (!job) {
        set_reason(reason, reason_cap, "too many helper requests are running", 0);
        return -1;
    }
    if (access(argv[0], X_OK) != 0) {
        char what[160];
        snprintf(what, sizeof what, "the helper %s cannot be run", argv[0]);
        set_reason(reason, reason_cap, what, errno);
        return -1;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        set_reason(reason, reason_cap, "cannot create a pipe for the helper", errno);
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        set_reason(reason, reason_cap, "cannot start the helper", saved);
        return -1;
    }
    if (pid == 0) {
        /* only async-signal-safe calls until exec: senkod has other threads */
        dup2(pipefd[1], STDOUT_FILENO);
        close_inherited();
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    (void)fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    (void)fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    memset(job, 0, sizeof *job);
    job->used = 1;
    job->pid = pid;
    job->fd = pipefd[0];
    job->client_slot = client_slot;
    job->client_generation = client_generation;
    job->started_ms = now_ms;
    job->deadline_ms = now_ms + HELPER_JOB_TIMEOUT_MS;
    return 0;
}

size_t helper_jobs_fds(const helper_jobs_t *jobs, int *fds, size_t cap) {
    size_t n = 0;
    for (size_t i = 0; jobs && i < HELPER_JOB_MAX && n < cap; ++i)
        if (jobs->jobs[i].used && jobs->jobs[i].fd >= 0) fds[n++] = jobs->jobs[i].fd;
    return n;
}

static void drain(helper_job_t *job) {
    for (;;) {
        char chunk[256];
        ssize_t got = read(job->fd, chunk, sizeof chunk);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return; /* EAGAIN: more later */
        if (got == 0) {
            close(job->fd);
            job->fd = -1;
            return;
        }
        size_t room = sizeof job->output - 1 - job->output_len;
        size_t take = (size_t)got < room ? (size_t)got : room;
        memcpy(job->output + job->output_len, chunk, take);
        job->output_len += take;
        job->output[job->output_len] = '\0';
    }
}

void helper_jobs_service(helper_jobs_t *jobs, int64_t now_ms,
                         void (*done)(void *ctx, const helper_job_done_t *job),
                         void *ctx) {
    if (!jobs) return;
    for (size_t i = 0; i < HELPER_JOB_MAX; ++i) {
        helper_job_t *job = &jobs->jobs[i];
        if (!job->used) continue;
        if (job->fd >= 0) drain(job);
        if (!job->reaped) {
            pid_t got = waitpid(job->pid, &job->status, WNOHANG);
            if (got == job->pid) {
                job->reaped = 1;
                /* a child of the helper may still hold the pipe; its output
                   gets one more second */
                if (job->deadline_ms > now_ms + 1000) job->deadline_ms = now_ms + 1000;
            } else if (now_ms >= job->deadline_ms) {
                kill(job->pid, SIGKILL);
                while (waitpid(job->pid, &job->status, 0) < 0 && errno == EINTR) {}
                job->reaped = 1;
                job->timed_out = 1;
            }
        }
        if (job->fd >= 0 && job->reaped && now_ms >= job->deadline_ms) {
            close(job->fd);
            job->fd = -1;
        }
        if (!job->reaped || job->fd >= 0) continue;

        helper_job_done_t result;
        memset(&result, 0, sizeof result);
        result.client_slot = job->client_slot;
        result.client_generation = job->client_generation;
        result.elapsed_ms = now_ms - job->started_ms;
        result.timed_out = job->timed_out;
        result.exit_code = job->timed_out || !WIFEXITED(job->status)
            ? -1 : WEXITSTATUS(job->status);
        result.output = job->output;
        result.output_len = job->output_len;
        if (done) done(ctx, &result);
        memset(job, 0, sizeof *job);
        job->fd = -1;
    }
}

void helper_jobs_stop(helper_jobs_t *jobs) {
    if (!jobs) return;
    for (size_t i = 0; i < HELPER_JOB_MAX; ++i) {
        helper_job_t *job = &jobs->jobs[i];
        if (!job->used) continue;
        if (!job->reaped) {
            kill(job->pid, SIGKILL);
            while (waitpid(job->pid, NULL, 0) < 0 && errno == EINTR) {}
        }
        if (job->fd >= 0) close(job->fd);
        memset(job, 0, sizeof *job);
        job->fd = -1;
    }
}

int helper_detached_start(char *const argv[], const char *log_path,
                          char *reason, size_t reason_cap) {
    if (reason && reason_cap) reason[0] = '\0';
    if (!argv || !argv[0] || !log_path) return -1;
    if (access(argv[0], X_OK) != 0) {
        char what[160];
        snprintf(what, sizeof what, "the helper %s cannot be run", argv[0]);
        set_reason(reason, reason_cap, what, errno);
        return -1;
    }
    /* the app reads the progress from this file, as mobile. append mode
       because dpkg writes into the same file through its own descriptor */
    int log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (log_fd < 0) {
        set_reason(reason, reason_cap, "cannot create the update log", errno);
        return -1;
    }
    (void)fchmod(log_fd, 0644);
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(log_fd);
        set_reason(reason, reason_cap, "cannot start the update", saved);
        return -1;
    }
    if (pid == 0) {
        /* a session of its own: stopping senkod's launchd job, which the
           package scripts do, must not take the update down with it */
        setsid();
        if (fork() != 0) _exit(0);
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) dup2(null_fd, STDIN_FILENO);
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close_inherited();
        execv(argv[0], argv);
        _exit(127);
    }
    close(log_fd);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 0;
}
