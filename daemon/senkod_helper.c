/* the work senkod hands to a child of its own: an amneziawg handshake probe
   and package updates. senkod runs its own binary in one of these modes, so no
   separate setuid helper exists (h3lix, doubleh3lix and sockport never gave
   one root when the app spawned it) and senkod's control loop never waits on
   dpkg or a server */
#define _DEFAULT_SOURCE

#include "senkod_helper.h"

#include "core/awg_config.h"
#include "core/awg_handshake.h"
#include "core/senko_time.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <dirent.h>
#endif
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/senko_paths.h"

extern char **environ;

#define PLIST  SENKO_LAUNCH_DAEMONS "/com.senko.senkod.plist"
#define SOCK   "/var/tmp/senkod.sock"
#define BIN    SENKO_USR_BIN "/senkod"
#define CFG    "/var/root/Library/Preferences/senko.cfg"
#define LABEL  "com.senko.senkod"
#define SYSTEM_LOG SENKO_SYSTEM_LOG
#define UPDATE_LOG SENKO_UPDATE_LOG
#define UPDATE_MAX_BYTES (64 * 1024 * 1024)
#define HELPER_LOCK "/var/tmp/senkod-helper.lock"
#define HELPER_LOCK_WAIT_MS 30000
#define COMMAND_TIMEOUT_MS 30000
#define DPKG_TIMEOUT_MS 180000

/* rootful ios 13 installs keep a compatibility copy under /var/jb while
   launchd resolves the canonical /usr paths. choose the executable
   and plist that actually belong to the running jailbreak before spawning. */
const char *senkod_binary_path(void) {
    static const char *path;
    static const char *candidates[] = {
        SENKO_USR_BIN "/senkod", "/usr/bin/senkod",
        "/var/jb/usr/bin/senkod", NULL
    };
    if (path) return path;
    for (int i = 0; candidates[i]; ++i) {
        if (access(candidates[i], X_OK) == 0) {
            path = candidates[i];
            break;
        }
    }
    return path ? path : BIN;
}

static const char *senko_daemon_plist(void) {
    static const char *path;
    static const char *candidates[] = {
        SENKO_LAUNCH_DAEMONS "/com.senko.senkod.plist",
        "/Library/LaunchDaemons/com.senko.senkod.plist",
        "/var/jb/Library/LaunchDaemons/com.senko.senkod.plist", NULL
    };
    if (path) return path;
    for (int i = 0; candidates[i]; ++i) {
        if (access(candidates[i], R_OK) == 0) {
            path = candidates[i];
            break;
        }
    }
    return path ? path : PLIST;
}

static int acquire_helper_lock(void) {
    int fd = open(HELPER_LOCK, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return -1;
    for (int waited = 0; waited < HELPER_LOCK_WAIT_MS; waited += 100) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
        if (errno != EWOULDBLOCK && errno != EAGAIN) break;
        usleep(100000);
    }
    close(fd);
    return -1;
}

/* stderr is the update log, which the app reads */
static void klog(const char *msg) {
    fprintf(stderr, "senkod: %s\n", msg);
}

static long elapsed_ms(const struct timeval *start, const struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000L +
           (end->tv_usec - start->tv_usec) / 1000L;
}

/* never leave dpkg, launchctl, or a helper waiting forever */
static int wait_child_timeout(pid_t pid, int timeout_ms, int *status) {
    struct timeval start, now;
    gettimeofday(&start, NULL);
    for (;;) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid) return 0;
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        gettimeofday(&now, NULL);
        if (elapsed_ms(&start, &now) >= timeout_ms) break;
        usleep(100000);
    }

    (void)kill(pid, SIGTERM);
    for (int i = 0; i < 10; ++i) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid) return 124;
        if (got < 0 && errno != EINTR) break;
        usleep(100000);
    }
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, status, 0) < 0 && errno == EINTR) {}
    return 124;
}

static int run_argv(char *const argv[]) {
    pid_t pid = 0;
    int rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
    if (rc != 0) return -1;
    int st = 0;
    if (wait_child_timeout(pid, COMMAND_TIMEOUT_MS, &st) != 0) return 124;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static int run_capture_text(char *const argv[], char *out, size_t cap) {
    if (!argv || !argv[0] || !out || cap == 0) return -1;
    out[0] = '\0';
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    int action_rc = posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
    if (action_rc == 0)
        action_rc = posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
                                                      O_WRONLY, 0);
    if (action_rc == 0)
        action_rc = posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    if (action_rc == 0)
        action_rc = posix_spawn_file_actions_addclose(&fa, pipefd[1]);
    pid_t pid = 0;
    int spawn_rc = action_rc == 0
        ? posix_spawn(&pid, argv[0], &fa, NULL, argv, environ)
        : -1;
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    if (spawn_rc != 0) {
        close(pipefd[0]);
        return -1;
    }

    size_t used = 0;
    int truncated = 0;
    for (;;) {
        char buf[256];
        ssize_t n = read(pipefd[0], buf, sizeof buf);
        if (n > 0) {
            size_t keep = (size_t)n;
            size_t room = used < cap - 1 ? cap - 1 - used : 0;
            if (keep > room) {
                keep = room;
                truncated = 1;
            }
            if (keep > 0) {
                memcpy(out + used, buf, keep);
                used += keep;
                out[used] = '\0';
            }
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(pipefd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status)) return -1;
    if (truncated) return -1;
    out[strcspn(out, "\r\n")] = '\0';
    return WEXITSTATUS(status);
}

static int run_logged_timeout(char *const argv[], int timeout_ms) {
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) return -1;
    int action_rc = posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, UPDATE_LOG,
                                                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (action_rc == 0)
        action_rc = posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, UPDATE_LOG,
                                                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    pid_t pid = 0;
    int spawn_rc = action_rc == 0
        ? posix_spawn(&pid, argv[0], &fa, NULL, argv, environ)
        : -1;
    posix_spawn_file_actions_destroy(&fa);
    if (spawn_rc != 0) return -1;
    int status = 0;
    if (wait_child_timeout(pid, timeout_ms, &status) != 0) return 124;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int find_bin(const char *const *cands, char *out, size_t cap) {
    for (int i = 0; cands[i]; ++i) {
        if (access(cands[i], X_OK) == 0) {
            snprintf(out, cap, "%s", cands[i]);
            return 0;
        }
    }
    return -1;
}

/* accept mobile and temporary paths, including their /private aliases */
static int update_path_ok(const char *path) {
    if (!path || !path[0] || strstr(path, "..") != NULL) return 0;
    int under = 0;
    if (strncmp(path, "/var/mobile/", 12) == 0) under = 1;
    else if (strncmp(path, "/private/var/mobile/", 20) == 0) under = 1;
    else if (strncmp(path, "/tmp/", 5) == 0) under = 1;
    else if (strncmp(path, "/private/tmp/", 13) == 0) under = 1;
    else if (strncmp(path, "/var/tmp/", 9) == 0) under = 1;
    else if (strncmp(path, "/private/var/tmp/", 17) == 0) under = 1;
    if (!under) return 0;
    size_t len = strlen(path);
    if (len < 5) return 0;
    const char *ext = path + len - 4;
    if (!((ext[0] == '.' ) &&
          (ext[1] == 'd' || ext[1] == 'D') &&
          (ext[2] == 'e' || ext[2] == 'E') &&
          (ext[3] == 'b' || ext[3] == 'B')))
        return 0;
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    return st.st_size > 0 && st.st_size <= UPDATE_MAX_BYTES;
}

static int update_stage_copy(const char *src, char *dst, size_t dstcap) {
    if (!src || !dst || dstcap < 40) return -1;
    char tmpl[] = "/tmp/senko-update-XXXXXX";
    int out = mkstemp(tmpl);
    if (out < 0) return -1;
    int in = open(src, O_RDONLY);
    if (in < 0) {
        close(out);
        unlink(tmpl);
        return -1;
    }
    char buf[8192];
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(in);
            close(out);
            unlink(tmpl);
            return -1;
        }
        if (n == 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                close(in);
                close(out);
                unlink(tmpl);
                return -1;
            }
            off += w;
        }
    }
    close(in);
    (void)fchmod(out, 0644);
    if (fsync(out) != 0) {
        /* old jailbreak filesystems may not support fsync */
    }
    close(out);
    if (strlen(tmpl) + 1 > dstcap) {
        unlink(tmpl);
        return -1;
    }
    memcpy(dst, tmpl, strlen(tmpl) + 1);
    return 0;
}

/* the control socket answers an unauthenticated STATUS with the auth challenge,
   and only senkod speaks that. checking for the state line alone meant every
   probe failed once the control token landed: the helper then killed a healthy
   daemon, spent its whole repair budget, and reported a start failure while the
   daemon it killed had been answering the app all along */
static int reply_proves_daemon(const char *buf, size_t len) {
    static const char challenge[] = "ERR auth required";
    if (len >= 6 && memcmp(buf, "STATE ", 6) == 0) return 1;
    return len >= sizeof challenge - 1 &&
           memcmp(buf, challenge, sizeof challenge - 1) == 0;
}

static int sock_alive(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return 0;
    }
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    const char *req = "STATUS\n";
    if (write(fd, req, 7) != 7) {
        close(fd);
        return 0;
    }
    char buf[96];
    size_t tot = 0;
    while (tot + 1 < sizeof buf) {
        ssize_t n = read(fd, buf + tot, sizeof buf - 1 - tot);
        if (n > 0) {
            tot += (size_t)n;
            buf[tot] = '\0';
            if (memchr(buf, '\n', tot)) break;
            continue;
        }
        break;
    }
    close(fd);
    return reply_proves_daemon(buf, tot);
}

static int wait_sock(int tenths) {
    for (int i = 0; i < tenths; ++i) {
        if (sock_alive()) return 0;
        usleep(100000);
    }
    return -1;
}

static int wait_sock_down(int tenths) {
    for (int i = 0; i < tenths; ++i) {
        if (!sock_alive()) return 0;
        usleep(100000);
    }
    return sock_alive() ? -1 : 0;
}

/* start senkod without launchd */
static int spawn_senkod_direct(void) {
    const char *bin = senkod_binary_path();
    char *argv[] = {
        (char *)bin,
        (char *)"--managed",
        (char *)"--ctl", (char *)SOCK,
        (char *)"--config", (char *)CFG,
        NULL
    };

    posix_spawn_file_actions_t fa;
    int action_rc = posix_spawn_file_actions_init(&fa);
    if (action_rc != 0) {
        char msg[128];
        snprintf(msg, sizeof msg, "direct spawn setup failed (%d: %s)",
                 action_rc, strerror(action_rc));
        klog(msg);
        return -1;
    }
    /* keep both backends in one append-only stream for the ui */
    action_rc = posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, SYSTEM_LOG,
                                                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (action_rc == 0)
        action_rc = posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, SYSTEM_LOG,
                                                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (action_rc != 0) {
        char msg[128];
        snprintf(msg, sizeof msg, "direct spawn log setup failed (%d: %s)",
                 action_rc, strerror(action_rc));
        posix_spawn_file_actions_destroy(&fa);
        klog(msg);
        return -1;
    }

    pid_t pid = 0;
    int rc = posix_spawn(&pid, bin, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof msg, "direct spawn failed (%d: %s)",
                 rc, strerror(rc));
        klog(msg);
        return -1;
    }

    return 0;
}

/* this process is a senkod too, so killall senkod would end the update that
   called it. signals every other process named senkod; returns how many */
static int signal_other_senkod(int sig) {
    pid_t self = getpid();
    int count = 0;
#ifdef __APPLE__
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0) return 0;
    len += len / 4; /* processes started between the two calls */
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return 0;
    if (sysctl(mib, 3, procs, &len, NULL, 0) != 0) {
        free(procs);
        return 0;
    }
    for (size_t i = 0; i < len / sizeof *procs; ++i) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid == self || strncmp(procs[i].kp_proc.p_comm, "senkod", sizeof procs[i].kp_proc.p_comm) != 0)
            continue;
        if (kill(pid, sig) == 0) ++count;
    }
    free(procs);
#else
    DIR *dir = opendir("/proc");
    if (!dir) return 0;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        char *end = NULL;
        long pid = strtol(e->d_name, &end, 10);
        if (!end || *end || pid <= 0 || (pid_t)pid == self) continue;
        char path[64], comm[32] = "";
        snprintf(path, sizeof path, "/proc/%ld/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (!fgets(comm, sizeof comm, f)) comm[0] = '\0';
        fclose(f);
        comm[strcspn(comm, "\n")] = '\0';
        if (strcmp(comm, "senkod") == 0 && kill((pid_t)pid, sig) == 0) ++count;
    }
    closedir(dir);
#endif
    return count;
}

static void kill_senkod(void) {
    (void)signal_other_senkod(SIGKILL);
}

static int senkod_alive(void) {
    return signal_other_senkod(0) > 0;
}

static int wait_senkod_down(int tenths) {
    for (int i = 0; i < tenths; ++i) {
        if (!senkod_alive()) return 0;
        usleep(100000);
    }
    return senkod_alive() ? -1 : 0;
}

static int launch_job_loaded(const char *launchctl) {
    char output[256];
    char *argv[] = { (char *)launchctl, (char *)"list", (char *)LABEL, NULL };
    return run_capture_text(argv, output, sizeof output) == 0;
}

static int launch_job_stop(const char *launchctl) {
    char *unload[] = { (char *)launchctl, (char *)"unload",
                       (char *)senko_daemon_plist(), NULL };
    char *remove[] = { (char *)launchctl, (char *)"remove", (char *)LABEL, NULL };
    (void)run_argv(unload);
    (void)run_argv(remove);
    if (launch_job_loaded(launchctl)) return -1;
    kill_senkod();
    (void)wait_senkod_down(30);
    (void)wait_sock_down(30);
    unlink(SOCK);
    return 0;
}

static void stop_senkod_for_update(void) {
    char launchctl[64];
    static const char *launchctl_paths[] = {
        SENKO_JBROOT "/bin/launchctl", SENKO_USR_BIN "/launchctl",
        "/bin/launchctl", "/usr/bin/launchctl", "/sbin/launchctl",
        "/usr/sbin/launchctl", NULL
    };
    if (find_bin(launchctl_paths, launchctl, sizeof launchctl) == 0) {
        char *unload[] = { launchctl, (char *)"unload",
                           (char *)senko_daemon_plist(), NULL };
        (void)run_argv(unload);
        char *remove[] = { launchctl, (char *)"remove", (char *)LABEL, NULL };
        (void)run_argv(remove);
    }
    (void)signal_other_senkod(SIGTERM);
    usleep(700000);
    kill_senkod();
    (void)wait_senkod_down(30);
    (void)wait_sock_down(30);
    unlink(SOCK);
}

static int ensure_senkod(void);

static int restart_senkod_after_update(void) {
    return ensure_senkod();
}

static void update_stage(const char *name) {
    /* flush progress lines immediately */
    printf("UPDATE STAGE %s\n", name);
    fflush(stdout);
}

static int update_package(const char *path) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* keep SpringBoard alive until dpkg exits */
    setenv("SENKO_SKIP_RESPRING", "1", 1);
    /* postinst must not restart senkod: this update does it once dpkg is done */
    setenv("SENKO_UPDATE", "1", 1);

    if (!update_path_ok(path)) {
        fputs("UPDATE ERR invalid package path\n", stdout);
        return 1;
    }
    if (access(path, R_OK) != 0) {
        fputs("UPDATE ERR package not readable\n", stdout);
        return 1;
    }

    update_stage("checking package");

    char staged[96];
    staged[0] = '\0';
    if (update_stage_copy(path, staged, sizeof staged) != 0) {
        fputs("UPDATE ERR cannot stage package\n", stdout);
        return 1;
    }
    const char *pkg_path = staged;

    char dpkg_deb[64];
    static const char *dpkg_deb_paths[] = {
        SENKO_USR_BIN "/dpkg-deb", SENKO_JBROOT "/bin/dpkg-deb",
        "/usr/bin/dpkg-deb", "/bin/dpkg-deb", "/sbin/dpkg-deb", NULL
    };
    if (find_bin(dpkg_deb_paths, dpkg_deb, sizeof dpkg_deb) != 0) {
        unlink(staged);
        fputs("UPDATE ERR dpkg-deb missing\n", stdout);
        return 1;
    }

    char package[128];
    char *field_argv[] = { dpkg_deb, (char *)"-f", (char *)pkg_path,
                           (char *)"Package", NULL };
    if (run_capture_text(field_argv, package, sizeof package) != 0 ||
        strcmp(package, "com.senko.daemon") != 0) {
        unlink(staged);
        fputs("UPDATE ERR package is not Senko\n", stdout);
        return 1;
    }

    char version[128];
    char *version_argv[] = { dpkg_deb, (char *)"-f", (char *)pkg_path,
                             (char *)"Version", NULL };
    if (run_capture_text(version_argv, version, sizeof version) != 0 || !version[0]) {
        unlink(staged);
        fputs("UPDATE ERR package version missing\n", stdout);
        return 1;
    }

    char arch[128];
    char *arch_argv[] = { dpkg_deb, (char *)"-f", (char *)pkg_path,
                          (char *)"Architecture", NULL };
    if (run_capture_text(arch_argv, arch, sizeof arch) != 0 ||
        (strcmp(arch, "iphoneos-arm") != 0 &&
         strcmp(arch, "iphoneos-arm64") != 0 &&
         strcmp(arch, "all") != 0)) {
        unlink(staged);
        fputs("UPDATE ERR package architecture mismatch\n", stdout);
        return 1;
    }
    printf("UPDATE META version %s\n", version);
    fflush(stdout);

    /* a running amneziawg profile stays recorded in AWG_BACKEND_ACTIVE_PATH,
       and the new senkod brings it back up by itself */
    update_stage("stopping daemon");
    stop_senkod_for_update();

    char dpkg[64];
    static const char *dpkg_paths[] = {
        SENKO_USR_BIN "/dpkg", SENKO_JBROOT "/bin/dpkg",
        "/usr/bin/dpkg", "/bin/dpkg", "/sbin/dpkg", NULL
    };
    if (find_bin(dpkg_paths, dpkg, sizeof dpkg) != 0) {
        unlink(staged);
        (void)restart_senkod_after_update();
        fputs("UPDATE ERR dpkg missing\n", stdout);
        return 1;
    }

    update_stage("installing");
    char *install_argv[] = { dpkg, (char *)"--install", (char *)pkg_path, NULL };
    int rc = run_logged_timeout(install_argv, DPKG_TIMEOUT_MS);
    unlink(staged);
    update_stage("starting daemon");
    int daemon_rc = restart_senkod_after_update();
    if (rc == 124) {
        printf("UPDATE ERR dpkg timeout after %d seconds\n", DPKG_TIMEOUT_MS / 1000);
        return 1;
    }
    if (rc != 0) {
        printf("UPDATE ERR dpkg exit %d\n", rc);
        return 1;
    }
    if (daemon_rc != 0) {
        fputs("UPDATE ERR daemon did not start\n", stdout);
        return 1;
    }
    update_stage("done");
    printf("UPDATE OK %s\n", version);
    return 0;
}

/* repair launchd, then fall back to a direct start */
static int ensure_senkod(void) {
    if (sock_alive()) {
        klog("already up");
        return 0;
    }

    char lc[64];
    static const char *lcs[] = {
        SENKO_JBROOT "/bin/launchctl", SENKO_USR_BIN "/launchctl",
        "/bin/launchctl", "/usr/bin/launchctl",
        "/sbin/launchctl", "/usr/sbin/launchctl", NULL
    };
    int have_lc = (find_bin(lcs, lc, sizeof lc) == 0);

    /* a job launchd already holds may still be starting, and waiting for it
       beats racing it. when launchd does not hold the job there is nothing to
       wait for, and the long wait was six seconds of nothing on every launch
       of the app */
    if (wait_sock(have_lc && launch_job_loaded(lc) ? 60 : 5) == 0) {
        klog("already up via launchctl");
        return 0;
    }

    const char *bin = senkod_binary_path();
    if (access(bin, X_OK) != 0) {
        klog("senkod missing");
        return 2;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        const char *plist = senko_daemon_plist();
        if (have_lc && access(plist, R_OK) == 0) {
            if (!launch_job_loaded(lc)) {
                char *load[] = { lc, (char *)"load", (char *)plist, NULL };
                if (run_argv(load) != 0) {
                    char *loadw[] = { lc, (char *)"load", (char *)"-w",
                                      (char *)plist, NULL };
                    (void)run_argv(loadw);
                }
            }
            char *start[] = { lc, (char *)"start", (char *)LABEL, NULL };
            (void)run_argv(start);

            if (wait_sock(180) == 0) {
                klog("up via launchctl");
                return 0;
            }
            if (launch_job_stop(lc) != 0) {
                klog("launchd job still loaded; retrying repair");
                (void)run_argv((char *[]) { lc, (char *)"remove", (char *)LABEL, NULL });
                if (launch_job_loaded(lc)) return 5;
            }
            klog("launchd handoff complete, trying direct spawn");
        } else {
            klog("no launchctl/plist, direct spawn");
        }

        kill_senkod();
        (void)wait_senkod_down(60);
        (void)wait_sock_down(60);
        unlink(SOCK);
        if (spawn_senkod_direct() == 0 && wait_sock(120) == 0) {
            klog("up via direct spawn");
            return 0;
        }

        klog(attempt == 0 ? "direct start failed, retrying" :
             "senkod did not open sock");
    }

    return 5;
}

/* a handshake with the server and nothing else: no utun, no routes. it runs
   in a child so the control loop never waits on the server */
static int awg_probe(const char *path) {
    if (!awg_config_path_ok(path)) {
        printf("error the config is not a .conf file in %s: %.120s\n",
               AWG_CONFIG_DIR, path);
        return 1;
    }
    awg_config_t cfg;
    char why[160];
    if (awg_config_load_file(path, &cfg, why, sizeof why) != AWG_CFG_OK) {
        printf("error config rejected: %s\n", why);
        return 1;
    }
    int64_t started = senko_now_ms();
    awg_hs_status_t r = awg_handshake_probe(&cfg, 5000, why, sizeof why);
    int64_t took = senko_now_ms() - started;
    OPENSSL_cleanse(&cfg, sizeof cfg);
    if (r != AWG_HS_OK) {
        printf("error %s\n", why);
        return 1;
    }
    printf("PING %lld\n", (long long)took);
    return 0;
}

int senkod_helper_main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "--awg-probe") != 0 && strcmp(argv[1], "--update") != 0))
        return -1;
    signal(SIGPIPE, SIG_IGN);
    if (argc != 3) {
        fprintf(stderr, "senkod: %s takes one path\n", argv[1]);
        return 2;
    }
    if (strcmp(argv[1], "--awg-probe") == 0) return awg_probe(argv[2]);
    if (geteuid() != 0) {
        fprintf(stderr, "senkod: --update needs root, ask senkod over its control socket\n");
        return 1;
    }
    int lock = acquire_helper_lock();
    if (lock < 0) {
        klog("another update still holds the helper lock");
        fputs("UPDATE ERR another update is running\n", stdout);
        return 3;
    }
    return update_package(argv[2]);
}
