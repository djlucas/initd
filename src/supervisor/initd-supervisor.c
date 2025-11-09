/* initd-supervisor.c - Privileged supervisor process
 *
 * Responsibilities:
 * - Fork supervisor-worker and drop privileges
 * - Handle privileged requests from worker (fork/exec services)
 * - Set up cgroups (Linux only)
 * - Set up namespaces
 * - Drop privileges before exec
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE  /* for unshare(), CLONE_NEWNS */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <syslog.h>
#include <dirent.h>
#ifdef __linux__
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <linux/loop.h>
#include <sys/prctl.h>
#include <sched.h>       /* for unshare(), CLONE_NEWNS */
#include <sys/sysmacros.h> /* for makedev() */
#endif
#ifdef __FreeBSD__
#include <sys/procctl.h>
#endif
#if defined(__linux__) && defined(__HAVE_LIBCAP__)
#include <sys/capability.h>
#endif
#include "../common/ipc.h"
#include "../common/privileged-ops.h"
#include "../common/parser.h"
#include "../common/path-security.h"
#include "../common/control.h"
#include "../common/log-enhanced.h"
#include "service-registry.h"
#include "process-tracking.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexec/initd/initd-supervisor-worker"
#endif

#ifndef SUPERVISOR_USER
#define SUPERVISOR_USER "initd-supervisor"
#endif

/* Shutdown types */
enum shutdown_type {
    SHUTDOWN_NONE = 0,
    SHUTDOWN_POWEROFF,
    SHUTDOWN_REBOOT,
    SHUTDOWN_HALT
};

static volatile sig_atomic_t shutdown_requested = 0;
static enum shutdown_type shutdown_type = SHUTDOWN_NONE;
static pid_t worker_pid = 0;
static int ipc_socket = -1;
static bool user_mode = false;
#ifdef UNIT_TEST
static bool debug_mode __attribute__((unused)) = false;
#else
static bool debug_mode = false;
#endif

#if defined(__linux__) && !defined(UNIT_TEST)
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static int ensure_run_tmpfs(void) {
    struct statfs fs;
    if (statfs("/run", &fs) == 0 && fs.f_type == TMPFS_MAGIC) {
        return 0; /* already tmpfs */
    }

    struct stat st;
    if (stat("/run", &st) < 0) {
        if (errno == ENOENT) {
            if (mkdir("/run", 0755) < 0 && errno != EEXIST) {
                return -1;
            }
        } else {
            return -1;
        }
    }

    if (mount("tmpfs", "/run", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_STRICTATIME,
              "mode=0755") < 0) {
        if (errno != EBUSY) {
            return -1;
        }

        if (statfs("/run", &fs) < 0 || fs.f_type != TMPFS_MAGIC) {
            return -1;
        }
    }

    return 0;
}
#endif

static int build_exec_argv(const char *command, char ***argv_out) {
    if (!command || command[0] == '\0' || !argv_out) {
        errno = EINVAL;
        return -1;
    }

    char *copy = strdup(command);
    if (!copy) {
        return -1;
    }

    size_t capacity = 8;
    size_t argc = 0;
    char **argv = calloc(capacity, sizeof(char *));
    if (!argv) {
        free(copy);
        return -1;
    }

    char *saveptr = NULL;
    const char *token = strtok_r(copy, " \t", &saveptr);
    while (token) {
        if (argc + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char **tmp = realloc(argv, new_capacity * sizeof(char *));
            if (!tmp) {
                goto error;
            }
            argv = tmp;
            capacity = new_capacity;
        }

        argv[argc] = strdup(token);
        if (!argv[argc]) {
            goto error;
        }
        argc++;

        token = strtok_r(NULL, " \t", &saveptr);
    }

    free(copy);

    if (argc == 0) {
        free(argv);
        errno = EINVAL;
        return -1;
    }

    argv[argc] = NULL;
    *argv_out = argv;
    return 0;

error:
    if (argv) {
        for (size_t i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);
    }
    free(copy);
    return -1;
}

static void free_exec_argv(char **argv) {
    if (!argv) {
        return;
    }
    for (size_t i = 0; argv[i] != NULL; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* Forward declaration */
static void scrub_dangerous_environment(void);

static int run_lifecycle_command(const struct service_section *service,
                                 const char *command,
                                 uid_t validated_uid,
                                 gid_t validated_gid,
                                 const char *unit_name,
                                 const char *stage,
                                 bool prepare_environment) {
    if (!command || command[0] == '\0') {
        return 0;
    }

    char **argv = NULL;
    if (build_exec_argv(command, &argv) < 0) {
        log_error("supervisor", "%s for %s failed to parse command", stage, unit_name);
        return -1;
    }

    const char *exec_path = argv[0];
    if (!exec_path || exec_path[0] != '/') {
        log_error("supervisor", "%s for %s must use absolute path", stage, unit_name);
        free_exec_argv(argv);
        errno = EINVAL;
        return -1;
    }

    if (strstr(exec_path, "..") != NULL) {
        log_error("supervisor", "%s for %s path contains '..'", stage, unit_name);
        free_exec_argv(argv);
        errno = EINVAL;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        log_error("supervisor", "fork lifecycle command: %s", strerror(saved_errno));
        free_exec_argv(argv);
        errno = saved_errno;
        return -1;
    }

    if (pid == 0) {
        if (setsid() < 0) {
            log_error("supervisor", "setsid (lifecycle): %s", strerror(errno));
        }

        if (prepare_environment) {
            if (setup_service_environment(service) < 0) {
                log_error("supervisor", "%s failed to setup environment for %s",
                          stage, unit_name);
                _exit(1);
            }
        }

        if (validated_gid != 0) {
            if (setgroups(1, &validated_gid) < 0) {
                log_error("supervisor", "setgroups (lifecycle): %s", strerror(errno));
                _exit(1);
            }
            if (setgid(validated_gid) < 0) {
                log_error("supervisor", "setgid (lifecycle): %s", strerror(errno));
                _exit(1);
            }
        }

        if (validated_uid != 0) {
            if (setuid(validated_uid) < 0) {
                log_error("supervisor", "setuid (lifecycle): %s", strerror(errno));
                _exit(1);
            }
        }

        if (validated_uid != 0) {
            if (setuid(0) == 0 || seteuid(0) == 0) {
                log_error("supervisor", "SECURITY: %s for %s can regain root!",
                          stage, unit_name);
                _exit(1);
            }
        }

        /* SECURITY: Scrub dangerous environment variables */
        scrub_dangerous_environment();

        execv(exec_path, argv);
        log_error("supervisor", "execv lifecycle: %s", strerror(errno));
        _exit(1);
    }

    free_exec_argv(argv);

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        int saved_errno = errno;
        log_error("supervisor", "waitpid lifecycle: %s", strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("supervisor", "%s for %s failed (status=%d)",
                  stage, unit_name,
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        errno = ECANCELED;
        return -1;
    }

    return 0;
}

static int run_exec_command_list(const struct service_section *service,
                                 char *const list[],
                                 int count,
                                 uid_t validated_uid,
                                 gid_t validated_gid,
                                 const char *unit_name,
                                 const char *stage,
                                 bool prepare_environment) {
    if (!list || count <= 0) {
        return 0;
    }

    for (int i = 0; i < count; i++) {
        if (!list[i] || list[i][0] == '\0') {
            continue;
        }

        char stage_name[64];
        if (count > 1) {
            snprintf(stage_name, sizeof(stage_name), "%s[%d]", stage, i);
        } else {
            snprintf(stage_name, sizeof(stage_name), "%s", stage);
        }

        if (run_lifecycle_command(service,
                                   list[i],
                                   validated_uid,
                                   validated_gid,
                                   unit_name,
                                   stage_name,
                                   prepare_environment) < 0) {
            return -1;
        }
    }

    return 0;
}

static pid_t read_pid_file_with_timeout(const char *path,
                                        int attempts,
                                        int interval_ms) {
    if (!path || path[0] == '\0' || attempts <= 0) {
        return -1;
    }

    for (int i = 0; i < attempts; i++) {
        FILE *f = fopen(path, "r");
        if (f) {
            long pid;
            int scanned = fscanf(f, "%ld", &pid);
            fclose(f);
            if (scanned == 1 && pid > 0) {
                return (pid_t)pid;
            }
        }
        if (interval_ms > 0) {
            usleep((useconds_t)interval_ms * 1000);
        }
    }

    return -1;
}

static int fallback_to_nobody_allowed(void) {
    const char *env = getenv("INITD_ALLOW_USER_FALLBACK");
    if (!env) {
        return 0;
    }

    return (strcmp(env, "1") == 0 ||
            strcmp(env, "true") == 0 ||
            strcmp(env, "TRUE") == 0 ||
            strcmp(env, "yes") == 0 ||
            strcmp(env, "YES") == 0);
}

static void warn_user_fallback(const char *component, const char *missing_user) {
    log_warn(component, "dedicated user '%s' not found; falling back to 'nobody'. "
             "This mode is UNSUPPORTED for production", missing_user);
}

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Reaping handled in main loop */
}

/* Setup signal handlers */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error("supervisor", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        log_error("supervisor", "sigaction SIGCHLD: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Create IPC socketpair for master/worker communication */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_ipc_socket(int *master_fd, int *worker_fd) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        log_error("supervisor", "socketpair: %s", strerror(errno));
        return -1;
    }

    *master_fd = sv[0];
    *worker_fd = sv[1];
    return 0;
}

/* Lookup unprivileged user for worker */
static int lookup_supervisor_user(uid_t *uid, gid_t *gid) {
    if (user_mode) {
        *uid = getuid();
        *gid = getgid();
        return 0;
    }

    const struct passwd *pw = getpwnam(SUPERVISOR_USER);
    if (!pw) {
        if (!fallback_to_nobody_allowed()) {
            log_error("supervisor",
                      "user '%s' not found. Create the dedicated account or set "
                      "INITD_ALLOW_USER_FALLBACK=1 to permit an UNSUPPORTED fallback to 'nobody'",
                      SUPERVISOR_USER);
            return -1;
        }

        warn_user_fallback("initd-supervisor", SUPERVISOR_USER);
        pw = getpwnam("nobody");
        if (!pw) {
            log_error("supervisor", "fallback user 'nobody' not found; cannot continue");
            return -1;
        }
    }

    *uid = pw->pw_uid;
    *gid = pw->pw_gid;

    log_debug("supervisor", "worker will run as %s (uid=%d, gid=%d)",
              pw->pw_name, *uid, *gid);
    return 0;
}

/* Fork and exec worker process */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static pid_t start_worker(int worker_fd) {
    uid_t worker_uid;
    gid_t worker_gid;

    /* Lookup unprivileged user */
    if (lookup_supervisor_user(&worker_uid, &worker_gid) < 0) {
        log_error("supervisor", "cannot find unprivileged user for worker");
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        log_error("supervisor", "fork worker: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: will become worker */
        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", worker_fd);

        /* Drop privileges before exec */
        if (!user_mode && worker_gid != 0) {
            /* Set supplementary groups */
            if (setgroups(1, &worker_gid) < 0) {
                log_error("supervisor", "setgroups: %s", strerror(errno));
                _exit(1);
            }

            /* Set GID */
            if (setgid(worker_gid) < 0) {
                log_error("supervisor", "setgid: %s", strerror(errno));
                _exit(1);
            }
        }

        if (!user_mode && worker_uid != 0) {
            /* Set UID (must be last) */
            if (setuid(worker_uid) < 0) {
                log_error("supervisor", "setuid: %s", strerror(errno));
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (!user_mode && (getuid() == 0 || geteuid() == 0)) {
            log_error("supervisor", "failed to drop privileges!");
            _exit(1);
        }

        log_debug("worker", "running as uid=%d, gid=%d", getuid(), getgid());

        /* Clear FD_CLOEXEC flag so worker_fd survives exec */
        int flags = fcntl(worker_fd, F_GETFD);
        if (flags >= 0) {
            fcntl(worker_fd, F_SETFD, flags & ~FD_CLOEXEC);
        }

        execl(WORKER_PATH, "initd-supervisor-worker", fd_str, NULL);
        log_error("supervisor", "exec worker: %s", strerror(errno));
        _exit(1);
    }

    /* Parent */
    close(worker_fd); /* Master doesn't need worker's end */
    log_info("supervisor", "Started worker (pid %d)", pid);
    return pid;
}

/* SECURITY: Scrub dangerous environment variables before exec
 * Removes LD_*, TMPDIR, IFS, and other variables that can hijack execution */
static void scrub_dangerous_environment(void) {
    static const char *dangerous_vars[] = {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_BIND_NOW",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_USE_LOAD_BIAS",
        "LD_DYNAMIC_WEAK",
        "LD_SHOW_AUXV",
        "LD_ORIGIN_PATH",
        "LD_HWCAP_MASK",
        "LD_AOUT_LIBRARY_PATH",
        "LD_AOUT_PRELOAD",
        "TMPDIR",
        "TEMP",
        "TMP",
        "IFS",
        "BASH_ENV",
        "ENV",
        "CDPATH",
        "GLOBIGNORE",
        "PS4",
        "SHELLOPTS",
        NULL
    };

    for (int i = 0; dangerous_vars[i] != NULL; i++) {
        unsetenv(dangerous_vars[i]);
    }
}

/* Start a service process with privilege dropping
 * Returns PID on success, -1 on error
 * On success, *stdout_pipe_fd and *stderr_pipe_fd are set to pipe read ends
 */
static pid_t start_service_process(const struct service_section *service,
                                   const char *unit_name,
                                   const char *exec_path,
                                   char *const argv[],
                                   uid_t validated_uid,
                                   gid_t validated_gid,
                                   int *stdout_pipe_fd,
                                   int *stderr_pipe_fd) {
    if (!service || !exec_path || !argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }

    /* Create pipes for stdout/stderr capture */
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    if (pipe(stdout_pipe) < 0) {
        log_error("supervisor", "pipe(stdout): %s", strerror(errno));
        return -1;
    }
    if (pipe(stderr_pipe) < 0) {
        log_error("supervisor", "pipe(stderr): %s", strerror(errno));
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        return -1;
    }

    /* Ensure parent's read ends do not leak across future execs */
    int flags = fcntl(stdout_pipe[0], F_GETFD);
    if (flags >= 0) {
        (void)fcntl(stdout_pipe[0], F_SETFD, flags | FD_CLOEXEC);
    }
    flags = fcntl(stderr_pipe[0], F_GETFD);
    if (flags >= 0) {
        (void)fcntl(stderr_pipe[0], F_SETFD, flags | FD_CLOEXEC);
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: will become service */

        /* Close read ends of pipes */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        /* Handle StandardInput/Output/Error */
        int tty_fd = -1;

        /* Open TTY if needed */
        if (service->standard_input == STDIO_TTY || service->standard_input == STDIO_TTY_FORCE ||
            service->standard_output == STDIO_TTY || service->standard_error == STDIO_TTY) {

            if (service->tty_path[0] != '\0') {
                /* Open TTY with O_NOFOLLOW to prevent symlink attacks */
                tty_fd = open(service->tty_path, O_RDWR | O_NOCTTY | O_NOFOLLOW);
                if (tty_fd < 0) {
                    log_error("supervisor", "open TTY %s: %s (use O_NOFOLLOW to prevent symlink attacks)",
                             service->tty_path, strerror(errno));
                    _exit(1);
                }
                /* Verify it's a character device (TTY) */
                struct stat st;
                if (fstat(tty_fd, &st) < 0 || !S_ISCHR(st.st_mode)) {
                    log_error("supervisor", "TTY path %s is not a character device", service->tty_path);
                    close(tty_fd);
                    _exit(1);
                }

                /* Make this our controlling terminal */
                if (ioctl(tty_fd, TIOCSCTTY, 0) < 0) {
                    if (service->standard_input != STDIO_TTY_FORCE) {
                        log_error("supervisor", "TIOCSCTTY %s: %s", service->tty_path, strerror(errno));
                        close(tty_fd);
                        _exit(1);
                    }
                }
            }
        }

        /* LogLevelMax= - set maximum log level for service output */
        if (service->log_level_max != -1) {
            /* Set LOG_LEVEL_MAX environment variable for the service
             * This allows services and logging infrastructure to respect the limit */
            char log_level_str[16];
            snprintf(log_level_str, sizeof(log_level_str), "%d", service->log_level_max);
            setenv("INITD_LOG_LEVEL_MAX", log_level_str, 1);

            /* Also set standard syslog level limit */
            setlogmask(LOG_UPTO(service->log_level_max));

            log_debug("supervisor", "Set LogLevelMax=%d for service output", service->log_level_max);
        }

        /* Type=notify - set NOTIFY_SOCKET for sd_notify protocol */
        if (service->type == SERVICE_NOTIFY
#ifndef HAVE_DBUS
            || service->type == SERVICE_DBUS  /* Type=dbus uses sd_notify fallback when no D-Bus */
#endif
           ) {
            /* Use filesystem socket (not abstract) for BSD portability */
            setenv("NOTIFY_SOCKET", "/run/initd/notify", 1);
            const char *type_str = service->type == SERVICE_NOTIFY ? "notify" : "dbus";
            log_debug("supervisor", "Set NOTIFY_SOCKET=/run/initd/notify for Type=%s service", type_str);
        }

        /* Setup stdin */
        if (service->standard_input == STDIO_NULL) {
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        } else if ((service->standard_input == STDIO_TTY || service->standard_input == STDIO_TTY_FORCE) && tty_fd >= 0) {
            if (dup2(tty_fd, STDIN_FILENO) < 0) {
                log_error("supervisor", "dup2(stdin, tty): %s", strerror(errno));
                close(tty_fd);
                _exit(1);
            }
        } else if (service->standard_input == STDIO_FILE && service->input_file[0] != '\0') {
            /* Open with O_NOFOLLOW to prevent symlink attacks */
            int file_fd = open(service->input_file, O_RDONLY | O_NOFOLLOW);
            if (file_fd < 0) {
                log_error("supervisor", "open input file %s: %s (use O_NOFOLLOW to prevent symlink attacks)",
                         service->input_file, strerror(errno));
                _exit(1);
            }
            /* Verify it's a regular file, not a device or special file */
            struct stat st;
            if (fstat(file_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
                log_error("supervisor", "input file %s is not a regular file", service->input_file);
                close(file_fd);
                _exit(1);
            }
            if (dup2(file_fd, STDIN_FILENO) < 0) {
                log_error("supervisor", "dup2(stdin, file): %s", strerror(errno));
                close(file_fd);
                _exit(1);
            }
            close(file_fd);
        } else if (service->standard_input == STDIO_DATA && service->input_data != NULL) {
            /* Create pipe and write data to it */
            int data_pipe[2];
            if (pipe(data_pipe) < 0) {
                log_error("supervisor", "pipe for input data: %s", strerror(errno));
                _exit(1);
            }
            /* Write data in blocking mode (should be small) */
            ssize_t written = write(data_pipe[1], service->input_data, service->input_data_size);
            if (written != (ssize_t)service->input_data_size) {
                log_error("supervisor", "write input data: %s", strerror(errno));
                close(data_pipe[0]);
                close(data_pipe[1]);
                _exit(1);
            }
            close(data_pipe[1]); /* Close write end */
            if (dup2(data_pipe[0], STDIN_FILENO) < 0) {
                log_error("supervisor", "dup2(stdin, data pipe): %s", strerror(errno));
                close(data_pipe[0]);
                _exit(1);
            }
            close(data_pipe[0]);
        }

        /* Setup stdout */
        if (service->standard_output == STDIO_NULL) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                close(devnull);
            }
        } else if (service->standard_output == STDIO_TTY && tty_fd >= 0) {
            if (dup2(tty_fd, STDOUT_FILENO) < 0) {
                log_error("supervisor", "dup2(stdout, tty): %s", strerror(errno));
                close(tty_fd);
                _exit(1);
            }
        } else if (service->standard_output == STDIO_FILE && service->output_file[0] != '\0') {
            /* Open with O_NOFOLLOW to prevent symlink attacks - O_CREAT + O_EXCL if new */
            int file_fd = open(service->output_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (file_fd < 0) {
                log_error("supervisor", "open output file %s: %s (use O_NOFOLLOW to prevent symlink attacks)",
                         service->output_file, strerror(errno));
                _exit(1);
            }
            /* Verify it's a regular file, not a device or special file */
            struct stat st;
            if (fstat(file_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
                log_error("supervisor", "output file %s is not a regular file", service->output_file);
                close(file_fd);
                _exit(1);
            }
            if (dup2(file_fd, STDOUT_FILENO) < 0) {
                log_error("supervisor", "dup2(stdout, file): %s", strerror(errno));
                close(file_fd);
                _exit(1);
            }
            close(file_fd);
        } else {
            /* Default: redirect to pipe (for logging to syslog) */
            if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0) {
                log_error("supervisor", "dup2(stdout): %s", strerror(errno));
                _exit(1);
            }
        }

        /* Setup stderr */
        if (service->standard_error == STDIO_NULL) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        } else if (service->standard_error == STDIO_TTY && tty_fd >= 0) {
            if (dup2(tty_fd, STDERR_FILENO) < 0) {
                log_error("supervisor", "dup2(stderr, tty): %s", strerror(errno));
                close(tty_fd);
                _exit(1);
            }
        } else if (service->standard_error == STDIO_FILE && service->error_file[0] != '\0') {
            /* Open with O_NOFOLLOW to prevent symlink attacks */
            int file_fd = open(service->error_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (file_fd < 0) {
                log_error("supervisor", "open error file %s: %s (use O_NOFOLLOW to prevent symlink attacks)",
                         service->error_file, strerror(errno));
                _exit(1);
            }
            /* Verify it's a regular file, not a device or special file */
            struct stat st;
            if (fstat(file_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
                log_error("supervisor", "error file %s is not a regular file", service->error_file);
                close(file_fd);
                _exit(1);
            }
            if (dup2(file_fd, STDERR_FILENO) < 0) {
                log_error("supervisor", "dup2(stderr, file): %s", strerror(errno));
                close(file_fd);
                _exit(1);
            }
            close(file_fd);
        } else {
            /* Default: redirect to pipe (for logging to syslog) */
            if (dup2(stderr_pipe[1], STDERR_FILENO) < 0) {
                log_error("supervisor", "dup2(stderr): %s", strerror(errno));
                _exit(1);
            }
        }

        /* Close TTY fd if we opened it (already dup2'd where needed) */
        if (tty_fd >= 0) {
            close(tty_fd);
        }

        /* Close write ends after dup2 */
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        /* Create new process group so we can kill all children with killpg() */
        if (process_tracking_setup_child() < 0) {
            log_error("supervisor", "setsid: %s", strerror(errno));
        }

        /* Setup service environment (PrivateTmp, LimitNOFILE) BEFORE dropping privileges */
        if (setup_service_environment(service) < 0) {
            log_error("supervisor", "failed to setup service environment");
            _exit(1);
        }

        /* Validate exec_path is absolute (prevent relative path attacks) */
        if (exec_path[0] != '/') {
            log_error("supervisor", "exec_path must be absolute: %s", exec_path);
            _exit(1);
        }

        /* Check for directory traversal attempts */
        if (strstr(exec_path, "..") != NULL) {
            log_error("supervisor", "exec_path contains '..': %s", exec_path);
            _exit(1);
        }

        /* Set up mount namespace for sandboxing directives (Linux-only) */
#ifdef __linux__
        if (service->protect_system > 0 || service->protect_home > 0 ||
            service->private_devices || service->protect_kernel_tunables ||
            service->protect_control_groups) {

            /* Create new mount namespace */
            if (unshare(CLONE_NEWNS) < 0) {
                log_error("supervisor", "unshare(CLONE_NEWNS): %s", strerror(errno));
                _exit(1);
            }

            /* Set mount propagation based on MountFlags= */
            unsigned long mount_flag;
            const char *mount_flag_name;
            if (service->mount_flags == 0) {
                mount_flag = MS_SHARED;
                mount_flag_name = "MS_SHARED";
            } else if (service->mount_flags == 1) {
                mount_flag = MS_SLAVE;
                mount_flag_name = "MS_SLAVE";
            } else {
                mount_flag = MS_PRIVATE;
                mount_flag_name = "MS_PRIVATE";
            }

            if (mount(NULL, "/", NULL, MS_REC | mount_flag, NULL) < 0) {
                log_error("supervisor", "mount(%s): %s", mount_flag_name, strerror(errno));
                _exit(1);
            }

            /* ProtectSystem= - make system directories read-only */
            if (service->protect_system >= 1) {
                /* yes/true: protect /usr and /boot */
                const char *sys_dirs[] = {"/usr", "/boot", NULL};
                for (int i = 0; sys_dirs[i]; i++) {
                    struct stat st;
                    if (stat(sys_dirs[i], &st) == 0) {
                        if (mount(sys_dirs[i], sys_dirs[i], NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                            log_warn("supervisor", "mount(%s, MS_RDONLY): %s", sys_dirs[i], strerror(errno));
                        }
                    }
                }
            }
            if (service->protect_system >= 2) {
                /* full: also protect /etc */
                struct stat st;
                if (stat("/etc", &st) == 0) {
                    if (mount("/etc", "/etc", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                        log_warn("supervisor", "mount(/etc, MS_RDONLY): %s", strerror(errno));
                    }
                }
            }
            if (service->protect_system >= 3) {
                /* strict: make entire / read-only except /dev, /proc, /sys */
                if (mount("/", "/", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                    log_warn("supervisor", "mount(/, MS_RDONLY): %s", strerror(errno));
                }
            }

            /* ProtectHome= - restrict access to home directories */
            if (service->protect_home >= 1) {
                const char *home_dirs[] = {"/home", "/root", NULL};
                for (int i = 0; home_dirs[i]; i++) {
                    struct stat st;
                    if (stat(home_dirs[i], &st) == 0) {
                        if (service->protect_home == 1) {
                            /* yes: make inaccessible (bind mount empty dir) */
                            if (mount("tmpfs", home_dirs[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_STRICTATIME, "mode=000") < 0) {
                                log_warn("supervisor", "mount(%s, tmpfs): %s", home_dirs[i], strerror(errno));
                            }
                        } else if (service->protect_home == 2) {
                            /* read-only */
                            if (mount(home_dirs[i], home_dirs[i], NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                                log_warn("supervisor", "mount(%s, MS_RDONLY): %s", home_dirs[i], strerror(errno));
                            }
                        } else if (service->protect_home == 3) {
                            /* tmpfs: mount empty tmpfs */
                            if (mount("tmpfs", home_dirs[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_STRICTATIME, "mode=0755") < 0) {
                                log_warn("supervisor", "mount(%s, tmpfs): %s", home_dirs[i], strerror(errno));
                            }
                        }
                    }
                }
            }

            /* PrivateDevices= - mount minimal /dev */
            if (service->private_devices) {
                if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=0755") < 0) {
                    log_warn("supervisor", "mount(/dev, tmpfs): %s", strerror(errno));
                }
                /* Create essential device nodes with correct major/minor and permissions */
                struct {
                    const char *name;
                    unsigned int major;
                    unsigned int minor;
                    mode_t mode;
                } devices[] = {
                    {"null",    1, 3, 0666},  /* /dev/null */
                    {"zero",    1, 5, 0666},  /* /dev/zero */
                    {"full",    1, 7, 0666},  /* /dev/full */
                    {"random",  1, 8, 0644},  /* /dev/random - read-only for non-root */
                    {"urandom", 1, 9, 0644},  /* /dev/urandom - read-only for non-root */
                    {"tty",     5, 0, 0666},  /* /dev/tty */
                    {NULL, 0, 0, 0}
                };
                for (int i = 0; devices[i].name; i++) {
                    char path[64];
                    snprintf(path, sizeof(path), "/dev/%s", devices[i].name);
                    if (mknod(path, S_IFCHR | devices[i].mode, makedev(devices[i].major, devices[i].minor)) < 0) {
                        log_warn("supervisor", "mknod(%s): %s", path, strerror(errno));
                    }
                }
            }

            /* ProtectKernelTunables= - make /proc/sys and /sys read-only */
            if (service->protect_kernel_tunables) {
                struct stat st;
                if (stat("/proc/sys", &st) == 0) {
                    if (mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                        log_warn("supervisor", "mount(/proc/sys, MS_RDONLY): %s", strerror(errno));
                    }
                }
                if (stat("/sys", &st) == 0) {
                    if (mount("/sys", "/sys", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                        log_warn("supervisor", "mount(/sys, MS_RDONLY): %s", strerror(errno));
                    }
                }
            }

            /* ProtectControlGroups= - make /sys/fs/cgroup read-only */
            if (service->protect_control_groups) {
                struct stat st;
                if (stat("/sys/fs/cgroup", &st) == 0) {
                    if (mount("/sys/fs/cgroup", "/sys/fs/cgroup", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
                        log_warn("supervisor", "mount(/sys/fs/cgroup, MS_RDONLY): %s", strerror(errno));
                    }
                }
            }
        }
#else
        /* Warn on non-Linux platforms */
        if (service->protect_system > 0 || service->protect_home > 0 ||
            service->private_devices || service->protect_kernel_tunables ||
            service->protect_control_groups) {
            log_warn("supervisor", "Sandboxing directives (ProtectSystem, ProtectHome, etc.) not supported on this platform");
        }
#endif

        /* DeviceAllow= - set up cgroup device controller (Linux-only, requires cgroup infrastructure) */
#ifdef __linux__
        if (service->device_allow_count > 0) {
            /* Create cgroup for device access control */
            char cgroup_path[PATH_MAX - 20];  /* Leave room for file names */
            snprintf(cgroup_path, sizeof(cgroup_path),
                    "/sys/fs/cgroup/devices/initd.slice/%s-%d",
                    unit_name, getpid());

            /* Create cgroup directory */
            if (mkdir(cgroup_path, 0755) < 0 && errno != EEXIST) {
                log_error("supervisor", "Failed to create cgroup %s: %s",
                         cgroup_path, strerror(errno));
            } else {
                /* Deny all devices by default */
                char deny_path[PATH_MAX];
                snprintf(deny_path, sizeof(deny_path), "%s/devices.deny", cgroup_path);
                int deny_fd = open(deny_path, O_WRONLY);
                if (deny_fd >= 0) {
                    write(deny_fd, "a", 1);
                    close(deny_fd);
                }

                /* Allow specified devices */
                char allow_path[PATH_MAX];
                snprintf(allow_path, sizeof(allow_path), "%s/devices.allow", cgroup_path);
                int allow_fd = open(allow_path, O_WRONLY);
                if (allow_fd >= 0) {
                    for (int i = 0; i < service->device_allow_count; i++) {
                        const struct device_allow *dev = &service->device_allow[i];
                        char allow_rule[256];

                        /* Format: type major:minor permissions */
                        char perms[4] = {0};
                        int perm_idx = 0;
                        if (dev->read) perms[perm_idx++] = 'r';
                        if (dev->write) perms[perm_idx++] = 'w';
                        if (dev->mknod) perms[perm_idx++] = 'm';

                        /* Get device major/minor numbers */
                        struct stat st;
                        if (stat(dev->path, &st) == 0 && S_ISBLK(st.st_mode)) {
                            snprintf(allow_rule, sizeof(allow_rule), "b %u:%u %s\n",
                                   major(st.st_rdev), minor(st.st_rdev), perms);
                        } else if (stat(dev->path, &st) == 0 && S_ISCHR(st.st_mode)) {
                            snprintf(allow_rule, sizeof(allow_rule), "c %u:%u %s\n",
                                   major(st.st_rdev), minor(st.st_rdev), perms);
                        } else {
                            log_warn("supervisor", "DeviceAllow: %s is not a device node", dev->path);
                            continue;
                        }

                        if (write(allow_fd, allow_rule, strlen(allow_rule)) < 0) {
                            log_warn("supervisor", "Failed to allow device %s: %s",
                                   dev->path, strerror(errno));
                        } else {
                            log_debug("supervisor", "Allowed device %s (%s)", dev->path, perms);
                        }
                    }
                    close(allow_fd);
                }

                /* Add this process to the cgroup */
                char tasks_path[PATH_MAX];
                snprintf(tasks_path, sizeof(tasks_path), "%s/tasks", cgroup_path);
                int tasks_fd = open(tasks_path, O_WRONLY);
                if (tasks_fd >= 0) {
                    char pid_str[32];
                    snprintf(pid_str, sizeof(pid_str), "%d", getpid());
                    write(tasks_fd, pid_str, strlen(pid_str));
                    close(tasks_fd);
                    log_debug("supervisor", "Added PID %d to device cgroup", getpid());
                }
            }
        }
#else
        if (service->device_allow_count > 0) {
            log_warn("supervisor", "DeviceAllow= not supported on non-Linux platforms");
        }
#endif

        /* RootImage= - mount disk image as root filesystem (requires loop device support) */
        if (service->root_image[0] != '\0') {
#ifdef __linux__
            /* SECURITY: Validate RootImage path */
            if (service->root_image[0] != '/') {
                log_error("supervisor", "SECURITY: RootImage must be absolute: %s",
                         service->root_image);
                _exit(1);
            }

            /* Set up loop device and mount the image */
            int loop_fd = open("/dev/loop-control", O_RDWR);
            if (loop_fd < 0) {
                log_error("supervisor", "Failed to open /dev/loop-control: %s", strerror(errno));
                _exit(1);
            }

            /* Allocate a free loop device */
            int loop_num = ioctl(loop_fd, LOOP_CTL_GET_FREE);
            close(loop_fd);
            if (loop_num < 0) {
                log_error("supervisor", "Failed to get free loop device: %s", strerror(errno));
                _exit(1);
            }

            char loop_dev[64];
            snprintf(loop_dev, sizeof(loop_dev), "/dev/loop%d", loop_num);

            /* Open the loop device */
            int loop_device_fd = open(loop_dev, O_RDWR);
            if (loop_device_fd < 0) {
                log_error("supervisor", "Failed to open %s: %s", loop_dev, strerror(errno));
                _exit(1);
            }

            /* Open the image file with O_NOFOLLOW to prevent symlink attacks */
            int image_fd = open(service->root_image, O_RDWR | O_NOFOLLOW);
            if (image_fd < 0) {
                log_error("supervisor", "Failed to open image %s: %s (use O_NOFOLLOW to prevent symlink attacks)",
                         service->root_image, strerror(errno));
                close(loop_device_fd);
                _exit(1);
            }
            /* Verify it's a regular file */
            struct stat st;
            if (fstat(image_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
                log_error("supervisor", "RootImage %s is not a regular file", service->root_image);
                close(image_fd);
                close(loop_device_fd);
                _exit(1);
            }

            /* Associate the image with the loop device */
            if (ioctl(loop_device_fd, LOOP_SET_FD, image_fd) < 0) {
                log_error("supervisor", "Failed to set loop device: %s", strerror(errno));
                close(image_fd);
                close(loop_device_fd);
                _exit(1);
            }
            close(image_fd);
            close(loop_device_fd);

            /* Create mount point */
            char mount_point[PATH_MAX];
            snprintf(mount_point, sizeof(mount_point), "/run/initd/rootimg/%s-%d",
                    unit_name, getpid());

            /* Create directory hierarchy */
            char *parent = strdup(mount_point);
            char *slash = strrchr(parent, '/');
            if (slash) {
                *slash = '\0';
                mkdir(parent, 0755);  /* /run/initd/rootimg */
            }
            free(parent);

            if (mkdir(mount_point, 0755) < 0 && errno != EEXIST) {
                log_error("supervisor", "Failed to create mount point %s: %s",
                         mount_point, strerror(errno));
                ioctl(open(loop_dev, O_RDWR), LOOP_CLR_FD, 0);
                _exit(1);
            }

            /* Mount the loop device */
            if (mount(loop_dev, mount_point, "auto", MS_RDONLY, NULL) < 0) {
                log_error("supervisor", "Failed to mount %s: %s", loop_dev, strerror(errno));
                rmdir(mount_point);
                ioctl(open(loop_dev, O_RDWR), LOOP_CLR_FD, 0);
                _exit(1);
            }

            /* chroot to the mounted image */
            if (chroot(mount_point) < 0) {
                log_error("supervisor", "chroot(%s): %s", mount_point, strerror(errno));
                umount(mount_point);
                rmdir(mount_point);
                ioctl(open(loop_dev, O_RDWR), LOOP_CLR_FD, 0);
                _exit(1);
            }
            if (chdir("/") < 0) {
                log_error("supervisor", "chdir(/): %s", strerror(errno));
                _exit(1);
            }
            log_debug("supervisor", "Mounted RootImage %s on %s via %s",
                     service->root_image, mount_point, loop_dev);
#else
            log_error("supervisor", "RootImage= not supported on non-Linux platforms");
            _exit(1);
#endif
        }

        /* chroot if RootDirectory is specified (must be done before dropping privileges) */
        if (service->root_directory[0] != '\0') {
            /* SECURITY: Validate RootDirectory path to prevent traversal/symlink attacks
             * Must be absolute, no symlinks, and within allowed directories */
            if (service->root_directory[0] != '/') {
                log_error("supervisor", "SECURITY: RootDirectory must be absolute: %s",
                         service->root_directory);
                _exit(1);
            }

            /* Verify path doesn't contain symlinks using O_NOFOLLOW traversal */
            int fd = open(service->root_directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                log_error("supervisor", "SECURITY: RootDirectory validation failed (symlink/traversal?): %s: %s",
                         service->root_directory, strerror(errno));
                _exit(1);
            }
            close(fd);

            if (chroot(service->root_directory) < 0) {
                log_error("supervisor", "chroot(%s): %s", service->root_directory, strerror(errno));
                _exit(1);
            }
            /* chroot() doesn't change cwd, so we must chdir to the new root */
            if (chdir("/") < 0) {
                log_error("supervisor", "chdir(/) after chroot: %s", strerror(errno));
                _exit(1);
            }
        }

        /* Set up Linux capabilities (must be before dropping privileges) */
#if defined(__linux__) && defined(__HAVE_LIBCAP__)
        /* Get last valid capability number from kernel */
        int last_cap = -1;
        {
            FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
            if (f) {
                if (fscanf(f, "%d", &last_cap) != 1) {
                    last_cap = -1;
                }
                fclose(f);
            }
#ifdef CAP_LAST_CAP
            /* Fall back to compile-time constant if available */
            if (last_cap < 0) {
                last_cap = CAP_LAST_CAP;
            }
#endif
            /* Final fallback to a reasonable maximum */
            if (last_cap < 0) {
                last_cap = 40; /* Reasonable upper bound for older kernels */
            }
        }

        /* Linux with libcap - set up capabilities */
        if (service->capability_bounding_set_count > 0 || service->ambient_capabilities_count > 0) {
            cap_t caps = cap_get_proc();
            if (!caps) {
                log_error("supervisor", "Failed to get current capabilities: %s", strerror(errno));
                exit(1);
            }

            /* Set capability bounding set */
            if (service->capability_bounding_set_count > 0) {
                /* Build capability set from names */
                cap_value_t cap_vals[MAX_CAPABILITIES];
                int cap_count = 0;

                for (int i = 0; i < service->capability_bounding_set_count; i++) {
                    if (cap_from_name(service->capability_bounding_set[i], &cap_vals[cap_count]) == 0) {
                        cap_count++;
                    } else {
                        log_warn("supervisor", "Unknown capability: %s", service->capability_bounding_set[i]);
                    }
                }

                /* SECURITY: Clear all capabilities first, then set only requested ones
                 * Without this, services running as root retain all unmentioned capabilities */
                if (cap_clear(caps) < 0) {
                    log_error("supervisor", "Failed to clear capabilities: %s", strerror(errno));
                    cap_free(caps);
                    exit(1);
                }

                if (cap_count > 0) {
                    if (cap_set_flag(caps, CAP_PERMITTED, cap_count, cap_vals, CAP_SET) < 0 ||
                        cap_set_flag(caps, CAP_EFFECTIVE, cap_count, cap_vals, CAP_SET) < 0) {
                        log_error("supervisor", "Failed to set capability flags: %s", strerror(errno));
                        cap_free(caps);
                        exit(1);
                    }

                    if (cap_set_proc(caps) < 0) {
                        log_error("supervisor", "Failed to set process capabilities: %s", strerror(errno));
                        cap_free(caps);
                        exit(1);
                    }

                    log_debug("supervisor", "Set %d capabilities in bounding set", cap_count);
                }

                /* Drop capabilities from the bounding set using prctl
                 * This ensures even setuid-root binaries can't gain these caps */
                for (int cap = 0; cap <= last_cap; cap++) {
                    bool keep = false;
                    for (int i = 0; i < cap_count; i++) {
                        if (cap_vals[i] == cap) {
                            keep = true;
                            break;
                        }
                    }
                    if (!keep) {
                        /* SECURITY: Hard-fail on drop errors (except EINVAL for unsupported caps)
                         * If we can't drop a capability, the service runs with extra privilege */
                        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
                            if (errno == EINVAL) {
                                /* Capability not supported by kernel - safe to ignore */
                                continue;
                            }
                            log_error("supervisor", "SECURITY: Failed to drop capability %d from bounding set: %s",
                                   cap, strerror(errno));
                            cap_free(caps);
                            _exit(1);
                        }
                    }
                }
            }

            /* Set ambient capabilities (requires Linux 4.3+) */
            if (service->ambient_capabilities_count > 0) {
                for (int i = 0; i < service->ambient_capabilities_count; i++) {
                    cap_value_t cap_val;
                    if (cap_from_name(service->ambient_capabilities[i], &cap_val) == 0) {
                        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_val, 0, 0) < 0) {
                            log_warn("supervisor", "Failed to raise ambient capability %s: %s",
                                   service->ambient_capabilities[i], strerror(errno));
                        } else {
                            log_debug("supervisor", "Raised ambient capability: %s",
                                    service->ambient_capabilities[i]);
                        }
                    } else {
                        log_warn("supervisor", "Unknown ambient capability: %s",
                               service->ambient_capabilities[i]);
                    }
                }
            }

            /* SECURITY: Keep capabilities across setuid() if ambient caps are configured
             * Without PR_SET_KEEPCAPS, setuid() clears all capabilities including ambient */
            if (service->ambient_capabilities_count > 0 && validated_uid != 0) {
                if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
                    log_warn("supervisor", "Failed to set PR_SET_KEEPCAPS: %s", strerror(errno));
                }
            }

            cap_free(caps);
        }
#elif defined(__linux__)
        /* Linux but no libcap compiled in */
        if (service->capability_bounding_set_count > 0 || service->ambient_capabilities_count > 0) {
            log_warn("supervisor", "Capability directives configured but libcap support not compiled in");
        }
#else
        /* Non-Linux platforms (BSD, Hurd) */
        if (service->capability_bounding_set_count > 0 || service->ambient_capabilities_count > 0) {
            log_warn("supervisor", "Capability directives not supported on non-Linux platforms");
        }
#endif

        /* Drop privileges using VALIDATED UID/GID from master's unit file parsing */
        if (validated_gid != 0) {
            /* Clear supplementary groups first */
            if (setgroups(1, &validated_gid) < 0) {
                log_error("supervisor", "setgroups: %s", strerror(errno));
                _exit(1);
            }

            if (setgid(validated_gid) < 0) {
                log_error("supervisor", "setgid: %s", strerror(errno));
                _exit(1);
            }
        }

        if (validated_uid != 0) {
            if (setuid(validated_uid) < 0) {
                log_error("supervisor", "setuid: %s", strerror(errno));
                _exit(1);
            }

#if defined(__linux__) && defined(__HAVE_LIBCAP__)
            /* Restore capabilities after setuid if PR_SET_KEEPCAPS was set
             * This makes ambient capabilities actually work for non-root services */
            if (service->ambient_capabilities_count > 0) {
                cap_t caps = cap_get_proc();
                if (caps) {
                    /* Re-raise ambient capabilities that were set earlier */
                    for (int i = 0; i < service->ambient_capabilities_count; i++) {
                        cap_value_t cap_val;
                        if (cap_from_name(service->ambient_capabilities[i], &cap_val) == 0) {
                            /* Ensure capability is in permitted and effective sets */
                            if (cap_set_flag(caps, CAP_PERMITTED, 1, &cap_val, CAP_SET) == 0 &&
                                cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_val, CAP_SET) == 0) {
                                if (cap_set_proc(caps) == 0) {
                                    /* Re-raise in ambient set after setuid */
                                    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_val, 0, 0) < 0) {
                                        log_warn("supervisor", "Failed to restore ambient capability %s after setuid: %s",
                                               service->ambient_capabilities[i], strerror(errno));
                                    } else {
                                        log_debug("supervisor", "Restored ambient capability after setuid: %s",
                                                service->ambient_capabilities[i]);
                                    }
                                }
                            }
                        }
                    }
                    cap_free(caps);
                }

                /* Clear PR_SET_KEEPCAPS now that we're done */
                prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
            }
#endif
        }

        /* Verify we cannot regain privileges */
        if (validated_uid != 0) {
            if (setuid(0) == 0 || seteuid(0) == 0) {
                log_error("supervisor", "SECURITY: can still become root after dropping privileges!");
                _exit(1);
            }
        }

        /* Set memory limit if specified (using setrlimit for address space) */
        if (service->memory_limit > 0) {
            struct rlimit rlim;
            rlim.rlim_cur = service->memory_limit;
            rlim.rlim_max = service->memory_limit;
            if (setrlimit(RLIMIT_AS, &rlim) < 0) {
                log_warn("supervisor", "Failed to set memory limit to %ld bytes: %s",
                        service->memory_limit, strerror(errno));
            } else {
                log_debug("supervisor", "Set memory limit to %ld bytes", service->memory_limit);
            }
        }

        /* Set umask if specified */
        if (service->umask_value != 0) {
            umask(service->umask_value);
        }

        /* Set no_new_privs if specified (Linux and FreeBSD only) */
        if (service->no_new_privs) {
#ifdef __linux__
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                log_error("supervisor", "prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
                _exit(1);
            }
#elif defined(__FreeBSD__)
            int enable = PROC_NO_NEW_PRIVS_ENABLE;
            if (procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable) < 0) {
                log_error("supervisor", "procctl(PROC_NO_NEW_PRIVS_CTL): %s", strerror(errno));
                _exit(1);
            }
#else
            /* OpenBSD/Hurd: no equivalent - log warning and continue */
            log_warn("supervisor", "NoNewPrivileges= not supported on this platform");
#endif
        }

        /* Restrict SUID/SGID if specified (same mechanism as no_new_privs) */
        if (service->restrict_suid_sgid) {
#ifdef __linux__
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                log_error("supervisor", "prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
                _exit(1);
            }
#elif defined(__FreeBSD__)
            int enable = PROC_NO_NEW_PRIVS_ENABLE;
            if (procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable) < 0) {
                log_error("supervisor", "procctl(PROC_NO_NEW_PRIVS_CTL): %s", strerror(errno));
                _exit(1);
            }
#else
            /* NetBSD/OpenBSD/Hurd: no equivalent - log warning and continue */
            log_warn("supervisor", "RestrictSUIDSGID= not supported on this platform");
#endif
        }

        /* SECURITY: Scrub dangerous environment variables that could hijack execution
         * Must be done after all our setenv calls but before execv */
        scrub_dangerous_environment();

        /* Exec service using argv (NO SHELL - prevents injection) */
        execv(exec_path, argv);

        log_error("supervisor", "execv: %s", strerror(errno));
        _exit(1);
    }

    /* Parent: close write ends, return read ends */
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    *stdout_pipe_fd = stdout_pipe[0];
    *stderr_pipe_fd = stderr_pipe[0];

    return pid;
}

/* Validate unit path from worker is in allowed directory */
static bool validate_unit_path_from_worker(const char *path) {
    /* SECURITY: Worker-supplied paths must be in whitelisted directories only */
    return validate_path_in_directory(path, "/lib/initd/system") ||
           validate_path_in_directory(path, "/etc/initd/system") ||
           validate_path_in_directory(path, "/usr/lib/initd/system") ||
           validate_path_in_directory(path, "/lib/systemd/system") ||
           validate_path_in_directory(path, "/usr/lib/systemd/system") ||
           validate_path_in_directory(path, "/etc/systemd/system")
#ifdef UNIT_TEST
           || validate_path_in_directory(path, "/tmp")
#endif
           ;
}

/* Handle privileged request from worker */
static int handle_request(struct priv_request *req, struct priv_response *resp) {
    memset(resp, 0, sizeof(*resp));

    switch (req->type) {
    case REQ_START_SERVICE: {
        log_debug("supervisor", "start service request: %s", req->unit_name);

        /* SECURITY: Validate unit path is in allowed directory before parsing */
        if (!validate_unit_path_from_worker(req->unit_path)) {
            log_error("supervisor", "SECURITY: invalid unit path: %s", req->unit_path);
            resp->type = RESP_ERROR;
            resp->error_code = EACCES;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit path not in allowed directory");
            break;
        }

        /* DoS PREVENTION: Check if registry has capacity before starting service */
        if (!has_registry_capacity()) {
            log_debug("supervisor", "DoS Prevention: service registry full, cannot start %s",
                      req->unit_name);
            resp->type = RESP_ERROR;
            resp->error_code = ENOMEM;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Service registry full (max %d services)", MAX_SERVICES);
            break;
        }

        update_restart_limits(req->unit_name,
                               req->start_limit_burst,
                               req->start_limit_interval_sec,
                               MIN_RESTART_INTERVAL_SEC,
                               req->start_limit_action);

        /* DoS PREVENTION: Check restart rate limiting */
        if (!can_restart_service(req->unit_name)) {
            log_debug("supervisor", "DoS Prevention: %s rate limited", req->unit_name);
            resp->type = RESP_ERROR;
            resp->error_code = EAGAIN;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Service restart rate limited (max %d/%dsec)",
                     MAX_RESTARTS_PER_WINDOW, RESTART_WINDOW_SEC);
            break;
        }

        /* DoS PREVENTION: Record restart attempt for tracking */
        record_restart_attempt(req->unit_name);

        /* SECURITY: Master must parse unit file to get authoritative User/Group values.
         * Never trust worker-supplied run_uid/run_gid as compromised worker could
         * request uid=0 to escalate privileges. */
        struct unit_file unit = {0};
        char **exec_argv = NULL;
        const char *exec_path = NULL;

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
            goto start_cleanup;
        }

        if ((unit.config.service.exec_start_count == 0) &&
            (!unit.config.service.exec_start || unit.config.service.exec_start[0] == '\0')) {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit has no ExecStart");
            goto start_cleanup;
        }

        /* Extract and validate User/Group from parsed unit file */
        uid_t validated_uid = 0;  /* Default: root */
        gid_t validated_gid = 0;

        /* DynamicUser= - allocate ephemeral UID/GID */
        if (unit.config.service.dynamic_user) {
            /* systemd uses UID range 61184-65519 for dynamic users */
            /* We'll use a simple allocation: hash the unit name into this range */
            unsigned long hash = 5381;
            for (const char *p = req->unit_name; *p; p++) {
                hash = ((hash << 5) + hash) + (unsigned char)*p;
            }
            /* Map hash to range 61184-65519 (4336 UIDs) */
            validated_uid = 61184 + (hash % 4336);
            validated_gid = validated_uid;  /* Use same value for GID */
            log_debug("supervisor", "DynamicUser: allocated uid=%d gid=%d for %s",
                      validated_uid, validated_gid, req->unit_name);
        } else if (unit.config.service.user[0] != '\0') {
            const struct passwd *pw = getpwnam(unit.config.service.user);
            if (!pw) {
                log_error("supervisor", "user '%s' not found", unit.config.service.user);
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "User '%s' not found", unit.config.service.user);
                goto start_cleanup;
            }
            validated_uid = pw->pw_uid;
            log_debug("supervisor", "service will run as user %s (uid=%d)",
                      unit.config.service.user, validated_uid);
        }

        if (unit.config.service.group[0] != '\0' && !unit.config.service.dynamic_user) {
            const struct group *gr = getgrnam(unit.config.service.group);
            if (!gr) {
                log_error("supervisor", "group '%s' not found", unit.config.service.group);
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "Group '%s' not found", unit.config.service.group);
                goto start_cleanup;
            }
            validated_gid = gr->gr_gid;
            log_debug("supervisor", "service will run as group %s (gid=%d)",
                      unit.config.service.group, validated_gid);
        } else if (validated_uid != 0 && !unit.config.service.dynamic_user) {
            /* If User specified but Group not specified, use user's primary group */
            const struct passwd *pw = getpwuid(validated_uid);
            if (pw) {
                validated_gid = pw->pw_gid;
            }
        }

        if (run_exec_command_list(&unit.config.service,
                                   unit.config.service.exec_condition,
                                   unit.config.service.exec_condition_count,
                                   validated_uid,
                                   validated_gid,
                                   unit.name,
                                   "ExecCondition",
                                   true) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecCondition failed");
            goto start_cleanup;
        }

        if (run_lifecycle_command(&unit.config.service,
                                   unit.config.service.exec_start_pre,
                                   validated_uid,
                                   validated_gid,
                                   unit.name,
                                   "ExecStartPre",
                                   true) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecStartPre failed");
            goto start_cleanup;
        }

        if (unit.config.service.type == SERVICE_ONESHOT &&
            unit.config.service.exec_start_count > 1) {
            for (int i = 0; i < unit.config.service.exec_start_count - 1; i++) {
                if (!unit.config.service.exec_start_list[i] ||
                    unit.config.service.exec_start_list[i][0] == '\0') {
                    continue;
                }
                char stage_name[32];
                snprintf(stage_name, sizeof(stage_name), "ExecStart[%d]", i);
                if (run_lifecycle_command(&unit.config.service,
                                           unit.config.service.exec_start_list[i],
                                           validated_uid,
                                           validated_gid,
                                           unit.name,
                                           stage_name,
                                           true) < 0) {
                    resp->type = RESP_ERROR;
                    resp->error_code = errno;
                    snprintf(resp->error_msg, sizeof(resp->error_msg),
                             "%s failed", stage_name);
                    goto start_cleanup;
                }
            }
        }

        const char *main_exec = unit.config.service.exec_start;
        if (unit.config.service.exec_start_count > 0) {
            main_exec = unit.config.service.exec_start_list[unit.config.service.exec_start_count - 1];
        }

        if (!main_exec || main_exec[0] == '\0') {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit has no ExecStart");
            goto start_cleanup;
        }

        if (build_exec_argv(main_exec, &exec_argv) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse ExecStart command");
            goto start_cleanup;
        }

        if (!exec_argv || !exec_argv[0]) {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecStart parsing produced empty command");
            goto start_cleanup;
        }

        exec_path = exec_argv[0];
        if (exec_path[0] != '/') {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecStart must use absolute path");
            goto start_cleanup;
        }

        if (strstr(exec_path, "..") != NULL) {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecStart path contains '..'");
            goto start_cleanup;
        }

        /* Start service with validated credentials */
        int kill_mode = unit.config.service.kill_mode;
        int stdout_fd = -1, stderr_fd = -1;
        pid_t pid = start_service_process(&unit.config.service, unit.name, exec_path, exec_argv,
                                          validated_uid, validated_gid,
                                          &stdout_fd, &stderr_fd);
        int saved_errno = errno;

        /* exec_argv is guaranteed non-NULL here (validated at line 580) */
        free_exec_argv(exec_argv);
        exec_argv = NULL;

        if (pid < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = saved_errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to start service");
            goto start_cleanup;
        }

        /* Register service in the registry to prevent arbitrary kill() attacks */
        if (register_service(pid, req->unit_name, unit.path, kill_mode, stdout_fd, stderr_fd, unit.config.service.runtime_max_sec) < 0) {
            /* Registry full - kill the service we just started */
            close(stdout_fd);
            close(stderr_fd);
            process_tracking_signal_process(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            resp->type = RESP_ERROR;
            resp->error_code = ENOMEM;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Service registry full");
            goto start_cleanup;
        }

        pid_t reported_pid = pid;
        if (unit.config.service.pid_file && unit.config.service.pid_file[0] != '\0') {
            pid_t pidfile_pid = read_pid_file_with_timeout(unit.config.service.pid_file, 50, 100);
            if (pidfile_pid > 0) {
                if (service_registry_update_pid(req->unit_name, pidfile_pid) == 0) {
                    reported_pid = pidfile_pid;
                }
            } else {
                log_warn("supervisor", "PIDFile %s not available for %s",
                         unit.config.service.pid_file, unit.name);
            }
        }

        if (run_lifecycle_command(&unit.config.service,
                                   unit.config.service.exec_start_post,
                                   validated_uid,
                                   validated_gid,
                                   unit.name,
                                   "ExecStartPost",
                                   true) < 0) {
            log_error("supervisor", "ExecStartPost failed for %s, terminating service",
                      unit.name);
            unregister_service(pid);
            process_tracking_signal_group(pid, SIGKILL);
            process_tracking_signal_process(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecStartPost failed");
            goto start_cleanup;
        }

        resp->type = RESP_SERVICE_STARTED;
        resp->service_pid = reported_pid;
        log_debug("supervisor", "started %s (pid %d)", req->unit_name, reported_pid);
start_cleanup:
        free_unit_file(&unit);
        if (exec_argv) {
            free_exec_argv(exec_argv);
        }
        break;
    }

    case REQ_STOP_SERVICE: {
        log_debug("supervisor", "stop service request: pid %d", req->service_pid);

        /* SECURITY: Validate that this PID belongs to a managed service.
         * Prevents compromised worker from killing arbitrary processes. */
        struct service_record *svc = lookup_service(req->service_pid);
        if (!svc) {
            log_error("supervisor", "SECURITY: attempt to stop unmanaged PID %d",
                      req->service_pid);
            resp->type = RESP_ERROR;
            resp->error_code = ESRCH;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "PID %d is not a managed service", req->service_pid);
            break;
        }

        log_debug("supervisor", "stopping service %s (pid=%d, kill_mode=%d)",
                  svc->unit_name, svc->pid, svc->kill_mode);

        int kill_mode = svc->kill_mode;
        struct unit_file stop_unit = {0};
        bool unit_parsed = false;
        uid_t validated_uid = 0;
        gid_t validated_gid = 0;

        if (svc->unit_path[0] != '\0') {
            if (!validate_unit_path_from_worker(svc->unit_path)) {
                log_error("supervisor", "SECURITY: stored unit path invalid: %s",
                          svc->unit_path);
            } else if (parse_unit_file(svc->unit_path, &stop_unit) < 0) {
                log_error("supervisor", "failed to parse unit file for %s",
                          svc->unit_name);
            } else {
                unit_parsed = true;
                kill_mode = stop_unit.config.service.kill_mode;

                if (stop_unit.config.service.user[0] != '\0') {
                    const struct passwd *pw = getpwnam(stop_unit.config.service.user);
                    if (!pw) {
                        log_error("supervisor", "stop: user '%s' not found",
                                  stop_unit.config.service.user);
                    } else {
                        validated_uid = pw->pw_uid;
                    }
                }

                if (stop_unit.config.service.group[0] != '\0') {
                    const struct group *gr = getgrnam(stop_unit.config.service.group);
                    if (!gr) {
                        log_error("supervisor", "stop: group '%s' not found",
                                  stop_unit.config.service.group);
                    } else {
                        validated_gid = gr->gr_gid;
                    }
                } else if (validated_uid != 0) {
                    const struct passwd *pw = getpwuid(validated_uid);
                    if (pw) {
                        validated_gid = pw->pw_gid;
                    }
                }

                if (stop_unit.config.service.exec_stop &&
                    stop_unit.config.service.exec_stop[0] != '\0') {
                    if (run_lifecycle_command(&stop_unit.config.service,
                                               stop_unit.config.service.exec_stop,
                                               validated_uid,
                                               validated_gid,
                                               stop_unit.name,
                                               "ExecStop",
                                               false) < 0) {
                        log_error("supervisor", "ExecStop failed for %s",
                                  stop_unit.name);
                    }
                }
            }
        }

        bool kill_failed = false;
        int kill_errno = 0;

        /* Use VALIDATED kill_mode from registry (from unit file), not from worker request */
        switch (kill_mode) {
        case KILL_NONE:
            /* Don't kill anything */
            log_debug("supervisor", "KillMode=none, not sending signal");
            break;

        case KILL_PROCESS:
            /* Kill only the main process (default) */
            if (process_tracking_signal_process(svc->pid, SIGTERM) < 0 && errno != ESRCH) {
                kill_failed = true;
                kill_errno = errno;
            }
            break;

        case KILL_CONTROL_GROUP:
            /* Kill entire process group using VALIDATED pgid from registry */
            if (process_tracking_signal_group(svc->pgid, SIGTERM) < 0 && errno != ESRCH) {
                /* If killpg fails (not a process group leader), fallback to kill */
                if (process_tracking_signal_process(svc->pid, SIGTERM) < 0 && errno != ESRCH) {
                    kill_failed = true;
                    kill_errno = errno;
                }
            }
            break;

        case KILL_MIXED:
            /* SIGTERM to main process, SIGKILL to rest of group */
            if (process_tracking_signal_process(svc->pid, SIGTERM) < 0 && errno != ESRCH) {
                kill_failed = true;
                kill_errno = errno;
            }
            /* Sleep briefly to let main process exit gracefully */
            usleep(100000); /* 100ms */
            /* Kill remaining processes in group */
            if (!kill_failed && process_tracking_signal_group(svc->pgid, SIGKILL) < 0 && errno != ESRCH) {
                kill_failed = true;
                kill_errno = errno;
            }
            break;

        default:
            /* Fallback to process mode */
            if (process_tracking_signal_process(svc->pid, SIGTERM) < 0 && errno != ESRCH) {
                kill_failed = true;
                kill_errno = errno;
            }
            break;
        }

        if (unit_parsed) {
            if (stop_unit.config.service.exec_stop_post_count > 0) {
                if (run_exec_command_list(&stop_unit.config.service,
                                           stop_unit.config.service.exec_stop_post,
                                           stop_unit.config.service.exec_stop_post_count,
                                           validated_uid,
                                           validated_gid,
                                           stop_unit.name,
                                           "ExecStopPost",
                                           false) < 0) {
                    log_error("supervisor", "ExecStopPost list failed for %s",
                              stop_unit.name);
                }
            }
            free_unit_file(&stop_unit);
        }

        if (kill_failed) {
            resp->type = RESP_ERROR;
            resp->error_code = kill_errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to kill service");
        } else {
            resp->type = RESP_SERVICE_STOPPED;
        }
        break;
    }

    case REQ_ENABLE_UNIT: {
        log_debug("supervisor", "enable unit request: %s", req->unit_path);

        /* SECURITY: Validate unit path is in allowed directory */
        if (!validate_unit_path_from_worker(req->unit_path)) {
            log_error("supervisor", "SECURITY: invalid unit path: %s", req->unit_path);
            resp->type = RESP_ERROR;
            resp->error_code = EACCES;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit path not in allowed directory");
            break;
        }

        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (enable_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to enable unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_ENABLED;
            free_unit_file(&unit);
            log_info("supervisor", "Enabled unit %s", req->unit_path);
        }
        break;
    }

    case REQ_DISABLE_UNIT: {
        log_debug("supervisor", "disable unit request: %s", req->unit_path);

        /* SECURITY: Validate unit path is in allowed directory */
        if (!validate_unit_path_from_worker(req->unit_path)) {
            log_error("supervisor", "SECURITY: invalid unit path: %s", req->unit_path);
            resp->type = RESP_ERROR;
            resp->error_code = EACCES;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit path not in allowed directory");
            break;
        }

        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (disable_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to disable unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_DISABLED;
            free_unit_file(&unit);
            log_info("supervisor", "Disabled unit %s", req->unit_path);
        }
        break;
    }

    case REQ_RELOAD_SERVICE: {
        log_debug("supervisor", "reload service request: %s (pid=%d)",
                  req->unit_name, req->service_pid);

        struct service_record *svc = NULL;
        if (req->service_pid > 0) {
            svc = lookup_service(req->service_pid);
        }
        if (!svc) {
            svc = lookup_service_by_name(req->unit_name);
        }
        if (!svc) {
            resp->type = RESP_ERROR;
            resp->error_code = ESRCH;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Service %.200s is not running", req->unit_name);
            break;
        }

        const char *unit_path = svc->unit_path[0] != '\0' ? svc->unit_path : req->unit_path;
        if (!unit_path || unit_path[0] == '\0') {
            resp->type = RESP_ERROR;
            resp->error_code = ENOENT;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Unit path unknown for %.200s", req->unit_name);
            break;
        }

        if (!validate_unit_path_from_worker(unit_path)) {
            resp->type = RESP_ERROR;
            resp->error_code = EACCES;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Unit path not in allowed directory");
            break;
        }

        struct unit_file unit = {0};

        if (parse_unit_file(unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
            break;
        }

        if (!unit.config.service.exec_reload || unit.config.service.exec_reload[0] == '\0') {
            resp->type = RESP_ERROR;
            resp->error_code = ENOTSUP;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "Unit %.200s has no ExecReload", unit.name[0] ? unit.name : req->unit_name);
            free_unit_file(&unit);
            break;
        }

        uid_t validated_uid = 0;
        gid_t validated_gid = 0;

        if (unit.config.service.user[0] != '\0') {
            const struct passwd *pw = getpwnam(unit.config.service.user);
            if (!pw) {
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg),
                         "User '%s' not found", unit.config.service.user);
                free_unit_file(&unit);
                break;
            }
            validated_uid = pw->pw_uid;
        }

        if (unit.config.service.group[0] != '\0') {
            const struct group *gr = getgrnam(unit.config.service.group);
            if (!gr) {
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg),
                         "Group '%s' not found", unit.config.service.group);
                free_unit_file(&unit);
                break;
            }
            validated_gid = gr->gr_gid;
        } else if (validated_uid != 0) {
            const struct passwd *pw = getpwuid(validated_uid);
            if (pw) {
                validated_gid = pw->pw_gid;
            }
        }

        if (run_lifecycle_command(&unit.config.service,
                                   unit.config.service.exec_reload,
                                   validated_uid,
                                   validated_gid,
                                   unit.name,
                                   "ExecReload",
                                   false) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "ExecReload failed");
        } else {
            resp->type = RESP_SERVICE_RELOADED;
        }

        free_unit_file(&unit);
        break;
    }

    case REQ_CONVERT_UNIT: {
        log_debug("supervisor", "convert unit request: %s", req->unit_path);

        /* SECURITY: Validate unit path is in allowed directory */
        if (!validate_unit_path_from_worker(req->unit_path)) {
            log_error("supervisor", "SECURITY: invalid unit path: %s", req->unit_path);
            resp->type = RESP_ERROR;
            resp->error_code = EACCES;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit path not in allowed directory");
            break;
        }

        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (convert_systemd_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to convert unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_CONVERTED;
            strncpy(resp->converted_path, unit.path, sizeof(resp->converted_path) - 1);
            free_unit_file(&unit);
            log_info("supervisor", "Converted unit to %s", resp->converted_path);
        }
        break;
    }

    case REQ_SHUTDOWN_COMPLETE:
        log_info("supervisor", "Worker shutdown complete");
        resp->type = RESP_OK;
        shutdown_requested = 1;
        break;

    case REQ_POWEROFF:
        log_info("supervisor", "Poweroff requested");
        resp->type = RESP_OK;
        shutdown_requested = 1;
        shutdown_type = SHUTDOWN_POWEROFF;
        break;

    case REQ_REBOOT:
        log_info("supervisor", "Reboot requested");
        resp->type = RESP_OK;
        shutdown_requested = 1;
        shutdown_type = SHUTDOWN_REBOOT;
        break;

    case REQ_HALT:
        log_info("supervisor", "Halt requested");
        resp->type = RESP_OK;
        shutdown_requested = 1;
        shutdown_type = SHUTDOWN_HALT;
        break;

    default:
        resp->type = RESP_ERROR;
        resp->error_code = EINVAL;
        snprintf(resp->error_msg, sizeof(resp->error_msg), "Unknown request type");
        break;
    }

    return 0;
}

#ifdef UNIT_TEST
int supervisor_handle_request_for_test(struct priv_request *req, struct priv_response *resp) {
    return handle_request(req, resp);
}
#endif

/* Read and log output from a service pipe
 * Format: [unitname] timestamp message
 */
static void read_service_output(int fd, const char *unit_name) {
    char buffer[4096];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);

    if (n <= 0) {
        return;  /* EOF or error - pipe will be closed by unregister_service() */
    }

    buffer[n] = '\0';

    /* Get unitname without extension */
    char short_name[256];
    strncpy(short_name, unit_name, sizeof(short_name) - 1);
    short_name[sizeof(short_name) - 1] = '\0';

    /* Strip extension (.service, .socket, .timer, .target) */
    char *dot = strrchr(short_name, '.');
    if (dot && (strcmp(dot, ".service") == 0 || strcmp(dot, ".socket") == 0 ||
                strcmp(dot, ".timer") == 0 || strcmp(dot, ".target") == 0)) {
        *dot = '\0';
    }

    /* Get timestamp */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char timestamp[64];  /* Increased buffer size to avoid truncation warning */
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    /* Split buffer by newlines and log each line */
    char *line = buffer;
    char *newline;
    while ((newline = strchr(line, '\n')) != NULL) {
        *newline = '\0';
        if (line[0] != '\0') {  /* Skip empty lines */
            /* Check for special prefixes that should also go to console */
            bool to_console = false;
            const char *color = "";
            if (strncmp(line, "ERROR:", 6) == 0 || strncmp(line, "CRITICAL:", 9) == 0) {
                to_console = true;
                color = COLOR_RED;
                log_msg(LOG_ERR, unit_name, "[%s] %s %s", short_name, timestamp, line);
            } else if (strncmp(line, "WARNING:", 8) == 0 || strncmp(line, "WARN:", 5) == 0) {
                to_console = true;
                color = COLOR_YELLOW;
                log_msg(LOG_WARNING, unit_name, "[%s] %s %s", short_name, timestamp, line);
            } else {
                log_msg_silent(LOG_INFO, unit_name, "[%s] %s %s", short_name, timestamp, line);
                /* In debug mode, also show normal output on console */
                if (debug_mode) {
                    fprintf(stderr, "[%s] %s\n", short_name, line);
                }
            }

            /* Also write to console if it's an error/warning */
            if (to_console) {
                fprintf(stderr, "%s[%s] %s%s\n", color, short_name, line, COLOR_RESET);
            }
        }
        line = newline + 1;
    }
    /* Log remaining partial line if any */
    if (line[0] != '\0') {
        bool to_console = false;
        const char *color = "";
        if (strncmp(line, "ERROR:", 6) == 0 || strncmp(line, "CRITICAL:", 9) == 0) {
            to_console = true;
            color = COLOR_RED;
            log_msg(LOG_ERR, unit_name, "[%s] %s %s", short_name, timestamp, line);
        } else if (strncmp(line, "WARNING:", 8) == 0 || strncmp(line, "WARN:", 5) == 0) {
            to_console = true;
            color = COLOR_YELLOW;
            log_msg(LOG_WARNING, unit_name, "[%s] %s %s", short_name, timestamp, line);
        } else {
            log_msg_silent(LOG_INFO, unit_name, "[%s] %s %s", short_name, timestamp, line);
            /* In debug mode, also show normal output on console */
            if (debug_mode) {
                fprintf(stderr, "[%s] %s\n", short_name, line);
            }
        }

        if (to_console) {
            fprintf(stderr, "%s[%s] %s%s\n", color, short_name, line, COLOR_RESET);
        }
    }
}

/* Reap zombie processes and notify worker */
static void reap_zombies(void) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == worker_pid) {
            log_warn("supervisor", "worker exited (status %d)",
                     WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            worker_pid = 0;
        } else {
            /* Service process exited - unregister and notify worker */
            int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            log_msg_silent(LOG_DEBUG, "supervisor", "service pid %d exited (status %d)",
                      pid, exit_status);

            /* Remove from service registry */
            unregister_service(pid);

            /* Find any children that may have been reparented to us (for forking services) */
            /* Scan /proc to find processes with PPID = our PID */
            pid_t child_pids[8] = {0};
            int child_count = 0;
            DIR *proc_dir = opendir("/proc");
            if (proc_dir) {
                struct dirent *entry;
                while ((entry = readdir(proc_dir)) != NULL && child_count < 8) {
                    if (entry->d_type != DT_DIR) continue;
                    pid_t check_pid = atoi(entry->d_name);
                    if (check_pid <= 0) continue;

                    char stat_path[256];
                    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", check_pid);
                    FILE *fp = fopen(stat_path, "r");
                    if (fp) {
                        pid_t ppid = 0;
                        /* stat format: pid (comm) state ppid ... */
                        if (fscanf(fp, "%*d %*s %*c %d", &ppid) == 1) {
                            if (ppid == getpid() && check_pid != worker_pid) {
                                /* This process is our child and not the worker */
                                child_pids[child_count++] = check_pid;
                            }
                        }
                        fclose(fp);
                    }
                }
                closedir(proc_dir);
            }

            /* Send notification to worker */
            struct priv_response notif = {0};
            notif.type = RESP_SERVICE_EXITED;
            notif.service_pid = pid;
            notif.exit_status = exit_status;
            notif.child_pid_count = child_count;
            for (int i = 0; i < child_count; i++) {
                notif.child_pids[i] = child_pids[i];
            }

            if (send_response(ipc_socket, &notif) < 0) {
                log_error("supervisor", "failed to notify worker of service exit");
            }
        }
    }
}

/* Main loop: handle IPC from worker and service output */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int main_loop(void) {
    fd_set readfds;
    struct timeval tv;
    struct priv_request req;
    struct priv_response resp;

    while (!shutdown_requested && worker_pid > 0) {
        /* Set up select */
        FD_ZERO(&readfds);
        FD_SET(ipc_socket, &readfds);
        int max_fd = ipc_socket;

        /* Add all service output pipes to readfds */
        int service_count = 0;
        struct service_record *services = get_all_services(&service_count);
        for (int i = 0; i < service_count; i++) {
            if (services[i].in_use) {
                if (services[i].stdout_fd >= 0) {
                    FD_SET(services[i].stdout_fd, &readfds);
                    if (services[i].stdout_fd > max_fd) {
                        max_fd = services[i].stdout_fd;
                    }
                }
                if (services[i].stderr_fd >= 0) {
                    FD_SET(services[i].stderr_fd, &readfds);
                    if (services[i].stderr_fd > max_fd) {
                        max_fd = services[i].stderr_fd;
                    }
                }
            }
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("supervisor", "select: %s", strerror(errno));
            break;
        }

        /* Check for RuntimeMaxSec= timeouts */
        char timeout_unit[256];
        pid_t timeout_pid = check_runtime_timeout(timeout_unit, sizeof(timeout_unit));
        if (timeout_pid > 0) {
            log_info("supervisor", "Service %s exceeded RuntimeMaxSec, terminating", timeout_unit);
            process_tracking_signal_process(timeout_pid, SIGTERM);
            /* The service will be reaped in the normal SIGCHLD handler */
        }

        /* Handle IPC request from worker */
        if (ret > 0 && FD_ISSET(ipc_socket, &readfds)) {
            if (recv_request(ipc_socket, &req) < 0) {
                log_error("supervisor", "IPC read failed");
                break;
            }

            /* Handle the request */
            handle_request(&req, &resp);

            /* Send response */
            if (send_response(ipc_socket, &resp) < 0) {
                log_error("supervisor", "IPC write failed");
                free_request(&req);
                break;
            }

            /* Free dynamically allocated request fields */
            free_request(&req);
        }

        /* Read service output from pipes */
        if (ret > 0) {
            for (int i = 0; i < service_count; i++) {
                if (services[i].in_use) {
                    if (services[i].stdout_fd >= 0 && FD_ISSET(services[i].stdout_fd, &readfds)) {
                        read_service_output(services[i].stdout_fd, services[i].unit_name);
                    }
                    if (services[i].stderr_fd >= 0 && FD_ISSET(services[i].stderr_fd, &readfds)) {
                        read_service_output(services[i].stderr_fd, services[i].unit_name);
                    }
                }
            }
        }

        /* Reap zombies */
        reap_zombies();
    }

    return 0;
}

#ifndef UNIT_TEST
int main(int argc, const char * const argv[]) {
    const char *runtime_dir_arg = NULL;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--user-mode") == 0) {
            user_mode = true;
        } else if (strncmp(arg, "--runtime-dir=", 14) == 0) {
            runtime_dir_arg = arg + 14;
        } else if (strcmp(arg, "--runtime-dir") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "initd-supervisor: --runtime-dir requires a value\n");
                return 1;
            }
            runtime_dir_arg = argv[++i];
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            printf("Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "initd-supervisor: unknown option '%s'\n", arg);
            fprintf(stderr, "Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 1;
        }
    }

#if defined(__linux__) && !defined(UNIT_TEST)
    if (!user_mode && initd_is_running_as_init()) {
        if (ensure_run_tmpfs() < 0) {
            fprintf(stderr, "initd-supervisor: failed to mount tmpfs at /run: %s\n",
                    strerror(errno));
            return 1;
        }
    }
#endif

    const char *debug_env = getenv("INITD_DEBUG_SUPERVISOR");
    debug_mode = (debug_env && strcmp(debug_env, "0") != 0);

    if (runtime_dir_arg) {
        if (initd_validate_runtime_dir(runtime_dir_arg, user_mode) < 0) {
            fprintf(stderr, "initd-supervisor: runtime dir '%s' invalid: %s\n",
                    runtime_dir_arg, strerror(errno));
            return 1;
        }
        if (setenv(INITD_RUNTIME_DIR_ENV, runtime_dir_arg, 1) < 0) {
            fprintf(stderr, "initd-supervisor: setenv(%s) failed: %s\n",
                    INITD_RUNTIME_DIR_ENV, strerror(errno));
            return 1;
        }
    } else if (user_mode) {
        const char *current = getenv(INITD_RUNTIME_DIR_ENV);
        if (!current || current[0] == '\0') {
            char user_dir[PATH_MAX];
            if (initd_default_user_runtime_dir(user_dir, sizeof(user_dir)) < 0) {
                fprintf(stderr, "initd-supervisor: cannot determine user runtime directory.\n");
                fprintf(stderr, "Please set INITD_RUNTIME_DIR or use --runtime-dir.\n");
                return 1;
            }
            if (setenv(INITD_RUNTIME_DIR_ENV, user_dir, 1) < 0) {
                fprintf(stderr, "initd-supervisor: setenv(%s) failed: %s\n",
                        INITD_RUNTIME_DIR_ENV, strerror(errno));
                return 1;
            }
        }
    }

    if (initd_set_runtime_dir(NULL) < 0) {
        fprintf(stderr, "initd-supervisor: initd_set_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    /* Create runtime directory (owned by root or current user) */
    if (initd_ensure_runtime_dir() < 0) {
        fprintf(stderr, "initd-supervisor: initd_ensure_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    if (debug_mode) {
        log_debug("supervisor", "Ensuring runtime directory root exists");
    }

    if (!user_mode) {
        uid_t worker_uid;
        gid_t worker_gid;
        if (lookup_supervisor_user(&worker_uid, &worker_gid) == 0) {
            if (ensure_component_runtime_dir("supervisor", worker_uid, worker_gid, false) < 0) {
                fprintf(stderr, "initd-supervisor: ensure runtime dir failed: %s\n",
                        strerror(errno));
                return 1;
            }
        } else {
            return 1;
        }
    } else {
        if (ensure_component_runtime_dir("supervisor", 0, 0, true) < 0) {
            fprintf(stderr, "initd-supervisor: ensure runtime dir failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    /* Initialize enhanced logging */
    log_enhanced_init("initd-supervisor", NULL);
    if (debug_mode) {
        log_set_console_level(LOGLEVEL_DEBUG);
        log_set_file_level(LOGLEVEL_DEBUG);
    } else {
        log_set_console_level(LOGLEVEL_INFO);
        log_set_file_level(LOGLEVEL_INFO);
    }

    if (debug_mode) {
        log_info("supervisor", "Debug mode enabled (INITD_DEBUG_SUPERVISOR)");
    }
    log_info("supervisor", "Starting%s", user_mode ? " (user mode)" : "");

    /* Initialize service registry */
    log_msg_silent(LOG_DEBUG, "supervisor", "Initializing service registry");
    service_registry_init();

    /* Setup signals */
    log_msg_silent(LOG_DEBUG, "supervisor", "Setting up signal handlers");
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create IPC socket */
    log_msg_silent(LOG_DEBUG, "supervisor", "Creating IPC socket pair");
    int master_fd, worker_fd;
    if (create_ipc_socket(&master_fd, &worker_fd) < 0) {
        return 1;
    }
    log_debug("supervisor", "Created IPC socket pair (master_fd=%d, worker_fd=%d)",
              master_fd, worker_fd);
    ipc_socket = master_fd;

    /* Fork and exec worker */
    log_debug("supervisor", "Starting worker process");
    worker_pid = start_worker(worker_fd);
    if (worker_pid < 0) {
        return 1;
    }

    /* Main loop */
    log_debug("supervisor", "Entering main loop");
    main_loop();

    /* Cleanup */
    if (worker_pid > 0) {
        process_tracking_signal_process(worker_pid, SIGTERM);
        waitpid(worker_pid, NULL, 0);
    }

    /* Handle shutdown/reboot/halt if requested */
    if (shutdown_type != SHUTDOWN_NONE) {
        if (initd_is_running_as_init()) {
            /* Running as PID 1 or child of initd-init - perform system action */
            log_info("supervisor", "Performing system shutdown");

            #ifdef __linux__
            sync();

            switch (shutdown_type) {
            case SHUTDOWN_POWEROFF:
                reboot(RB_POWER_OFF);
                break;
            case SHUTDOWN_REBOOT:
                reboot(RB_AUTOBOOT);
                break;
            case SHUTDOWN_HALT:
                reboot(RB_HALT_SYSTEM);
                break;
            default:
                break;
            }
            #else
            /* Non-Linux: execute native shutdown commands */
            switch (shutdown_type) {
            case SHUTDOWN_POWEROFF:
                execl("/sbin/poweroff", "poweroff", NULL);
                execl("/sbin/shutdown", "shutdown", "-p", "now", NULL);
                break;
            case SHUTDOWN_REBOOT:
                execl("/sbin/reboot", "reboot", NULL);
                execl("/sbin/shutdown", "shutdown", "-r", "now", NULL);
                break;
            case SHUTDOWN_HALT:
                execl("/sbin/halt", "halt", NULL);
                execl("/sbin/shutdown", "shutdown", "-h", "now", NULL);
                break;
            default:
                break;
            }
            #endif

            log_error("supervisor", "shutdown failed: %s", strerror(errno));
            return 1;
        } else {
            /* Running standalone - execute native shutdown commands */
            log_info("supervisor", "Executing native shutdown command");

            switch (shutdown_type) {
            case SHUTDOWN_POWEROFF:
                execlp("poweroff", "poweroff", NULL);
                execlp("shutdown", "shutdown", "-P", "now", NULL);
                break;
            case SHUTDOWN_REBOOT:
                execlp("reboot", "reboot", NULL);
                execlp("shutdown", "shutdown", "-r", "now", NULL);
                break;
            case SHUTDOWN_HALT:
                execlp("halt", "halt", NULL);
                execlp("shutdown", "shutdown", "-h", "now", NULL);
                break;
            default:
                break;
            }

            log_error("supervisor", "shutdown command failed: %s", strerror(errno));
            return 1;
        }
    }

    log_info("supervisor", "Exiting");
    log_enhanced_close();
    return 0;
}
#endif /* !UNIT_TEST */
