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
#include <syslog.h>
#ifdef __linux__
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <sys/prctl.h>
#endif
#ifdef __FreeBSD__
#include <sys/procctl.h>
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
    char *token = strtok_r(copy, " \t", &saveptr);
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

    struct passwd *pw = getpwnam(SUPERVISOR_USER);
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

/* Start a service process with privilege dropping
 * Returns PID on success, -1 on error
 * On success, *stdout_pipe_fd and *stderr_pipe_fd are set to pipe read ends
 */
static pid_t start_service_process(const struct service_section *service,
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
                tty_fd = open(service->tty_path, O_RDWR | O_NOCTTY);
                if (tty_fd < 0) {
                    log_error("supervisor", "open TTY %s: %s", service->tty_path, strerror(errno));
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
            int file_fd = open(service->input_file, O_RDONLY);
            if (file_fd < 0) {
                log_error("supervisor", "open input file %s: %s", service->input_file, strerror(errno));
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
            int file_fd = open(service->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (file_fd < 0) {
                log_error("supervisor", "open output file %s: %s", service->output_file, strerror(errno));
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
            int file_fd = open(service->error_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (file_fd < 0) {
                log_error("supervisor", "open error file %s: %s", service->error_file, strerror(errno));
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
        }

        /* Verify we cannot regain privileges */
        if (validated_uid != 0) {
            if (setuid(0) == 0 || seteuid(0) == 0) {
                log_error("supervisor", "SECURITY: can still become root after dropping privileges!");
                _exit(1);
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
            log_warning("supervisor", "NoNewPrivileges= not supported on this platform");
#endif
        }

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

        if (unit.config.service.user[0] != '\0') {
            struct passwd *pw = getpwnam(unit.config.service.user);
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

        if (unit.config.service.group[0] != '\0') {
            struct group *gr = getgrnam(unit.config.service.group);
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
        } else if (validated_uid != 0) {
            /* If User specified but Group not specified, use user's primary group */
            struct passwd *pw = getpwuid(validated_uid);
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
        pid_t pid = start_service_process(&unit.config.service, exec_path, exec_argv,
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
        if (register_service(pid, req->unit_name, unit.path, kill_mode, stdout_fd, stderr_fd) < 0) {
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
                    struct passwd *pw = getpwnam(stop_unit.config.service.user);
                    if (!pw) {
                        log_error("supervisor", "stop: user '%s' not found",
                                  stop_unit.config.service.user);
                    } else {
                        validated_uid = pw->pw_uid;
                    }
                }

                if (stop_unit.config.service.group[0] != '\0') {
                    struct group *gr = getgrnam(stop_unit.config.service.group);
                    if (!gr) {
                        log_error("supervisor", "stop: group '%s' not found",
                                  stop_unit.config.service.group);
                    } else {
                        validated_gid = gr->gr_gid;
                    }
                } else if (validated_uid != 0) {
                    struct passwd *pw = getpwuid(validated_uid);
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
            struct passwd *pw = getpwnam(unit.config.service.user);
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
            struct group *gr = getgrnam(unit.config.service.group);
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
            struct passwd *pw = getpwuid(validated_uid);
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
            log_debug("supervisor", "service pid %d exited (status %d)",
                      pid, exit_status);

            /* Remove from service registry */
            unregister_service(pid);

            /* Send notification to worker */
            struct priv_response notif = {0};
            notif.type = RESP_SERVICE_EXITED;
            notif.service_pid = pid;
            notif.exit_status = exit_status;

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
int main(int argc, char *argv[]) {
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
    log_debug("supervisor", "Initializing service registry");
    service_registry_init();

    /* Setup signals */
    log_debug("supervisor", "Setting up signal handlers");
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create IPC socket */
    log_debug("supervisor", "Creating IPC socket pair");
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
