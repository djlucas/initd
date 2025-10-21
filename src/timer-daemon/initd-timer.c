/* initd-timer.c - Privileged timer daemon
 *
 * Responsibilities:
 * - Fork initd-timer-worker and drop privileges
 * - Handle privileged operations (enable, disable, convert units)
 * - Minimal root code for security
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
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <limits.h>
#include "../common/timer-ipc.h"
#include "../common/privileged-ops.h"
#include "../common/parser.h"
#include "../common/control.h"
#include "../common/log-enhanced.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexec/initd/initd-timer-worker"
#endif

#ifndef TIMER_USER
#define TIMER_USER "initd-timer"
#endif

static volatile sig_atomic_t shutdown_requested = 0;
static pid_t worker_pid = 0;
static bool user_mode = false;

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

static int lookup_timer_user(uid_t *uid, gid_t *gid) {
    if (user_mode) {
        *uid = getuid();
        *gid = getgid();
        return 0;
    }

    struct passwd *pw = getpwnam(TIMER_USER);
    if (!pw) {
        if (!fallback_to_nobody_allowed()) {
            log_error("timer",
                      "user '%s' not found. Create the dedicated account or set "
                      "INITD_ALLOW_USER_FALLBACK=1 to permit an UNSUPPORTED fallback to 'nobody'",
                      TIMER_USER);
            return -1;
        }

        warn_user_fallback("initd-timer", TIMER_USER);
        pw = getpwnam("nobody");
        if (!pw) {
            log_error("timer", "fallback user 'nobody' not found; cannot continue");
            return -1;
        }
    }

    *uid = pw->pw_uid;
    *gid = pw->pw_gid;
    return 0;
}

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    if (worker_pid > 0) {
        kill(worker_pid, SIGTERM);
    }
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Worker exited */
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid == worker_pid) {
        log_warn("timer", "Worker exited");
        worker_pid = 0;
    }
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error("timer", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_error("timer", "sigaction SIGINT: %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        log_error("timer", "sigaction SIGCHLD: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Handle IPC request from worker */
static void handle_request(int worker_fd) {
    struct timer_request req = {0};
    struct timer_response resp = {0};
    struct unit_file unit = {0};

    if (recv_timer_request(worker_fd, &req) < 0) {
        return;
    }

    resp.type = TIMER_RESP_OK;
    resp.error_code = 0;

    /* Parse unit file for enable/disable operations */
    if (req.type == TIMER_REQ_ENABLE_UNIT || req.type == TIMER_REQ_DISABLE_UNIT ||
        req.type == TIMER_REQ_CONVERT_UNIT) {

        if (parse_unit_file(req.unit_path, &unit) < 0) {
            resp.type = TIMER_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to parse unit file");
            send_timer_response(worker_fd, &resp);
            return;
        }
    }

    switch (req.type) {
    case TIMER_REQ_ENABLE_UNIT:
        if (enable_unit(&unit) < 0) {
            resp.type = TIMER_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to enable unit");
        }
        break;

    case TIMER_REQ_DISABLE_UNIT:
        if (disable_unit(&unit) < 0) {
            resp.type = TIMER_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to disable unit");
        }
        break;

    case TIMER_REQ_CONVERT_UNIT:
        if (convert_systemd_unit(&unit) < 0) {
            resp.type = TIMER_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to convert unit");
        } else {
            strncpy(resp.converted_path, unit.path, sizeof(resp.converted_path) - 1);
        }
        break;

    default:
        resp.type = TIMER_RESP_ERROR;
        resp.error_code = EINVAL;
        snprintf(resp.error_msg, sizeof(resp.error_msg),
                "Unknown request type");
        break;
    }

    send_timer_response(worker_fd, &resp);
    free_unit_file(&unit);
}

/* Fork and exec worker process */
static int spawn_worker(void) {
    int sockets[2];
    uid_t worker_uid = 0;
    gid_t worker_gid = 0;

    /* Create socketpair for IPC */
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
        log_error("timer", "socketpair: %s", strerror(errno));
        return -1;
    }

    if (lookup_timer_user(&worker_uid, &worker_gid) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        log_error("timer", "fork: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: will become worker */
        close(sockets[0]); /* Close parent end */

        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", sockets[1]);

        /* Drop privileges before exec */
        if (!user_mode && worker_gid != 0) {
            if (setgroups(1, &worker_gid) < 0) {
                log_error("timer", "setgroups: %s", strerror(errno));
                _exit(1);
            }

            if (setgid(worker_gid) < 0) {
                log_error("timer", "setgid: %s", strerror(errno));
                _exit(1);
            }
        }

        if (!user_mode && worker_uid != 0) {
            if (setuid(worker_uid) < 0) {
                log_error("timer", "setuid: %s", strerror(errno));
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (!user_mode && (getuid() == 0 || geteuid() == 0)) {
            log_error("timer", "failed to drop privileges!");
            _exit(1);
        }

        log_debug("timer-worker", "running as uid=%d, gid=%d",
                  getuid(), getgid());

        execl(WORKER_PATH, "initd-timer-worker", fd_str, NULL);
        log_error("timer", "exec worker: %s", strerror(errno));
        _exit(1);
    }

    /* Parent */
    close(sockets[1]); /* Close child end */
    worker_pid = pid;

    log_info("timer", "Spawned worker (pid %d)", pid);

    return sockets[0]; /* Return parent end for IPC */
}

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
                fprintf(stderr, "initd-timer: --runtime-dir requires a value\n");
                return 1;
            }
            runtime_dir_arg = argv[++i];
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            fprintf(stderr, "Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "initd-timer: unknown option '%s'\n", arg);
            fprintf(stderr, "Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 1;
        }
    }

    if (runtime_dir_arg) {
        if (initd_validate_runtime_dir(runtime_dir_arg, user_mode) < 0) {
            fprintf(stderr, "initd-timer: runtime dir '%s' invalid: %s\n",
                    runtime_dir_arg, strerror(errno));
            return 1;
        }
        if (setenv(INITD_RUNTIME_DIR_ENV, runtime_dir_arg, 1) < 0) {
            fprintf(stderr, "initd-timer: setenv(%s) failed: %s\n",
                    INITD_RUNTIME_DIR_ENV, strerror(errno));
            return 1;
        }
    } else if (user_mode) {
        const char *current = getenv(INITD_RUNTIME_DIR_ENV);
        if (!current || current[0] == '\0') {
            char user_dir[PATH_MAX];
            if (initd_default_user_runtime_dir(user_dir, sizeof(user_dir)) < 0) {
                fprintf(stderr, "initd-timer: cannot determine user runtime directory.\n");
                fprintf(stderr, "Please set INITD_RUNTIME_DIR or use --runtime-dir.\n");
                return 1;
            }
            if (setenv(INITD_RUNTIME_DIR_ENV, user_dir, 1) < 0) {
                fprintf(stderr, "initd-timer: setenv(%s) failed: %s\n",
                        INITD_RUNTIME_DIR_ENV, strerror(errno));
                return 1;
            }
        }
    }

    if (initd_set_runtime_dir(NULL) < 0) {
        fprintf(stderr, "initd-timer: initd_set_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    /* Create runtime directory (owned by root or current user) */
    if (initd_ensure_runtime_dir() < 0) {
        fprintf(stderr, "initd-timer: initd_ensure_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    if (!user_mode) {
        uid_t worker_uid;
        gid_t worker_gid;
        if (lookup_timer_user(&worker_uid, &worker_gid) == 0) {
            if (ensure_component_runtime_dir("timer", worker_uid, worker_gid, false) < 0) {
                fprintf(stderr, "initd-timer: ensure runtime dir failed: %s\n",
                        strerror(errno));
                return 1;
            }
        } else {
            return 1;
        }
    } else {
        if (ensure_component_runtime_dir("timer", 0, 0, true) < 0) {
            fprintf(stderr, "initd-timer: ensure runtime dir failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    /* Initialize enhanced logging */
    log_enhanced_init("initd-timer", "/var/log/initd/timer.log");
    log_set_console_level(LOGLEVEL_INFO);
    log_set_file_level(LOGLEVEL_DEBUG);

    log_info("timer", "Starting%s", user_mode ? " (user mode)" : "");

    /* Must run as root unless user mode */
    if (!user_mode && getuid() != 0) {
        log_error("timer", "must run as root");
        return 1;
    }

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Spawn worker */
    int worker_fd = spawn_worker();
    if (worker_fd < 0) {
        return 1;
    }

    /* Main loop: handle IPC requests from worker */
    while (!shutdown_requested && worker_pid > 0) {
        fd_set rfds;
        struct timeval tv;

        FD_ZERO(&rfds);
        FD_SET(worker_fd, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(worker_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("timer", "select: %s", strerror(errno));
            break;
        }

        if (ret > 0 && FD_ISSET(worker_fd, &rfds)) {
            handle_request(worker_fd);
        }
    }

    /* Cleanup */
    if (worker_pid > 0) {
        log_info("timer", "Waiting for worker to exit");
        kill(worker_pid, SIGTERM);
        waitpid(worker_pid, NULL, 0);
    }

    close(worker_fd);

    log_info("timer", "Exiting");
    log_enhanced_close();
    return 0;
}
