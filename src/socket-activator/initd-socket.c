/* initd-socket.c - Privileged socket activation daemon
 *
 * Responsibilities:
 * - Fork initd-socket-worker and drop privileges
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
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <limits.h>
#include "../common/socket-ipc.h"
#include "../common/privileged-ops.h"
#include "../common/parser.h"
#include "../common/control.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexecdir/initd/initd-socket-worker"
#endif

#ifndef SOCKET_USER
#define SOCKET_USER "initd-socket"
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
    fprintf(stderr,
            "\033[1;31m%s: WARNING: dedicated user '%s' not found; falling back to 'nobody'. "
            "This mode is UNSUPPORTED for production.\033[0m\n",
            component, missing_user);
}

static int lookup_socket_user(uid_t *uid, gid_t *gid) {
    if (user_mode) {
        *uid = getuid();
        *gid = getgid();
        return 0;
    }

    struct passwd *pw = getpwnam(SOCKET_USER);
    if (!pw) {
        if (!fallback_to_nobody_allowed()) {
            fprintf(stderr,
                    "initd-socket: ERROR: user '%s' not found. "
                    "Create the dedicated account or set INITD_ALLOW_USER_FALLBACK=1 "
                    "to permit an UNSUPPORTED fallback to 'nobody'.\n",
                    SOCKET_USER);
            return -1;
        }

        warn_user_fallback("initd-socket", SOCKET_USER);
        pw = getpwnam("nobody");
        if (!pw) {
            fprintf(stderr,
                    "initd-socket: ERROR: fallback user 'nobody' not found; cannot continue.\n");
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
        fprintf(stderr, "initd-socket: worker exited\n");
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
        perror("initd-socket: sigaction SIGTERM");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("initd-socket: sigaction SIGINT");
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("initd-socket: sigaction SIGCHLD");
        return -1;
    }

    return 0;
}

/* Handle IPC request from worker */
static void handle_request(int worker_fd) {
    struct socket_request req = {0};
    struct socket_response resp = {0};
    struct unit_file unit = {0};

    if (recv_socket_request(worker_fd, &req) < 0) {
        return;
    }

    resp.type = SOCKET_RESP_OK;
    resp.error_code = 0;

    /* Parse unit file for enable/disable operations */
    if (req.type == SOCKET_REQ_ENABLE_UNIT || req.type == SOCKET_REQ_DISABLE_UNIT ||
        req.type == SOCKET_REQ_CONVERT_UNIT) {

        if (parse_unit_file(req.unit_path, &unit) < 0) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to parse unit file");
            send_socket_response(worker_fd, &resp);
            return;
        }
    }

    switch (req.type) {
    case SOCKET_REQ_ENABLE_UNIT:
        if (enable_unit(&unit) < 0) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to enable unit");
        }
        break;

    case SOCKET_REQ_DISABLE_UNIT:
        if (disable_unit(&unit) < 0) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to disable unit");
        }
        break;

    case SOCKET_REQ_CONVERT_UNIT:
        if (convert_systemd_unit(&unit) < 0) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Failed to convert unit");
        } else {
            strncpy(resp.converted_path, unit.path, sizeof(resp.converted_path) - 1);
        }
        break;

    default:
        resp.type = SOCKET_RESP_ERROR;
        resp.error_code = EINVAL;
        snprintf(resp.error_msg, sizeof(resp.error_msg),
                "Unknown request type");
        break;
    }

    send_socket_response(worker_fd, &resp);
    free_unit_file(&unit);
}

/* Fork and exec worker process */
static int spawn_worker(void) {
    int sockets[2];
    uid_t worker_uid = 0;
    gid_t worker_gid = 0;

    /* Create socketpair for IPC */
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
        perror("initd-socket: socketpair");
        return -1;
    }

    if (lookup_socket_user(&worker_uid, &worker_gid) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("initd-socket: fork");
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
                perror("initd-socket: setgroups");
                _exit(1);
            }

            if (setgid(worker_gid) < 0) {
                perror("initd-socket: setgid");
                _exit(1);
            }
        }

        if (!user_mode && worker_uid != 0) {
            if (setuid(worker_uid) < 0) {
                perror("initd-socket: setuid");
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (!user_mode && (getuid() == 0 || geteuid() == 0)) {
            fprintf(stderr, "initd-socket: failed to drop privileges!\n");
            _exit(1);
        }

        fprintf(stderr, "initd-socket-worker: running as uid=%d, gid=%d\n",
                getuid(), getgid());

        execl(WORKER_PATH, "initd-socket-worker", fd_str, NULL);
        perror("initd-socket: exec worker");
        _exit(1);
    }

    /* Parent */
    close(sockets[1]); /* Close child end */
    worker_pid = pid;

    fprintf(stderr, "initd-socket: spawned worker pid %d\n", pid);

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
                fprintf(stderr, "initd-socket: --runtime-dir requires a value\n");
                return 1;
            }
            runtime_dir_arg = argv[++i];
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            fprintf(stderr, "Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "initd-socket: unknown option '%s'\n", arg);
            fprintf(stderr, "Usage: %s [--user-mode] [--runtime-dir PATH]\n", argv[0]);
            return 1;
        }
    }

    if (runtime_dir_arg) {
        if (setenv(INITD_RUNTIME_DIR_ENV, runtime_dir_arg, 1) < 0) {
            perror("setenv");
            return 1;
        }
    } else if (user_mode) {
        const char *current = getenv(INITD_RUNTIME_DIR_ENV);
        if (!current || current[0] == '\0') {
            char user_dir[PATH_MAX];
            if (initd_default_user_runtime_dir(user_dir, sizeof(user_dir)) < 0) {
                perror("initd_default_user_runtime_dir");
                return 1;
            }
            if (setenv(INITD_RUNTIME_DIR_ENV, user_dir, 1) < 0) {
                perror("setenv");
                return 1;
            }
        }
    }

    if (initd_set_runtime_dir(NULL) < 0) {
        perror("initd_set_runtime_dir");
        return 1;
    }

    fprintf(stderr, "initd-socket: starting%s\n", user_mode ? " (user mode)" : "");

    /* Must run as root unless user mode */
    if (!user_mode && getuid() != 0) {
        fprintf(stderr, "initd-socket: must run as root\n");
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
            perror("initd-socket: select");
            break;
        }

        if (ret > 0 && FD_ISSET(worker_fd, &rfds)) {
            handle_request(worker_fd);
        }
    }

    /* Cleanup */
    if (worker_pid > 0) {
        fprintf(stderr, "initd-socket: waiting for worker to exit\n");
        kill(worker_pid, SIGTERM);
        waitpid(worker_pid, NULL, 0);
    }

    close(worker_fd);

    fprintf(stderr, "initd-socket: exiting\n");
    return 0;
}
