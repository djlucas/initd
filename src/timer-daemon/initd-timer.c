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
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include "../common/timer-ipc.h"
#include "../common/privileged-ops.h"
#include "../common/parser.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexecdir/initd/initd-timer-worker"
#endif

#ifndef TIMER_USER
#define TIMER_USER "initd-timer"
#endif

static volatile sig_atomic_t shutdown_requested = 0;
static pid_t worker_pid = 0;

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
        fprintf(stderr, "initd-timer: worker exited\n");
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
        perror("initd-timer: sigaction SIGTERM");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("initd-timer: sigaction SIGINT");
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("initd-timer: sigaction SIGCHLD");
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
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        perror("initd-timer: socketpair");
        return -1;
    }

    /* Lookup worker user */
    struct passwd *pw = getpwnam(TIMER_USER);
    if (pw) {
        worker_uid = pw->pw_uid;
        worker_gid = pw->pw_gid;
    } else {
        fprintf(stderr, "initd-timer: warning: user %s not found, worker will run as root\n",
                TIMER_USER);
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("initd-timer: fork");
        return -1;
    }

    if (pid == 0) {
        /* Child: will become worker */
        close(sockets[0]); /* Close parent end */

        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", sockets[1]);

        /* Drop privileges before exec */
        if (worker_gid != 0) {
            if (setgroups(1, &worker_gid) < 0) {
                perror("initd-timer: setgroups");
                _exit(1);
            }

            if (setgid(worker_gid) < 0) {
                perror("initd-timer: setgid");
                _exit(1);
            }
        }

        if (worker_uid != 0) {
            if (setuid(worker_uid) < 0) {
                perror("initd-timer: setuid");
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (getuid() == 0 || geteuid() == 0) {
            fprintf(stderr, "initd-timer: failed to drop privileges!\n");
            _exit(1);
        }

        fprintf(stderr, "initd-timer-worker: running as uid=%d, gid=%d\n",
                getuid(), getgid());

        execl(WORKER_PATH, "initd-timer-worker", fd_str, NULL);
        perror("initd-timer: exec worker");
        _exit(1);
    }

    /* Parent */
    close(sockets[1]); /* Close child end */
    worker_pid = pid;

    fprintf(stderr, "initd-timer: spawned worker pid %d\n", pid);

    return sockets[0]; /* Return parent end for IPC */
}

int main(void) {
    fprintf(stderr, "initd-timer: starting (privileged daemon)\n");

    /* Must run as root */
    if (getuid() != 0) {
        fprintf(stderr, "initd-timer: must run as root\n");
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
            perror("initd-timer: select");
            break;
        }

        if (ret > 0 && FD_ISSET(worker_fd, &rfds)) {
            handle_request(worker_fd);
        }
    }

    /* Cleanup */
    if (worker_pid > 0) {
        fprintf(stderr, "initd-timer: waiting for worker to exit\n");
        kill(worker_pid, SIGTERM);
        waitpid(worker_pid, NULL, 0);
    }

    close(worker_fd);

    fprintf(stderr, "initd-timer: exiting\n");
    return 0;
}
