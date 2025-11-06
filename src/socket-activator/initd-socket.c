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
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include "../common/socket-ipc.h"
#include "../common/privileged-ops.h"
#include "../common/parser.h"
#include "../common/control.h"
#include "../common/log-enhanced.h"
#include "../common/path-security.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexec/initd/initd-socket-worker"
#endif

#ifndef SOCKET_USER
#define SOCKET_USER "initd-socket"
#endif

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t worker_exited = 0;
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

static int lookup_socket_user(uid_t *uid, gid_t *gid) {
    if (user_mode) {
        *uid = getuid();
        *gid = getgid();
        return 0;
    }

    const struct passwd *pw = getpwnam(SOCKET_USER);
    if (!pw) {
        if (!fallback_to_nobody_allowed()) {
            log_error("socket",
                      "user '%s' not found. Create the dedicated account or set "
                      "INITD_ALLOW_USER_FALLBACK=1 to permit an UNSUPPORTED fallback to 'nobody'",
                      SOCKET_USER);
            return -1;
        }

        warn_user_fallback("initd-socket", SOCKET_USER);
        pw = getpwnam("nobody");
        if (!pw) {
            log_error("socket", "fallback user 'nobody' not found; cannot continue");
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

/* SECURITY: Async-signal-safe handler - only sets flag
 * Calling log_warn() or other non-async-signal-safe functions here can cause
 * deadlock if the signal interrupts logging code that holds internal locks */
static void sigchld_handler(int sig) {
    (void)sig;
    /* Just set flag - reaping and logging happens in main loop */
    worker_exited = 1;
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error("socket", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_error("socket", "sigaction SIGINT: %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        log_error("socket", "sigaction SIGCHLD: %s", strerror(errno));
        return -1;
    }

    return 0;
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

        /* SECURITY: Validate unit path is in allowed directory before parsing */
        if (!validate_unit_path_from_worker(req.unit_path)) {
            log_error("socket", "SECURITY: invalid unit path: %s", req.unit_path);
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = EACCES;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Unit path not in allowed directory");
            send_socket_response(worker_fd, &resp);
            return;
        }

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

    case SOCKET_REQ_CHOWN: {
        uid_t uid = -1;
        gid_t gid = -1;

        /* Validate socket path is not empty */
        if (req.socket_path[0] == '\0') {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = EINVAL;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Empty socket path");
            break;
        }

        /* Validate path is absolute */
        if (req.socket_path[0] != '/') {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = EINVAL;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Socket path must be absolute");
            break;
        }

        /* SECURITY: Canonicalize path to prevent .. and symlink bypasses
         * Paths like /run/../etc/shadow could bypass prefix checks */
        char canonical_path[PATH_MAX];
        if (realpath(req.socket_path, canonical_path) == NULL) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Cannot resolve socket path: %s", strerror(errno));
            break;
        }

        /* SECURITY: Validate canonical path is within runtime directory */
        char *runtime_dir = getenv("XDG_RUNTIME_DIR");
        const char *allowed_prefix = runtime_dir ? runtime_dir : "/run";
        size_t prefix_len = strlen(allowed_prefix);

        if (strncmp(canonical_path, allowed_prefix, prefix_len) != 0 ||
            (canonical_path[prefix_len] != '/' && canonical_path[prefix_len] != '\0')) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = EPERM;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "Socket path must be under %s", allowed_prefix);
            break;
        }

        /* Look up owner if specified */
        if (req.owner[0] != '\0') {
            const struct passwd *pw = getpwnam(req.owner);
            if (pw) {
                uid = pw->pw_uid;
            } else {
                /* Try parsing as numeric UID */
                char *endptr;
                long parsed_uid = strtol(req.owner, &endptr, 10);
                if (*endptr == '\0' && parsed_uid >= 0 && parsed_uid <= INT_MAX) {
                    uid = (uid_t)parsed_uid;
                } else {
                    resp.type = SOCKET_RESP_ERROR;
                    resp.error_code = EINVAL;
                    snprintf(resp.error_msg, sizeof(resp.error_msg),
                            "Invalid user '%s'", req.owner);
                    break;
                }
            }
        }

        /* Look up group if specified */
        if (req.group[0] != '\0') {
            const struct group *gr = getgrnam(req.group);
            if (gr) {
                gid = gr->gr_gid;
            } else {
                /* Try parsing as numeric GID */
                char *endptr;
                long parsed_gid = strtol(req.group, &endptr, 10);
                if (*endptr == '\0' && parsed_gid >= 0 && parsed_gid <= INT_MAX) {
                    gid = (gid_t)parsed_gid;
                } else {
                    resp.type = SOCKET_RESP_ERROR;
                    resp.error_code = EINVAL;
                    snprintf(resp.error_msg, sizeof(resp.error_msg),
                            "Invalid group '%s'", req.group);
                    break;
                }
            }
        }

        /* Perform chown operation using fchownat with AT_SYMLINK_NOFOLLOW
         * to prevent following symlinks to arbitrary files */
        if (fchownat(AT_FDCWD, req.socket_path, uid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
            resp.type = SOCKET_RESP_ERROR;
            resp.error_code = errno;
            snprintf(resp.error_msg, sizeof(resp.error_msg),
                    "fchownat failed: %s", strerror(errno));
        }
        break;
    }

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
        log_error("socket", "socketpair: %s", strerror(errno));
        return -1;
    }

    if (lookup_socket_user(&worker_uid, &worker_gid) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        log_error("socket", "fork: %s", strerror(errno));
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
                log_error("socket", "setgroups: %s", strerror(errno));
                _exit(1);
            }

            if (setgid(worker_gid) < 0) {
                log_error("socket", "setgid: %s", strerror(errno));
                _exit(1);
            }
        }

        if (!user_mode && worker_uid != 0) {
            if (setuid(worker_uid) < 0) {
                log_error("socket", "setuid: %s", strerror(errno));
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (!user_mode && (getuid() == 0 || geteuid() == 0)) {
            log_error("socket", "failed to drop privileges!");
            _exit(1);
        }

        log_debug("socket-worker", "running as uid=%d, gid=%d",
                  getuid(), getgid());

        /* Clear FD_CLOEXEC flag so worker_fd survives exec */
        int flags = fcntl(sockets[1], F_GETFD);
        if (flags >= 0) {
            fcntl(sockets[1], F_SETFD, flags & ~FD_CLOEXEC);
        }

        execl(WORKER_PATH, "initd-socket-worker", fd_str, NULL);
        log_error("socket", "exec worker: %s", strerror(errno));
        _exit(1);
    }

    /* Parent */
    close(sockets[1]); /* Close child end */
    worker_pid = pid;

    log_info("socket", "Spawned worker (pid %d)", pid);

    return sockets[0]; /* Return parent end for IPC */
}

int main(int argc, char * const argv[]) {
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
        if (initd_validate_runtime_dir(runtime_dir_arg, user_mode) < 0) {
            fprintf(stderr, "initd-socket: runtime dir '%s' invalid: %s\n",
                    runtime_dir_arg, strerror(errno));
            return 1;
        }
        if (setenv(INITD_RUNTIME_DIR_ENV, runtime_dir_arg, 1) < 0) {
            fprintf(stderr, "initd-socket: setenv(%s) failed: %s\n",
                    INITD_RUNTIME_DIR_ENV, strerror(errno));
            return 1;
        }
    } else if (user_mode) {
        const char *current = getenv(INITD_RUNTIME_DIR_ENV);
        if (!current || current[0] == '\0') {
            char user_dir[PATH_MAX];
            if (initd_default_user_runtime_dir(user_dir, sizeof(user_dir)) < 0) {
                fprintf(stderr, "initd-socket: cannot determine user runtime directory.\n");
                fprintf(stderr, "Please set INITD_RUNTIME_DIR or use --runtime-dir.\n");
                return 1;
            }
            if (setenv(INITD_RUNTIME_DIR_ENV, user_dir, 1) < 0) {
                fprintf(stderr, "initd-socket: setenv(%s) failed: %s\n",
                        INITD_RUNTIME_DIR_ENV, strerror(errno));
                return 1;
            }
        }
    }

    if (initd_set_runtime_dir(NULL) < 0) {
        fprintf(stderr, "initd-socket: initd_set_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    /* Create runtime directory (owned by root or current user) */
    if (initd_ensure_runtime_dir() < 0) {
        fprintf(stderr, "initd-socket: initd_ensure_runtime_dir failed: %s\n",
                strerror(errno));
        return 1;
    }

    if (!user_mode) {
        uid_t worker_uid;
        gid_t worker_gid;
        if (lookup_socket_user(&worker_uid, &worker_gid) == 0) {
            if (ensure_component_runtime_dir("socket", worker_uid, worker_gid, false) < 0) {
                fprintf(stderr, "initd-socket: ensure runtime dir failed: %s\n",
                        strerror(errno));
                return 1;
            }
        } else {
            return 1;
        }
    } else {
        if (ensure_component_runtime_dir("socket", 0, 0, true) < 0) {
            fprintf(stderr, "initd-socket: ensure runtime dir failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    /* Initialize enhanced logging */
    log_enhanced_init("initd-socket", NULL);

    const char *debug_env = getenv("INITD_DEBUG_SOCKET");
    bool debug_mode = (debug_env && strcmp(debug_env, "0") != 0);
    if (debug_mode) {
        log_set_console_level(LOGLEVEL_DEBUG);
        log_set_file_level(LOGLEVEL_DEBUG);
        log_info("socket", "Debug mode enabled (INITD_DEBUG_SOCKET)");
    } else {
        log_set_console_level(LOGLEVEL_INFO);
        log_set_file_level(LOGLEVEL_INFO);
    }

    log_info("socket", "Starting%s", user_mode ? " (user mode)" : "");

    /* Must run as root unless user mode */
    if (!user_mode && getuid() != 0) {
        log_error("socket", "must run as root");
        return 1;
    }

    /* Setup signals */
    log_debug("socket", "Setting up signal handlers");
    if (setup_signals() < 0) {
        return 1;
    }

    /* Spawn worker */
    log_debug("socket", "Starting worker process");
    int worker_fd = spawn_worker();
    if (worker_fd < 0) {
        return 1;
    }

    /* Main loop: handle IPC requests from worker */
    log_debug("socket", "Entering main loop");
    while (!shutdown_requested && worker_pid > 0) {
        /* Check if worker exited (set by signal handler) */
        if (worker_exited) {
            worker_exited = 0;
            int status;
            pid_t pid = waitpid(-1, &status, WNOHANG);
            if (pid == worker_pid) {
                log_warn("socket", "Worker exited (status %d)",
                        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
                worker_pid = 0;
                break;
            }
        }

        fd_set rfds;
        struct timeval tv;

        FD_ZERO(&rfds);
        FD_SET(worker_fd, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(worker_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("socket", "select: %s", strerror(errno));
            break;
        }

        if (ret > 0 && FD_ISSET(worker_fd, &rfds)) {
            handle_request(worker_fd);
        }
    }

    /* Cleanup */
    if (worker_pid > 0) {
        log_info("socket", "Waiting for worker to exit");
        kill(worker_pid, SIGTERM);
        waitpid(worker_pid, NULL, 0);
    }

    close(worker_fd);

    log_info("socket", "Exiting");
    log_enhanced_close();
    return 0;
}
