/* initd-supervisor.c - Privileged supervisor process
 *
 * Responsibilities:
 * - Fork supervisor-slave and drop privileges
 * - Handle privileged requests from slave (fork/exec services)
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
#ifdef __linux__
#include <sys/reboot.h>
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
static pid_t slave_pid = 0;
static int ipc_socket = -1;
static bool user_mode = false;

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

/* Create IPC socketpair for master/slave communication */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_ipc_socket(int *master_fd, int *slave_fd) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        log_error("supervisor", "socketpair: %s", strerror(errno));
        return -1;
    }

    *master_fd = sv[0];
    *slave_fd = sv[1];
    return 0;
}

/* Lookup unprivileged user for slave */
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
static pid_t start_slave(int slave_fd) {
    uid_t slave_uid;
    gid_t slave_gid;

    /* Lookup unprivileged user */
    if (lookup_supervisor_user(&slave_uid, &slave_gid) < 0) {
        log_error("supervisor", "cannot find unprivileged user for slave");
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        log_error("supervisor", "fork slave: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: will become slave */
        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", slave_fd);

        /* Drop privileges before exec */
        if (!user_mode && slave_gid != 0) {
            /* Set supplementary groups */
            if (setgroups(1, &slave_gid) < 0) {
                log_error("supervisor", "setgroups: %s", strerror(errno));
                _exit(1);
            }

            /* Set GID */
            if (setgid(slave_gid) < 0) {
                log_error("supervisor", "setgid: %s", strerror(errno));
                _exit(1);
            }
        }

        if (!user_mode && slave_uid != 0) {
            /* Set UID (must be last) */
            if (setuid(slave_uid) < 0) {
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

        execl(WORKER_PATH, "initd-supervisor-worker", fd_str, NULL);
        log_error("supervisor", "exec slave: %s", strerror(errno));
        _exit(1);
    }

    /* Parent */
    close(slave_fd); /* Master doesn't need slave's end */
    log_info("supervisor", "Started worker (pid %d)", pid);
    return pid;
}

/* Start a service process with privilege dropping */
static pid_t start_service_process(const struct service_section *service,
                                   const char *exec_path,
                                   char *const argv[],
                                   uid_t validated_uid,
                                   gid_t validated_gid) {
    if (!service || !exec_path || !argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child: will become service */

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

        /* Exec service using argv (NO SHELL - prevents injection) */
        execv(exec_path, argv);

        log_error("supervisor", "execv: %s", strerror(errno));
        _exit(1);
    }

    /* Parent */
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

/* Handle privileged request from slave */
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

        if (!unit.config.service.exec_start || unit.config.service.exec_start[0] == '\0') {
            resp->type = RESP_ERROR;
            resp->error_code = EINVAL;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Unit has no ExecStart");
            goto start_cleanup;
        }

        if (build_exec_argv(unit.config.service.exec_start, &exec_argv) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse ExecStart command");
            goto start_cleanup;
        }

        /* Defensive: exec_argv should never be NULL after successful build_exec_argv,
         * but verify before dereferencing to satisfy static analysis */
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

        /* Start service with validated credentials */
        int kill_mode = unit.config.service.kill_mode;
        pid_t pid = start_service_process(&unit.config.service, exec_path, exec_argv,
                                          validated_uid, validated_gid);
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
        if (register_service(pid, req->unit_name, unit.path, kill_mode) < 0) {
            /* Registry full - kill the service we just started */
            process_tracking_signal_process(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            resp->type = RESP_ERROR;
            resp->error_code = ENOMEM;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Service registry full");
            goto start_cleanup;
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
        resp->service_pid = pid;
        log_debug("supervisor", "started %s (pid %d)", req->unit_name, pid);
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

/* Reap zombie processes and notify slave */
static void reap_zombies(void) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == slave_pid) {
            log_warn("supervisor", "worker exited (status %d)",
                     WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            slave_pid = 0;
        } else {
            /* Service process exited - unregister and notify slave */
            int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            log_debug("supervisor", "service pid %d exited (status %d)",
                      pid, exit_status);

            /* Remove from service registry */
            unregister_service(pid);

            /* Send notification to slave */
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

/* Main loop: handle IPC from slave */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int main_loop(void) {
    fd_set readfds;
    struct timeval tv;
    struct priv_request req;
    struct priv_response resp;

    while (!shutdown_requested && slave_pid > 0) {
        /* Set up select */
        FD_ZERO(&readfds);
        FD_SET(ipc_socket, &readfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(ipc_socket + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("supervisor", "select: %s", strerror(errno));
            break;
        }

        /* Handle IPC request from slave */
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
                fprintf(stderr, "initd-supervisor: cannot determine user runtime directory.\n");
                fprintf(stderr, "Please set INITD_RUNTIME_DIR or use --runtime-dir.\n");
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

    /* Create runtime directory (owned by root) */
    if (initd_ensure_runtime_dir() < 0) {
        perror("initd_ensure_runtime_dir");
        return 1;
    }

    /* Create supervisor-specific subdirectory */
    const char *runtime_dir = getenv(INITD_RUNTIME_DIR_ENV);
    if (!runtime_dir || runtime_dir[0] == '\0') {
        runtime_dir = INITD_RUNTIME_DEFAULT;
    }
    char supervisor_dir[PATH_MAX];
    snprintf(supervisor_dir, sizeof(supervisor_dir), "%s/supervisor", runtime_dir);
    if (mkdir(supervisor_dir, 0755) < 0 && errno != EEXIST) {
        perror("mkdir supervisor directory");
        return 1;
    }

    /* Set ownership for worker in system mode */
    if (!user_mode) {
        uid_t worker_uid;
        gid_t worker_gid;
        if (lookup_supervisor_user(&worker_uid, &worker_gid) == 0) {
            if (chown(supervisor_dir, worker_uid, worker_gid) < 0) {
                perror("chown supervisor directory");
                return 1;
            }
        }
    }

    /* Initialize enhanced logging */
    log_enhanced_init("initd-supervisor", "/var/log/initd/supervisor.log");
    log_set_console_level(LOGLEVEL_INFO);
    log_set_file_level(LOGLEVEL_DEBUG);

    log_info("supervisor", "Starting%s", user_mode ? " (user mode)" : "");

    /* Initialize service registry */
    service_registry_init();

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create IPC socket */
    int master_fd, slave_fd;
    if (create_ipc_socket(&master_fd, &slave_fd) < 0) {
        return 1;
    }
    ipc_socket = master_fd;

    /* Fork and exec slave */
    slave_pid = start_slave(slave_fd);
    if (slave_pid < 0) {
        return 1;
    }

    /* Main loop */
    main_loop();

    /* Cleanup */
    if (slave_pid > 0) {
        process_tracking_signal_process(slave_pid, SIGTERM);
        waitpid(slave_pid, NULL, 0);
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
