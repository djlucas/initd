/* supervisor-slave.c - Unprivileged supervisor process
 *
 * Responsibilities:
 * - Parse unit files
 * - Build dependency graph
 * - Manage service state
 * - Monitor service PIDs
 * - Handle timer scheduling
 * - Accept systemctl connections
 * - Log to syslog
 *
 * Concurrency model:
 *   The worker runs a single-threaded event loop (poll/select) and services
 *   one request at a time. Dependency walks (`start_unit_recursive_depth`,
 *   `stop_unit_recursive_depth`) are therefore always executed serially and
 *   never interleave. This guarantees deterministic ordering without the
 *   complexity of locking; if the design ever changes to permit multiple
 *   outstanding operations, the dependency walkers would need additional
 *   synchronization.
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <stdbool.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/ucred.h>
#endif
#include "../common/ipc.h"
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/parser.h"
#include "../common/scanner.h"
#include "../common/log.h"
#include "../common/log-enhanced.h"

static volatile sig_atomic_t shutdown_requested = 0;
static int master_socket = -1;
static int control_socket = -1;
static int status_socket = -1;
static struct unit_file **units = NULL;
static int unit_count = 0;
static unsigned int start_traversal_generation = 0;
static unsigned int stop_traversal_generation = 0;
static unsigned int isolate_generation = 0;

/* Forward declarations */
static bool unit_provides(struct unit_file *unit, const char *service_name);
static int stop_unit_recursive(struct unit_file *unit);
static int start_unit_recursive(struct unit_file *unit);
static int stop_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation);
static int start_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation);
static void mark_isolate_closure(struct unit_file *unit, unsigned int generation);

/* Maximum recursion depth for dependency resolution */
#define MAX_RECURSION_DEPTH 100

static void reset_start_traversal_marks(void) {
    for (int i = 0; i < unit_count; i++) {
        units[i]->start_traversal_id = 0;
        units[i]->start_visit_state = DEP_VISIT_NONE;
    }
}

static unsigned int next_start_generation(void) {
    if (start_traversal_generation == UINT_MAX) {
        start_traversal_generation = 1;
        reset_start_traversal_marks();
    } else {
        start_traversal_generation++;
    }
    return start_traversal_generation;
}

static void reset_stop_traversal_marks(void) {
    for (int i = 0; i < unit_count; i++) {
        units[i]->stop_traversal_id = 0;
        units[i]->stop_visit_state = DEP_VISIT_NONE;
    }
}

static unsigned int next_stop_generation(void) {
    if (stop_traversal_generation == UINT_MAX) {
        stop_traversal_generation = 1;
        reset_stop_traversal_marks();
    } else {
        stop_traversal_generation++;
    }
    return stop_traversal_generation;
}

static void reset_isolate_marks(void) {
    for (int i = 0; i < unit_count; i++) {
        units[i]->isolate_mark_generation = 0;
        units[i]->isolate_needed = false;
    }
}

static unsigned int next_isolate_generation(void) {
    if (isolate_generation == UINT_MAX) {
        isolate_generation = 1;
        reset_isolate_marks();
    } else {
        isolate_generation++;
    }
    return isolate_generation;
}

static bool is_control_client_authorized(int client_fd) {
#if defined(__linux__)
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
        if (cred.uid == 0 || cred.uid == getuid()) {
            return true;
        }
        log_warn("worker", "unauthorized control socket client (uid=%u); connection rejected",
                 (unsigned int)cred.uid);
        return false;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    uid_t euid;
    gid_t egid;
    if (getpeereid(client_fd, &euid, &egid) == 0) {
        if (euid == 0 || euid == getuid()) {
            return true;
        }
        log_warn("worker", "unauthorized control socket client (uid=%u); connection rejected",
                 (unsigned int)euid);
        return false;
    }
#endif
    log_warn("worker", "unable to verify control socket client credentials; permitting connection");
    return true;
}

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
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
        log_error("worker", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Lookup user/group IDs */
static int lookup_user(const char *user, uid_t *uid, gid_t *gid) {
    if (!user || user[0] == '\0') {
        *uid = 0;
        *gid = 0;
        return 0;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        return -1;
    }

    *uid = pw->pw_uid;
    *gid = pw->pw_gid;
    return 0;
}

/* Request master to enable a unit */
static int enable_unit(struct unit_file *unit) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_ENABLE_UNIT;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit->path, sizeof(req.unit_path) - 1);

    log_debug("worker", "enabling %s", unit->name);

    /* Send request to master */
    if (send_request(master_socket, &req) < 0) {
        return -1;
    }

    /* Receive response */
    if (recv_response(master_socket, &resp) < 0) {
        return -1;
    }

    if (resp.type == RESP_UNIT_ENABLED) {
        return 0;
    } else if (resp.type == RESP_ERROR) {
        log_error("worker", "failed to enable %s: %s", unit->name, resp.error_msg);
        errno = resp.error_code;
        return -1;
    }

    return -1;
}

/* Request master to disable a unit */
static int disable_unit(struct unit_file *unit) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_DISABLE_UNIT;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit->path, sizeof(req.unit_path) - 1);

    log_debug("worker", "disabling %s", unit->name);

    /* Send request to master */
    if (send_request(master_socket, &req) < 0) {
        return -1;
    }

    /* Receive response */
    if (recv_response(master_socket, &resp) < 0) {
        return -1;
    }

    if (resp.type == RESP_UNIT_DISABLED) {
        return 0;
    } else if (resp.type == RESP_ERROR) {
        log_error("worker", "failed to disable %s: %s", unit->name, resp.error_msg);
        errno = resp.error_code;
        return -1;
    }

    return -1;
}

/* Check if a unit is enabled (requires IPC, but we'll implement a simple version) */
static bool is_unit_enabled(struct unit_file *unit) {
    /* For now, we'll just check if symlinks exist in the file system.
     * This doesn't require root privileges, so we can do it directly.
     * The enable/disable operations require root, but checking status doesn't. */

    /* This is a simplified check - we look for the unit in common target .wants dirs */
    char symlink_path[1024];
    struct stat st;

    /* Check multi-user.target.wants */
    snprintf(symlink_path, sizeof(symlink_path),
             "/etc/initd/system/multi-user.target.wants/%s", unit->name);
    if (stat(symlink_path, &st) == 0) return true;

    snprintf(symlink_path, sizeof(symlink_path),
             "/lib/initd/system/multi-user.target.wants/%s", unit->name);
    if (stat(symlink_path, &st) == 0) return true;

    /* Check default.target.wants */
    snprintf(symlink_path, sizeof(symlink_path),
             "/etc/initd/system/default.target.wants/%s", unit->name);
    if (stat(symlink_path, &st) == 0) return true;

    snprintf(symlink_path, sizeof(symlink_path),
             "/lib/initd/system/default.target.wants/%s", unit->name);
    if (stat(symlink_path, &st) == 0) return true;

    /* Check if unit has WantedBy or RequiredBy */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        snprintf(symlink_path, sizeof(symlink_path),
                 "/etc/initd/system/%s.wants/%s", unit->install.wanted_by[i], unit->name);
        if (stat(symlink_path, &st) == 0) return true;

        snprintf(symlink_path, sizeof(symlink_path),
                 "/lib/initd/system/%s.wants/%s", unit->install.wanted_by[i], unit->name);
        if (stat(symlink_path, &st) == 0) return true;
    }

    for (int i = 0; i < unit->install.required_by_count; i++) {
        snprintf(symlink_path, sizeof(symlink_path),
                 "/etc/initd/system/%s.requires/%s", unit->install.required_by[i], unit->name);
        if (stat(symlink_path, &st) == 0) return true;

        snprintf(symlink_path, sizeof(symlink_path),
                 "/lib/initd/system/%s.requires/%s", unit->install.required_by[i], unit->name);
        if (stat(symlink_path, &st) == 0) return true;
    }

    return false;
}

/* Request master to stop a service */
static int stop_service(struct unit_file *unit) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    if (unit->state != STATE_ACTIVE || unit->pid <= 0) {
        return 0; /* Nothing to stop */
    }

    req.type = REQ_STOP_SERVICE;
    req.service_pid = unit->pid;
    req.kill_mode = unit->config.service.kill_mode;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit->path, sizeof(req.unit_path) - 1);

    fprintf(stderr, "slave: stopping %s (pid %d)\n", unit->name, unit->pid);

    /* Send request to master */
    if (send_request(master_socket, &req) < 0) {
        return -1;
    }

    /* Receive response */
    if (recv_response(master_socket, &resp) < 0) {
        return -1;
    }

    if (resp.type == RESP_SERVICE_STOPPED || resp.type == RESP_OK) {
        unit->state = STATE_INACTIVE;

        /* Wait for process to actually exit with timeout */
        int timeout = unit->config.service.timeout_stop_sec;
        if (timeout <= 0) timeout = 90; /* Default 90 seconds */

        int waited = 0;
        while (waited < timeout) {
            /* Check if process is still alive */
            if (kill(unit->pid, 0) < 0) {
                /* Process is gone */
                unit->pid = 0;
                return 0;
            }
            sleep(1);
            waited++;
        }

        /* Timeout - send SIGKILL */
        fprintf(stderr, "slave: %s stop timeout, sending SIGKILL\n", unit->name);
        kill(unit->pid, SIGKILL);
        sleep(1); /* Give it a moment */
        unit->pid = 0;
        return 0;
    }

    return -1;
}

/* Request master to reload a service */
static int reload_service(struct unit_file *unit) {
    if (unit->state != STATE_ACTIVE || unit->pid <= 0) {
        errno = ESRCH;
        return -1;
    }

    if (!unit->config.service.exec_reload || unit->config.service.exec_reload[0] == '\0') {
        errno = ENOTSUP;
        return -1;
    }

    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_RELOAD_SERVICE;
    req.service_pid = unit->pid;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit->path, sizeof(req.unit_path) - 1);

    if (send_request(master_socket, &req) < 0) {
        return -1;
    }

    if (recv_response(master_socket, &resp) < 0) {
        return -1;
    }

    if (resp.type == RESP_SERVICE_RELOADED || resp.type == RESP_OK) {
        return 0;
    }

    if (resp.type == RESP_ERROR) {
        errno = resp.error_code;
    } else {
        errno = EPROTO;
    }

    return -1;
}

/* Request master to start a service */
static pid_t start_service(struct unit_file *unit) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit->path, sizeof(req.unit_path) - 1);

    if (unit->type == UNIT_SERVICE) {
        strncpy(req.exec_path, unit->config.service.exec_start, sizeof(req.exec_path) - 1);

        /* Lookup user/group */
        if (lookup_user(unit->config.service.user, &req.run_uid, &req.run_gid) < 0) {
            fprintf(stderr, "slave: failed to lookup user %s\n", unit->config.service.user);
            return -1;
        }

        /* Copy service configuration for environment setup */
        req.private_tmp = unit->config.service.private_tmp;
        req.limit_nofile = unit->config.service.limit_nofile;
        req.kill_mode = unit->config.service.kill_mode;
    }

    /* Send request to master */
    if (send_request(master_socket, &req) < 0) {
        return -1;
    }

    /* Receive response */
    if (recv_response(master_socket, &resp) < 0) {
        return -1;
    }

    if (resp.type == RESP_SERVICE_STARTED) {
        unit->pid = resp.service_pid;
        unit->state = STATE_ACTIVE;

        /* Check if this service provides syslog */
        if (unit_provides(unit, "syslog")) {
            log_msg(LOG_INFO, NULL, "syslog provider started, flushing buffered logs");
            log_syslog_ready();
        }

        return resp.service_pid;
    }

    return -1;
}

/* Notify master of shutdown completion */
static int notify_shutdown_complete(void) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_SHUTDOWN_COMPLETE;

    send_request(master_socket, &req);
    recv_response(master_socket, &resp);

    return 0;
}

/* Find unit by name */
static struct unit_file *find_unit(const char *name) {
    for (int i = 0; i < unit_count; i++) {
        if (strcmp(units[i]->name, name) == 0) {
            return units[i];
        }
    }
    return NULL;
}

static struct unit_file *resolve_unit(const char *name) {
    struct unit_file *unit = find_unit(name);
    if (unit) {
        return unit;
    }

    for (int i = 0; i < unit_count; i++) {
        if (unit_provides(units[i], name)) {
            return units[i];
        }
    }

    return NULL;
}

/* Find unit by PID */
static struct unit_file *find_unit_by_pid(pid_t pid) {
    for (int i = 0; i < unit_count; i++) {
        if (units[i]->pid == pid) {
            return units[i];
        }
    }
    return NULL;
}

/* Notify timer daemon that a service became inactive */
static void notify_timer_daemon_inactive(const char *service_name) {
    if (!service_name || service_name[0] == '\0') {
        return;
    }

    int fd = connect_to_timer_daemon();
    if (fd < 0) {
        log_msg(LOG_DEBUG, service_name, "timer daemon unavailable for notify-inactive");
        return;
    }

    struct control_request req = {0};
    struct control_response resp = {0};

    req.header.length = sizeof(req);
    req.header.command = CMD_NOTIFY_INACTIVE;
    strncpy(req.unit_name, service_name, sizeof(req.unit_name) - 1);

    if (send_control_request(fd, &req) < 0) {
        log_msg(LOG_WARNING, service_name, "failed to send notify-inactive to timer daemon");
        close(fd);
        return;
    }

    if (recv_control_response(fd, &resp) < 0) {
        log_msg(LOG_WARNING, service_name, "no response from timer daemon for notify-inactive");
        close(fd);
        return;
    }

    close(fd);

    if (resp.code != RESP_SUCCESS) {
        log_msg(LOG_DEBUG, service_name, "timer daemon notify-inactive: %s", resp.message);
    } else {
        log_msg(LOG_DEBUG, service_name, "timer daemon acknowledged notify-inactive");
    }
}

/* Check if unit provides a specific service */
static bool unit_provides(struct unit_file *unit, const char *service_name) {
    for (int i = 0; i < unit->unit.provides_count; i++) {
        if (strcmp(unit->unit.provides[i], service_name) == 0) {
            return true;
        }
    }
    return false;
}

/* Handle service exit notification from master */
static void handle_service_exit(pid_t pid, int exit_status) {
    struct unit_file *unit = find_unit_by_pid(pid);
    if (!unit) {
        log_msg(LOG_WARNING, NULL, "unknown service pid %d exited", pid);
        return;
    }

    log_msg(LOG_INFO, unit->name, "exited with status %d", exit_status);

    unit->pid = 0;

    /* Determine if this was a successful exit */
    bool success = (exit_status == 0);

    /* Update state based on exit status */
    if (success) {
        unit->state = STATE_INACTIVE;
    } else {
        unit->state = STATE_FAILED;
    }

    if (success && unit->type == UNIT_SERVICE) {
        notify_timer_daemon_inactive(unit->name);
    }

    /* Handle restart policy */
    bool should_restart = false;
    switch (unit->config.service.restart) {
    case RESTART_ALWAYS:
        should_restart = true;
        break;
    case RESTART_ON_FAILURE:
        should_restart = !success;
        break;
    case RESTART_NO:
    default:
        should_restart = false;
        break;
    }

    if (should_restart && !shutdown_requested) {
        int restart_sec = unit->config.service.restart_sec;
        if (restart_sec <= 0) restart_sec = 1; /* Default 1 second */

        fprintf(stderr, "slave: restarting %s in %d seconds (restart count: %d)\n",
                unit->name, restart_sec, unit->restart_count + 1);

        sleep(restart_sec);

        unit->restart_count++;
        if (start_service(unit) > 0) {
            fprintf(stderr, "slave: successfully restarted %s\n", unit->name);
        } else {
            fprintf(stderr, "slave: failed to restart %s\n", unit->name);
        }
    }
}

/* Create and bind control socket */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_control_socket(void) {
    const char *path = control_socket_path(false);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        log_error("worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("worker", "socket: %s", strerror(errno));
        return -1;
    }

    unlink(path);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("worker", "bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (fchmod(fd, 0600) < 0) {
        log_error("worker", "fchmod: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("worker", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_debug("worker", "Control socket listening on %s", path);
    return fd;
}

#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_status_socket(void) {
    const char *path = control_socket_path(true);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        log_error("worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("worker", "status socket: %s", strerror(errno));
        return -1;
    }

    unlink(path);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("worker", "bind status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (fchmod(fd, 0666) < 0) {
        log_error("worker", "fchmod status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("worker", "listen status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_debug("worker", "Status socket listening on %s", path);
    return fd;
}

/* Convert internal state to control protocol state */
static enum unit_state_response convert_state(enum unit_state state) {
    switch (state) {
    case STATE_INACTIVE:     return UNIT_STATE_INACTIVE;
    case STATE_ACTIVATING:   return UNIT_STATE_ACTIVATING;
    case STATE_ACTIVE:       return UNIT_STATE_ACTIVE;
    case STATE_DEACTIVATING: return UNIT_STATE_DEACTIVATING;
    case STATE_FAILED:       return UNIT_STATE_FAILED;
    default:                 return UNIT_STATE_UNKNOWN;
    }
}

static bool command_is_read_only(enum control_command cmd) {
    switch (cmd) {
    case CMD_STATUS:
    case CMD_IS_ACTIVE:
    case CMD_IS_ENABLED:
    case CMD_LIST_UNITS:
        return true;
    default:
        return false;
    }
}

/* Handle control command */
static void handle_control_command(int client_fd, bool read_only) {
    struct control_request req = {0};
    struct control_response resp = {0};

    if (recv_control_request(client_fd, &req) < 0) {
        close(client_fd);
        return;
    }

    if (read_only && !command_is_read_only(req.header.command)) {
        resp.header.length = sizeof(resp);
        resp.header.command = req.header.command;
        resp.code = RESP_PERMISSION_DENIED;
        snprintf(resp.message, sizeof(resp.message),
                 "Command %s requires privileged socket",
                 command_to_string(req.header.command));
        send_control_response(client_fd, &resp);
        close(client_fd);
        return;
    }

    fprintf(stderr, "slave: received command %s for unit %s\n",
            command_to_string(req.header.command), req.unit_name);

    /* Set default response */
    resp.header.length = sizeof(resp);
    resp.header.command = req.header.command;
    resp.code = RESP_SUCCESS;

    struct unit_file *unit = find_unit(req.unit_name);

    switch (req.header.command) {
    case CMD_START:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (unit->state == STATE_ACTIVE) {
            resp.code = RESP_UNIT_ALREADY_ACTIVE;
            snprintf(resp.message, sizeof(resp.message), "Unit %s is already active", req.unit_name);
        } else {
            if (start_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to start %s", req.unit_name);
            } else {
                snprintf(resp.message, sizeof(resp.message), "Started %s", req.unit_name);
            }
        }
        break;

    case CMD_STATUS:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else {
            resp.state = convert_state(unit->state);
            resp.pid = unit->pid;
            snprintf(resp.message, sizeof(resp.message), "%s - %s",
                     req.unit_name, state_to_string(resp.state));
        }
        break;

    case CMD_IS_ACTIVE:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            resp.state = UNIT_STATE_UNKNOWN;
        } else {
            resp.state = convert_state(unit->state);
            resp.code = (unit->state == STATE_ACTIVE) ? RESP_SUCCESS : RESP_UNIT_INACTIVE;
        }
        break;

    case CMD_STOP:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (unit->state != STATE_ACTIVE) {
            resp.code = RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "Unit %s is not active", req.unit_name);
        } else {
            if (stop_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to stop %s", req.unit_name);
            } else {
                snprintf(resp.message, sizeof(resp.message), "Stopped %s", req.unit_name);
            }
        }
        break;

    case CMD_ENABLE:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (enable_unit(unit) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to enable %s", req.unit_name);
        } else {
            snprintf(resp.message, sizeof(resp.message), "Enabled %s", req.unit_name);
        }
        break;

    case CMD_DISABLE:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (disable_unit(unit) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to disable %s", req.unit_name);
        } else {
            snprintf(resp.message, sizeof(resp.message), "Disabled %s", req.unit_name);
        }
        break;

    case CMD_SOCKET_ADOPT:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (unit->type != UNIT_SERVICE) {
            resp.code = RESP_INVALID_COMMAND;
            snprintf(resp.message, sizeof(resp.message), "%s is not a service", req.unit_name);
        } else {
            if (req.aux_pid > 0) {
                unit->pid = (pid_t)req.aux_pid;
                unit->state = STATE_ACTIVE;
                unit->last_start = time(NULL);
                snprintf(resp.message, sizeof(resp.message), "Adopted %s (pid %d)",
                         req.unit_name, unit->pid);
            } else {
                unit->pid = 0;
                unit->state = STATE_INACTIVE;
                snprintf(resp.message, sizeof(resp.message), "Marked %s inactive", req.unit_name);
            }
        }
        break;

    case CMD_IS_ENABLED:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else {
            bool enabled = is_unit_enabled(unit);
            resp.code = enabled ? RESP_SUCCESS : RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "%s", enabled ? "enabled" : "disabled");
        }
        break;

    case CMD_RELOAD:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (unit->type != UNIT_SERVICE) {
            resp.code = RESP_INVALID_COMMAND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s is not a service", req.unit_name);
        } else if (!unit->config.service.exec_reload ||
                   unit->config.service.exec_reload[0] == '\0') {
            resp.code = RESP_INVALID_COMMAND;
            snprintf(resp.message, sizeof(resp.message),
                     "Unit %s does not support reload", req.unit_name);
        } else if (unit->state != STATE_ACTIVE || unit->pid <= 0) {
            resp.code = RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "Unit %s is not active", req.unit_name);
        } else if (reload_service(unit) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to reload %s: %s",
                     req.unit_name, strerror(errno));
        } else {
            snprintf(resp.message, sizeof(resp.message), "Reloaded %s", req.unit_name);
        }
        break;

    case CMD_LIST_UNITS: {
        /* Scan units based on --all flag */
        int include_systemd = (req.header.flags & REQ_FLAG_ALL) ? 1 : 0;
        struct unit_file **scanned_units = NULL;
        int scanned_count = 0;

        if (scan_unit_directories_filtered(&scanned_units, &scanned_count, include_systemd) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to scan units");
            send_control_response(client_fd, &resp);
            close(client_fd);
            return;
        }

        /* Build list of unit entries */
        struct unit_list_entry *entries = calloc(scanned_count, sizeof(struct unit_list_entry));
        if (!entries) {
            free_units(scanned_units, scanned_count);
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Out of memory");
            send_control_response(client_fd, &resp);
            close(client_fd);
            return;
        }

        for (int i = 0; i < scanned_count; i++) {
            struct unit_file *u = scanned_units[i];
            strncpy(entries[i].name, u->name, sizeof(entries[i].name) - 1);
            entries[i].state = convert_state(u->state);
            entries[i].pid = u->pid;
            strncpy(entries[i].description, u->unit.description, sizeof(entries[i].description) - 1);
        }

        size_t total_count = (size_t)scanned_count;

        /* Attempt to append active sockets from socket activator */
        int sock_fd = connect_to_socket_activator();
        if (sock_fd >= 0) {
            struct control_request sock_req = {0};
            struct control_response sock_resp = {0};
            sock_req.header.length = sizeof(sock_req);
            sock_req.header.command = CMD_LIST_SOCKETS;

            if (send_control_request(sock_fd, &sock_req) == 0 &&
                recv_control_response(sock_fd, &sock_resp) == 0 &&
                sock_resp.code == RESP_SUCCESS) {
                struct socket_list_entry *socket_entries = NULL;
                size_t socket_count = 0;

                if (recv_socket_list(sock_fd, &socket_entries, &socket_count) == 0 && socket_count > 0) {
                    struct unit_list_entry *tmp =
                        realloc(entries, (total_count + socket_count) * sizeof(struct unit_list_entry));
                    if (tmp) {
                        entries = tmp;
                        for (size_t i = 0; i < socket_count; i++) {
                            struct socket_list_entry *se = &socket_entries[i];
                            struct unit_list_entry *dst = &entries[total_count + i];
                            memset(dst, 0, sizeof(*dst));
                            strncpy(dst->name, se->name, sizeof(dst->name) - 1);
                            dst->state = se->state;
                            dst->pid = se->service_pid;
                            if (se->description[0] != '\0') {
                                strncpy(dst->description, se->description, sizeof(dst->description) - 1);
                            } else {
                                const char *detail = se->listen[0] ? se->listen : se->unit;
                                strncpy(dst->description, "[socket] ", sizeof(dst->description) - 1);
                                strncat(dst->description, detail,
                                        sizeof(dst->description) - strlen(dst->description) - 1);
                            }
                        }
                        total_count += socket_count;
                    }

                    free(socket_entries);
                }
            }

            close(sock_fd);
        }

        /* Send success response first */
        resp.code = RESP_SUCCESS;
        snprintf(resp.message, sizeof(resp.message), "Listing %zu units", total_count);
        send_control_response(client_fd, &resp);

        /* Then send unit list */
        send_unit_list(client_fd, entries, total_count);

        free(entries);
        free_units(scanned_units, scanned_count);
        close(client_fd);
        return;
    }

    case CMD_RESTART:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else {
            if (stop_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to stop %s", req.unit_name);
            } else if (start_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to restart %s", req.unit_name);
            } else {
                resp.code = RESP_SUCCESS;
                snprintf(resp.message, sizeof(resp.message), "Restarted %s", req.unit_name);
            }
        }
        break;

    case CMD_LIST_TIMERS:
        resp.code = RESP_FAILURE;
        snprintf(resp.message, sizeof(resp.message),
                 "Supervisor does not manage timers; use timer daemon list-timers");
        break;

    case CMD_DAEMON_RELOAD: {
        struct unit_file **old_units = units;
        int old_count = unit_count;
        struct unit_file **new_units = NULL;
        int new_count = 0;

        if (scan_unit_directories(&new_units, &new_count) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to reload unit files");
            break;
        }

        for (int i = 0; i < new_count; i++) {
            struct unit_file *new_unit = new_units[i];
            for (int j = 0; j < old_count; j++) {
                struct unit_file *old_unit = old_units[j];
                if (strcmp(new_unit->name, old_unit->name) == 0) {
                    new_unit->state = old_unit->state;
                    new_unit->pid = old_unit->pid;
                    new_unit->restart_count = old_unit->restart_count;
                    new_unit->last_start = old_unit->last_start;
                    new_unit->start_traversal_id = old_unit->start_traversal_id;
                    new_unit->stop_traversal_id = old_unit->stop_traversal_id;
                    new_unit->start_visit_state = old_unit->start_visit_state;
                    new_unit->stop_visit_state = old_unit->stop_visit_state;
                    break;
                }
            }
        }

        units = new_units;
        unit_count = new_count;
        start_traversal_generation = 0;
        stop_traversal_generation = 0;
        isolate_generation = 0;
        if (old_units) {
            free_units(old_units, old_count);
        }

        resp.code = RESP_SUCCESS;
        snprintf(resp.message, sizeof(resp.message), "Supervisor configuration reloaded (%d units)", unit_count);
        break;
    }

    case CMD_ISOLATE:
        if (!unit) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s not found", req.unit_name);
        } else if (unit->type != UNIT_TARGET) {
            resp.code = RESP_INVALID_COMMAND;
            snprintf(resp.message, sizeof(resp.message), "%s is not a target", req.unit_name);
        } else {
            unsigned int generation = next_isolate_generation();
            mark_isolate_closure(unit, generation);

            bool stop_failed = false;
            for (int i = 0; i < unit_count; i++) {
                struct unit_file *other = units[i];
                if (other->isolate_mark_generation == generation) {
                    continue;
                }
                if (other->state == STATE_ACTIVE || other->state == STATE_ACTIVATING) {
                    if (stop_unit_recursive(other) < 0) {
                        stop_failed = true;
                    }
                }
            }

            if (stop_failed) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to stop non-target units");
            } else if (start_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to activate %s", req.unit_name);
            } else {
                resp.code = RESP_SUCCESS;
                snprintf(resp.message, sizeof(resp.message), "Isolated %s", req.unit_name);
            }
        }
        break;

    case CMD_POWEROFF:
    case CMD_REBOOT:
    case CMD_HALT: {
        struct priv_request shutdown_req = {0};
        struct priv_response shutdown_resp = {0};

        /* Map control command to IPC request type */
        if (req.header.command == CMD_POWEROFF) {
            shutdown_req.type = REQ_POWEROFF;
        } else if (req.header.command == CMD_REBOOT) {
            shutdown_req.type = REQ_REBOOT;
        } else {
            shutdown_req.type = REQ_HALT;
        }

        /* Send shutdown request to master */
        if (send_request(master_socket, &shutdown_req) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to send shutdown request to master");
        } else if (recv_response(master_socket, &shutdown_resp) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to receive response from master");
        } else if (shutdown_resp.type == RESP_OK) {
            resp.code = RESP_SUCCESS;
            const char *action = (req.header.command == CMD_POWEROFF) ? "poweroff" :
                                 (req.header.command == CMD_REBOOT) ? "reboot" : "halt";
            snprintf(resp.message, sizeof(resp.message), "System %s initiated", action);
        } else {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "%s", shutdown_resp.error_msg);
        }
        break;
    }

    default:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message), "Unknown command");
        break;
    }

    send_control_response(client_fd, &resp);
    close(client_fd);
}

/* Stop a unit (recursive, reverse dependency order, with depth limit) */
static int stop_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation) {
    if (!unit) {
        return -1;
    }

    if (depth > MAX_RECURSION_DEPTH) {
        fprintf(stderr, "slave: maximum recursion depth exceeded stopping %s\n", unit->name);
        log_msg(LOG_ERR, unit->name, "maximum recursion depth exceeded (possible circular dependency)");
        return -1;
    }

    if (unit->stop_traversal_id != generation) {
        unit->stop_traversal_id = generation;
        unit->stop_visit_state = DEP_VISIT_NONE;
    }

    if (unit->stop_visit_state == DEP_VISIT_DONE) {
        return 0;
    }

    if (unit->stop_visit_state == DEP_VISIT_IN_PROGRESS) {
        fprintf(stderr, "slave: circular dependency detected stopping %s\n", unit->name);
        log_msg(LOG_ERR, unit->name, "circular dependency detected during shutdown");
        return 0;
    }

    if (unit->state == STATE_INACTIVE) {
        unit->stop_visit_state = DEP_VISIT_DONE;
        return 0;
    }

    unit->stop_visit_state = DEP_VISIT_IN_PROGRESS;

    /* Mark as deactivating to detect cycles */
    unit->state = STATE_DEACTIVATING;
    fprintf(stderr, "slave: stopping %s\n", unit->name);

    for (int i = 0; i < unit_count; i++) {
        struct unit_file *other = units[i];
        if (other == unit || (other->state != STATE_ACTIVE && other->state != STATE_DEACTIVATING)) {
            continue;
        }

        bool depends_on_us = false;
        for (int j = 0; j < other->unit.requires_count; j++) {
            if (strcmp(other->unit.requires[j], unit->name) == 0) {
                depends_on_us = true;
                break;
            }
        }
        if (!depends_on_us) {
            for (int j = 0; j < other->unit.wants_count; j++) {
                if (strcmp(other->unit.wants[j], unit->name) == 0) {
                    depends_on_us = true;
                    break;
                }
            }
        }

        if (depends_on_us) {
            stop_unit_recursive_depth(other, depth + 1, generation);
        }
    }

    if (unit->type == UNIT_SERVICE) {
        stop_service(unit);
    } else if (unit->type == UNIT_TARGET) {
        unit->state = STATE_INACTIVE;
        log_msg(LOG_INFO, unit->name, "target deactivated");
    }

    unit->stop_visit_state = DEP_VISIT_DONE;
    return 0;
}

/* Public wrapper without depth parameter */
static int stop_unit_recursive(struct unit_file *unit) {
    unsigned int generation = next_stop_generation();
    return stop_unit_recursive_depth(unit, 0, generation);
}

static void mark_isolate_closure(struct unit_file *unit, unsigned int generation) {
    if (!unit) {
        return;
    }

    if (unit->isolate_mark_generation == generation) {
        return;
    }

    unit->isolate_mark_generation = generation;
    unit->isolate_needed = true;

    for (int i = 0; i < unit->unit.requires_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.requires[i]);
        mark_isolate_closure(dep, generation);
    }

    for (int i = 0; i < unit->unit.wants_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.wants[i]);
        mark_isolate_closure(dep, generation);
    }

    for (int i = 0; i < unit->unit.after_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.after[i]);
        mark_isolate_closure(dep, generation);
    }
}

/* Start a unit and its dependencies (recursive with depth limit) */
static int start_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation) {
    if (!unit) {
        return -1;
    }

    if (depth > MAX_RECURSION_DEPTH) {
        fprintf(stderr, "slave: maximum recursion depth exceeded starting %s\n", unit->name);
        log_msg(LOG_ERR, unit->name, "maximum recursion depth exceeded (possible circular dependency)");
        return -1;
    }

    if (unit->start_traversal_id != generation) {
        unit->start_traversal_id = generation;
        unit->start_visit_state = DEP_VISIT_NONE;
    }

    if (unit->start_visit_state == DEP_VISIT_DONE) {
        return 0;
    }

    if (unit->start_visit_state == DEP_VISIT_IN_PROGRESS) {
        fprintf(stderr, "slave: circular dependency detected starting %s\n", unit->name);
        log_msg(LOG_ERR, unit->name, "circular dependency detected");
        unit->state = STATE_FAILED;
        return -1;
    }

    if (unit->state == STATE_ACTIVE) {
        unit->start_visit_state = DEP_VISIT_DONE;
        return 0;
    }

    unit->start_visit_state = DEP_VISIT_IN_PROGRESS;

    unit->state = STATE_ACTIVATING;
    fprintf(stderr, "slave: starting %s\n", unit->name);

    for (int i = 0; i < unit->unit.requires_count; i++) {
        struct unit_file *dep = find_unit(unit->unit.requires[i]);
        if (dep && start_unit_recursive_depth(dep, depth + 1, generation) < 0) {
            fprintf(stderr, "slave: failed to start required dependency %s\n", unit->unit.requires[i]);
            log_msg(LOG_ERR, unit->name, "failed to start required dependency %s", unit->unit.requires[i]);
            unit->state = STATE_FAILED;
            unit->start_visit_state = DEP_VISIT_NONE;
            return -1;
        }
    }

    for (int i = 0; i < unit->unit.wants_count; i++) {
        struct unit_file *dep = find_unit(unit->unit.wants[i]);
        if (dep) {
            start_unit_recursive_depth(dep, depth + 1, generation);
        }
    }

    for (int i = 0; i < unit->unit.after_count; i++) {
        struct unit_file *dep = find_unit(unit->unit.after[i]);
        if (dep && dep->state != STATE_ACTIVE && dep->state != STATE_FAILED) {
            if (dep->state == STATE_INACTIVE) {
                if (start_unit_recursive_depth(dep, depth + 1, generation) < 0) {
                    fprintf(stderr, "slave: After= dependency %s failed\n", unit->unit.after[i]);
                    log_msg(LOG_WARNING, unit->name, "After= dependency %s failed", unit->unit.after[i]);
                }
            }
        }
    }

    if (unit->type == UNIT_SERVICE) {
        if (start_service(unit) < 0) {
            fprintf(stderr, "slave: failed to start %s\n", unit->name);
            log_msg(LOG_ERR, unit->name, "failed to start service");
            unit->state = STATE_FAILED;
            unit->start_visit_state = DEP_VISIT_NONE;
            return -1;
        }
    } else if (unit->type == UNIT_TARGET) {
        unit->state = STATE_ACTIVE;
        log_msg(LOG_INFO, unit->name, "target activated");
    }

    unit->start_visit_state = DEP_VISIT_DONE;
    return 0;
}

#ifdef UNIT_TEST
void supervisor_test_set_unit_context(struct unit_file **list, int count) {
    units = list;
    unit_count = count;
}

void supervisor_test_reset_generations(void) {
    start_traversal_generation = 0;
    stop_traversal_generation = 0;
    isolate_generation = 0;
    reset_start_traversal_marks();
    reset_stop_traversal_marks();
    reset_isolate_marks();
}

void supervisor_test_mark_isolate(struct unit_file *target) {
    unsigned int generation = next_isolate_generation();
    mark_isolate_closure(target, generation);
}

void supervisor_test_handle_control_fd(int fd) {
    handle_control_command(fd, false);
}

void supervisor_test_handle_status_fd(int fd) {
    handle_control_command(fd, true);
}
#endif

/* Public wrapper without depth parameter */
static int start_unit_recursive(struct unit_file *unit) {
    unsigned int generation = next_start_generation();
    return start_unit_recursive_depth(unit, 0, generation);
}

/* Main loop: manage services */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int main_loop(void) {
    log_debug("worker", "Entering main loop");

    /* Defensive check: ensure sockets are valid */
    if (control_socket < 0 || master_socket < 0) {
        log_error("worker", "invalid socket in main_loop");
        return -1;
    }

    struct pollfd fds[3];
    nfds_t nfds = 0;
    int idx_control = nfds;
    fds[nfds].fd = control_socket;
    fds[nfds].events = POLLIN;
    nfds++;

    int idx_status = -1;
    if (status_socket >= 0) {
        idx_status = nfds;
        fds[nfds].fd = status_socket;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    int idx_master = nfds;
    fds[nfds].fd = master_socket;
    fds[nfds].events = POLLIN;
    nfds++;

    while (!shutdown_requested) {
        /* Poll both control socket and master socket */
        int ret = poll(fds, nfds, 1000); /* 1 second timeout */

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("worker", "poll: %s", strerror(errno));
            break;
        }

        if (ret > 0) {
            /* Check for initctl control requests */
            if (fds[idx_control].revents & POLLIN) {
                int client_fd = accept(control_socket, NULL, NULL);
                if (client_fd >= 0) {
                    if (!is_control_client_authorized(client_fd)) {
                        close(client_fd);
                    } else {
                        handle_control_command(client_fd, false);
                    }
                }
            }

            if (idx_status >= 0 && (fds[idx_status].revents & POLLIN)) {
                int client_fd = accept(status_socket, NULL, NULL);
                if (client_fd >= 0) {
                    handle_control_command(client_fd, true);
                }
            }

            /* Check for notifications from master */
            if (fds[idx_master].revents & POLLIN) {
                struct priv_response notif = {0};
                if (recv_response(master_socket, &notif) == 0) {
                    if (notif.type == RESP_SERVICE_EXITED) {
                        handle_service_exit(notif.service_pid, notif.exit_status);
                    }
                } else {
                    log_warn("worker", "Master socket closed");
                    break;
                }
            }
        }

        /* Timer expirations are handled by independent timer-daemon */
    }

    /* Shutdown sequence */
    log_info("worker", "Shutting down services");

    /* Stop all active services in reverse dependency order */
    /* We iterate through all units and stop them; the recursive function
     * will handle dependency ordering */
    for (int i = 0; i < unit_count; i++) {
        if (units[i]->state == STATE_ACTIVE) {
            stop_unit_recursive(units[i]);
        }
    }

    log_info("worker", "All services stopped");

    /* Notify master we're done */
    notify_shutdown_complete();

    return 0;
}

#ifndef UNIT_TEST
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "supervisor-slave: usage: %s <ipc_fd>\n", argv[0]);
        return 1;
    }

    /* Get IPC socket FD from command line */
    master_socket = atoi(argv[1]);

    /* Initialize logging */
    log_init("supervisor-slave");
    log_enhanced_init("worker", "/var/log/initd/supervisor.log");
    log_set_console_level(LOGLEVEL_INFO);
    log_set_file_level(LOGLEVEL_DEBUG);

    log_info("worker", "Starting (ipc_fd=%d)", master_socket);

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    control_socket = create_control_socket();
    if (control_socket < 0) {
        log_error("worker", "failed to create control socket");
        return 1;
    }

    status_socket = create_status_socket();
    if (status_socket < 0) {
        log_error("worker", "failed to create status socket");
        close(control_socket);
        const char *ctrl_path = control_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        return 1;
    }

    /* Scan unit directories */
    log_debug("worker", "Scanning unit directories");
    if (scan_unit_directories(&units, &unit_count) < 0) {
        log_error("worker", "failed to scan unit directories");
        close(control_socket);
        const char *ctrl_path = control_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        if (status_socket >= 0) {
            close(status_socket);
            const char *status_path = control_socket_path(true);
            if (status_path) {
                unlink(status_path);
            }
        }
        return 1;
    }

    /* Start default.target */
    log_info("worker", "Starting default.target");
    struct unit_file *default_target = find_unit("default.target");
    if (!default_target) {
        /* Fallback to multi-user.target */
        default_target = find_unit("multi-user.target");
    }

    if (default_target) {
        if (start_unit_recursive(default_target) < 0) {
            log_error("worker", "failed to start default target");
        }
    } else {
        log_warn("worker", "no default target found");
    }

    /* Main loop */
    main_loop();

    /* Cleanup */
    free_units(units, unit_count);

    if (control_socket >= 0) {
        const char *path = control_socket_path(false);
        close(control_socket);
        if (path) {
            unlink(path);
        }
    }
    if (status_socket >= 0) {
        const char *path = control_socket_path(true);
        close(status_socket);
        if (path) {
            unlink(path);
        }
    }

    log_msg(LOG_INFO, NULL, "exiting");
    log_close();
    return 0;
}
#endif
