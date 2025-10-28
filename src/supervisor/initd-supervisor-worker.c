/* supervisor-worker.c - Unprivileged supervisor process
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
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <glob.h>
#include <dirent.h>
#include <libgen.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/ucred.h>
#include <sys/sysctl.h>
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
static bool debug_mode = false;
static bool stop_when_unneeded_guard = false;

/* Forward declarations */
static bool unit_provides(struct unit_file *unit, const char *service_name);
static int stop_unit_recursive(struct unit_file *unit);
static int start_unit_recursive(struct unit_file *unit);
static int stop_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation);
static int start_unit_recursive_depth(struct unit_file *unit, int depth, unsigned int generation);
static void mark_isolate_closure(struct unit_file *unit, unsigned int generation);
static void trigger_on_failure(struct unit_file *unit);
static bool unit_conditions_met(struct unit_file *unit);
static bool unit_has_active_dependents(struct unit_file *unit);
static void enforce_stop_when_unneeded(void);
static void stop_bound_dependents(struct unit_file *unit, const char *reason);
static bool dependency_matches(struct unit_file *candidate, const char *name);

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

    /* fprintf(stderr, "worker: stopping %s (pid %d)\n", unit->name, unit->pid); */

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
        /* fprintf(stderr, "worker: %s stop timeout, sending SIGKILL\n", unit->name); */
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
            log_error("worker", "Failed to lookup user %s", unit->config.service.user);
            return -1;
        }

        /* Copy service configuration for environment setup */
        req.private_tmp = unit->config.service.private_tmp;
        req.limit_nofile = unit->config.service.limit_nofile;
        req.limit_cpu = unit->config.service.limit_cpu;
        req.limit_fsize = unit->config.service.limit_fsize;
        req.limit_data = unit->config.service.limit_data;
        req.limit_stack = unit->config.service.limit_stack;
        req.limit_core = unit->config.service.limit_core;
        req.limit_rss = unit->config.service.limit_rss;
        req.limit_as = unit->config.service.limit_as;
        req.limit_nproc = unit->config.service.limit_nproc;
        req.limit_memlock = unit->config.service.limit_memlock;
        req.limit_locks = unit->config.service.limit_locks;
        req.limit_sigpending = unit->config.service.limit_sigpending;
        req.limit_msgqueue = unit->config.service.limit_msgqueue;
        req.limit_nice = unit->config.service.limit_nice;
        req.limit_rtprio = unit->config.service.limit_rtprio;
        req.limit_rttime = unit->config.service.limit_rttime;
        req.kill_mode = unit->config.service.kill_mode;
        req.standard_input = unit->config.service.standard_input;
        req.standard_output = unit->config.service.standard_output;
        req.standard_error = unit->config.service.standard_error;
        strncpy(req.tty_path, unit->config.service.tty_path, sizeof(req.tty_path) - 1);
        req.tty_path[sizeof(req.tty_path) - 1] = '\0';

        /* Copy file paths for StandardInput/Output/Error=file:path */
        strncpy(req.input_file, unit->config.service.input_file, sizeof(req.input_file) - 1);
        req.input_file[sizeof(req.input_file) - 1] = '\0';
        strncpy(req.output_file, unit->config.service.output_file, sizeof(req.output_file) - 1);
        req.output_file[sizeof(req.output_file) - 1] = '\0';
        strncpy(req.error_file, unit->config.service.error_file, sizeof(req.error_file) - 1);
        req.error_file[sizeof(req.error_file) - 1] = '\0';

        /* Copy input data for StandardInput=data */
        req.input_data = unit->config.service.input_data;
        req.input_data_size = unit->config.service.input_data_size;

        /* Copy syslog configuration */
        strncpy(req.syslog_identifier, unit->config.service.syslog_identifier, sizeof(req.syslog_identifier) - 1);
        req.syslog_identifier[sizeof(req.syslog_identifier) - 1] = '\0';
        req.syslog_facility = unit->config.service.syslog_facility;
        req.syslog_level = unit->config.service.syslog_level;
        req.syslog_level_prefix = unit->config.service.syslog_level_prefix;

        /* Copy umask */
        req.umask_value = unit->config.service.umask_value;

        /* Copy NoNewPrivileges */
        req.no_new_privs = unit->config.service.no_new_privs;

        /* Copy RootDirectory */
        strncpy(req.root_directory, unit->config.service.root_directory, sizeof(req.root_directory) - 1);
        req.root_directory[sizeof(req.root_directory) - 1] = '\0';

        int interval = unit->unit.start_limit_interval_set ?
            unit->unit.start_limit_interval_sec : INITD_DEFAULT_START_LIMIT_INTERVAL_SEC;
        if (interval < INITD_DEFAULT_START_LIMIT_INTERVAL_SEC) {
            interval = INITD_DEFAULT_START_LIMIT_INTERVAL_SEC;
        }
        req.start_limit_interval_sec = interval;

        int burst = unit->unit.start_limit_burst_set ?
            unit->unit.start_limit_burst : INITD_DEFAULT_START_LIMIT_BURST;
        if (burst < INITD_DEFAULT_START_LIMIT_BURST) {
            burst = INITD_DEFAULT_START_LIMIT_BURST;
        }
        if (burst > INITD_MAX_START_LIMIT_BURST_TRACK) {
            burst = INITD_MAX_START_LIMIT_BURST_TRACK;
        }
        req.start_limit_burst = burst;

        req.start_limit_action = unit->unit.start_limit_action_set ?
            unit->unit.start_limit_action : START_LIMIT_ACTION_NONE;

        req.restart_prevent_count = unit->config.service.restart_prevent_count;
        if (req.restart_prevent_count > MAX_RESTART_STATUS) {
            req.restart_prevent_count = MAX_RESTART_STATUS;
        }
        req.restart_force_count = unit->config.service.restart_force_count;
        if (req.restart_force_count > MAX_RESTART_STATUS) {
            req.restart_force_count = MAX_RESTART_STATUS;
        }
        for (int i = 0; i < req.restart_prevent_count; i++) {
            req.restart_prevent_statuses[i] = unit->config.service.restart_prevent_statuses[i];
        }
        for (int i = 0; i < req.restart_force_count; i++) {
            req.restart_force_statuses[i] = unit->config.service.restart_force_statuses[i];
        }
    }

    /* Send request to master */
    if (send_request(master_socket, &req) < 0) {
        log_error("worker", "send_request failed starting %s: %s",
                  unit->name, strerror(errno));
        return -1;
    }

    /* Receive response */
    if (recv_response(master_socket, &resp) < 0) {
        log_error("worker", "recv_response failed starting %s: %s",
                  unit->name, strerror(errno));
        return -1;
    }

    if (debug_mode) {
        log_debug("worker", "start_service response type=%d pid=%d",
                  resp.type, resp.service_pid);
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

    if (send_request(master_socket, &req) < 0) {
        log_error("worker", "failed to notify shutdown completion: %s",
                  strerror(errno));
        return -1;
    }
    if (recv_response(master_socket, &resp) < 0) {
        log_error("worker", "failed to receive shutdown ack: %s",
                  strerror(errno));
        return -1;
    }

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

static const char *condition_type_name(enum unit_condition_type type, bool is_assert) {
    const char *prefix = is_assert ? "Assert" : "Condition";

    switch (type) {
    case CONDITION_PATH_EXISTS:
        return is_assert ? "AssertPathExists" : "ConditionPathExists";
    case CONDITION_PATH_EXISTS_GLOB:
        return is_assert ? "AssertPathExistsGlob" : "ConditionPathExistsGlob";
    case CONDITION_PATH_IS_DIRECTORY:
        return is_assert ? "AssertPathIsDirectory" : "ConditionPathIsDirectory";
    case CONDITION_PATH_IS_SYMBOLIC_LINK:
        return is_assert ? "AssertPathIsSymbolicLink" : "ConditionPathIsSymbolicLink";
    case CONDITION_PATH_IS_MOUNT_POINT:
        return is_assert ? "AssertPathIsMountPoint" : "ConditionPathIsMountPoint";
    case CONDITION_PATH_IS_READ_WRITE:
        return is_assert ? "AssertPathIsReadWrite" : "ConditionPathIsReadWrite";
    case CONDITION_DIRECTORY_NOT_EMPTY:
        return is_assert ? "AssertDirectoryNotEmpty" : "ConditionDirectoryNotEmpty";
    case CONDITION_FILE_IS_EXECUTABLE:
        return is_assert ? "AssertFileIsExecutable" : "ConditionFileIsExecutable";
    case CONDITION_FILE_NOT_EMPTY:
        return is_assert ? "AssertFileNotEmpty" : "ConditionFileNotEmpty";
    case CONDITION_USER:
        return is_assert ? "AssertUser" : "ConditionUser";
    case CONDITION_GROUP:
        return is_assert ? "AssertGroup" : "ConditionGroup";
    case CONDITION_HOST:
        return is_assert ? "AssertHost" : "ConditionHost";
    case CONDITION_ARCHITECTURE:
        return is_assert ? "AssertArchitecture" : "ConditionArchitecture";
    case CONDITION_MEMORY:
        return is_assert ? "AssertMemory" : "ConditionMemory";
    case CONDITION_CPUS:
        return is_assert ? "AssertCPUs" : "ConditionCPUs";
    case CONDITION_ENVIRONMENT:
        return is_assert ? "AssertEnvironment" : "ConditionEnvironment";
    case CONDITION_VIRTUALIZATION:
        return is_assert ? "AssertVirtualization" : "ConditionVirtualization";
    case CONDITION_AC_POWER:
        return is_assert ? "AssertACPower" : "ConditionACPower";
    case CONDITION_OS_RELEASE:
        return is_assert ? "AssertOSRelease" : "ConditionOSRelease";
    case CONDITION_KERNEL_VERSION:
        return is_assert ? "AssertKernelVersion" : "ConditionKernelVersion";
    default:
        return prefix;
    }
}

static bool condition_path_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static bool condition_path_exists_glob(const char *pattern) {
    glob_t gl;
    memset(&gl, 0, sizeof(gl));
    int ret = glob(pattern, GLOB_NOSORT, NULL, &gl);
    if (ret != 0) {
        return false;
    }
    bool match = (gl.gl_pathc > 0);
    globfree(&gl);
    return match;
}

static bool condition_path_is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool condition_path_is_symlink(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
}

static bool condition_path_is_mount_point(const char *path) {
    struct stat st_path;
    char resolved[PATH_MAX];

    if (!realpath(path, resolved)) {
        return false;
    }

    if (stat(resolved, &st_path) < 0) {
        return false;
    }

    if (strcmp(resolved, "/") == 0) {
        return true;
    }

    char parent_buf[PATH_MAX];
    strncpy(parent_buf, resolved, sizeof(parent_buf));
    parent_buf[sizeof(parent_buf) - 1] = '\0';
    char *parent = dirname(parent_buf);
    if (!parent || parent[0] == '\0') {
        return false;
    }

    struct stat st_parent;
    if (stat(parent, &st_parent) < 0) {
        return false;
    }

    if (st_path.st_dev != st_parent.st_dev) {
        return true;
    }

    if (st_path.st_dev == st_parent.st_dev && st_path.st_ino == st_parent.st_ino) {
        return true;
    }

    return false;
}

static bool condition_path_is_read_write(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }
    int mode = R_OK | W_OK;
    if (S_ISDIR(st.st_mode)) {
        mode |= X_OK;
    }
    return access(path, mode) == 0;
}

static bool condition_directory_not_empty(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        return false;
    }

    struct dirent *entry;
    bool not_empty = false;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        not_empty = true;
        break;
    }

    closedir(dir);
    return not_empty;
}

static bool condition_file_is_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }
    return access(path, X_OK) == 0;
}

static bool condition_file_not_empty(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }
    return st.st_size > 0;
}

static bool condition_user(const char *value) {
    /* Format: "user" or "uid" or "@system" (runs as superuser) */
    uid_t current_uid = getuid();

    /* Special case: @system means running as superuser */
    if (strcmp(value, "@system") == 0) {
        return current_uid == 0;
    }

    /* Try to parse as numeric UID */
    char *endptr;
    long uid_long = strtol(value, &endptr, 10);
    if (*endptr == '\0' && uid_long >= 0) {
        return current_uid == (uid_t)uid_long;
    }

    /* Try to look up username */
    struct passwd *pwd = getpwnam(value);
    if (pwd) {
        return current_uid == pwd->pw_uid;
    }

    return false;
}

static bool condition_group(const char *value) {
    gid_t current_gid = getgid();

    /* Try to parse as numeric GID */
    char *endptr;
    long gid_long = strtol(value, &endptr, 10);
    if (*endptr == '\0' && gid_long >= 0) {
        return current_gid == (gid_t)gid_long;
    }

    /* Try to look up group name */
    struct group *grp = getgrnam(value);
    if (grp) {
        return current_gid == grp->gr_gid;
    }

    return false;
}

static bool condition_host(const char *value) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) < 0) {
        return false;
    }
    hostname[sizeof(hostname) - 1] = '\0';
    return strcmp(hostname, value) == 0;
}

static bool condition_architecture(const char *value) {
    struct utsname uts;
    if (uname(&uts) < 0) {
        return false;
    }

    /* Map systemd architecture names to uname machine types */
    const char *arch = uts.machine;

    /* Direct match */
    if (strcmp(value, arch) == 0) {
        return true;
    }

    /* Common systemd architecture names */
    if (strcmp(value, "x86-64") == 0 && (strcmp(arch, "x86_64") == 0 || strcmp(arch, "amd64") == 0)) {
        return true;
    }
    if (strcmp(value, "x86") == 0 && (strcmp(arch, "i386") == 0 || strcmp(arch, "i686") == 0)) {
        return true;
    }
    if (strcmp(value, "arm64") == 0 && strcmp(arch, "aarch64") == 0) {
        return true;
    }
    if (strcmp(value, "arm") == 0 && (strncmp(arch, "arm", 3) == 0 || strcmp(arch, "armv7l") == 0)) {
        return true;
    }

    return false;
}

static bool condition_memory(const char *value) {
    /* Parse memory requirement (supports suffixes: K, M, G) */
    char *endptr;
    long long required_bytes = strtoll(value, &endptr, 10);

    if (endptr == value) {
        return false;  /* No digits parsed */
    }

    /* Handle size suffixes */
    if (*endptr != '\0') {
        if (*endptr == 'K' || *endptr == 'k') {
            required_bytes *= 1024;
        } else if (*endptr == 'M' || *endptr == 'm') {
            required_bytes *= 1024 * 1024;
        } else if (*endptr == 'G' || *endptr == 'g') {
            required_bytes *= 1024 * 1024 * 1024;
        } else {
            return false;  /* Invalid suffix */
        }
    }

    /* Get system memory using POSIX sysconf */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);

    if (pages < 0 || page_size < 0) {
        return false;
    }

    long long total_memory = (long long)pages * page_size;
    return total_memory >= required_bytes;
}

static bool condition_cpus(const char *value) {
    /* Parse CPU requirement (number or range like ">=4") */
    int required_cpus;
    char op[3] = {0};

    /* Try to parse comparison operator */
    if (sscanf(value, "%2[<>=]%d", op, &required_cpus) == 2) {
        /* Has operator */
    } else if (sscanf(value, "%d", &required_cpus) == 1) {
        /* No operator, default to exact match */
        strcpy(op, "=");
    } else {
        return false;
    }

    /* Get CPU count */
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count < 0) {
        return false;
    }

    /* Compare */
    if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
        return cpu_count == required_cpus;
    } else if (strcmp(op, ">=") == 0) {
        return cpu_count >= required_cpus;
    } else if (strcmp(op, "<=") == 0) {
        return cpu_count <= required_cpus;
    } else if (strcmp(op, ">") == 0) {
        return cpu_count > required_cpus;
    } else if (strcmp(op, "<") == 0) {
        return cpu_count < required_cpus;
    }

    return false;
}

static bool condition_environment(const char *value) {
    /* Format: "VAR" (exists) or "VAR=value" (equals) */
    const char *equals = strchr(value, '=');

    if (equals) {
        /* Check for exact value */
        size_t name_len = equals - value;
        char name[256];
        if (name_len >= sizeof(name)) {
            return false;
        }
        strncpy(name, value, name_len);
        name[name_len] = '\0';

        const char *env_value = getenv(name);
        if (!env_value) {
            return false;
        }

        return strcmp(env_value, equals + 1) == 0;
    } else {
        /* Just check existence */
        return getenv(value) != NULL;
    }
}

static bool condition_virtualization(const char *value) {
    /* Detect virtualization/container type (platform-specific) */
    bool is_virtualized = false;
    char detected_type[64] = {0};

#ifdef __linux__
    /* Check for container indicators */
    if (access("/proc/vz", F_OK) == 0 && access("/proc/bc", F_OK) != 0) {
        is_virtualized = true;
        strncpy(detected_type, "openvz", sizeof(detected_type) - 1);
        if (strcmp(value, "openvz") == 0 || strcmp(value, "container") == 0) {
            return true;
        }
    }
    if (access("/.dockerenv", F_OK) == 0) {
        is_virtualized = true;
        strncpy(detected_type, "docker", sizeof(detected_type) - 1);
        if (strcmp(value, "docker") == 0 || strcmp(value, "container") == 0) {
            return true;
        }
    }
    if (access("/run/systemd/container", F_OK) == 0) {
        FILE *f = fopen("/run/systemd/container", "r");
        if (f) {
            char container[64];
            if (fgets(container, sizeof(container), f)) {
                container[strcspn(container, "\n")] = '\0';
                is_virtualized = true;
                strncpy(detected_type, container, sizeof(detected_type) - 1);
                fclose(f);
                if (strcmp(value, container) == 0 || strcmp(value, "container") == 0) {
                    return true;
                }
            } else {
                fclose(f);
            }
        }
    }

    /* Check for VM indicators via DMI/CPUID */
    FILE *f = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (f) {
        char vendor[128];
        if (fgets(vendor, sizeof(vendor), f)) {
            vendor[strcspn(vendor, "\n")] = '\0';
            fclose(f);
            if (strstr(vendor, "QEMU")) {
                is_virtualized = true;
                if (strcmp(value, "kvm") == 0 || strcmp(value, "qemu") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
            if (strstr(vendor, "VMware")) {
                is_virtualized = true;
                if (strcmp(value, "vmware") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
            if (strstr(vendor, "innotek")) {
                is_virtualized = true;
                if (strcmp(value, "oracle") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
            if (strstr(vendor, "Xen")) {
                is_virtualized = true;
                if (strcmp(value, "xen") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
            if (strstr(vendor, "Microsoft")) {
                is_virtualized = true;
                if (strcmp(value, "microsoft") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
        } else {
            fclose(f);
        }
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    /* BSD: use sysctl to detect virtualization */
    char vm_guest[64] = {0};
    size_t len = sizeof(vm_guest);

#ifdef __FreeBSD__
    /* FreeBSD: kern.vm_guest sysctl */
    if (sysctlbyname("kern.vm_guest", vm_guest, &len, NULL, 0) == 0) {
        if (strlen(vm_guest) > 0 && strcmp(vm_guest, "none") != 0) {
            is_virtualized = true;
            /* Map FreeBSD vm_guest values to systemd names */
            if (strcmp(vm_guest, "hv") == 0) {
                if (strcmp(value, "microsoft") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            } else if (strcmp(vm_guest, "vmware") == 0) {
                if (strcmp(value, "vmware") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            } else if (strcmp(vm_guest, "kvm") == 0) {
                if (strcmp(value, "kvm") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            } else if (strcmp(vm_guest, "xen") == 0) {
                if (strcmp(value, "xen") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            } else if (strcmp(vm_guest, "bhyve") == 0) {
                if (strcmp(value, "bhyve") == 0 || strcmp(value, "vm") == 0) {
                    return true;
                }
            }
        }
    }
#endif

    /* Check for jails (BSD container) */
    int jailed = 0;
    len = sizeof(jailed);
    if (sysctlbyname("security.jail.jailed", &jailed, &len, NULL, 0) == 0 && jailed) {
        is_virtualized = true;
        if (strcmp(value, "jail") == 0 || strcmp(value, "container") == 0) {
            return true;
        }
    }
#elif defined(__APPLE__)
    /* macOS: check for hypervisor via sysctl */
    uint32_t is_vm = 0;
    size_t len = sizeof(is_vm);

    if (sysctlbyname("kern.hv_vmm_present", &is_vm, &len, NULL, 0) == 0 && is_vm) {
        is_virtualized = true;
        if (strcmp(value, "vm") == 0) {
            return true;
        }
    }

    /* Check for specific hypervisors via CPU brand string */
    char brand[128] = {0};
    len = sizeof(brand);
    if (sysctlbyname("machdep.cpu.brand_string", brand, &len, NULL, 0) == 0) {
        if (strstr(brand, "QEMU") || strstr(brand, "Virtual")) {
            is_virtualized = true;
            if (strcmp(value, "qemu") == 0 || strcmp(value, "kvm") == 0 || strcmp(value, "vm") == 0) {
                return true;
            }
        }
        if (strstr(brand, "VMware")) {
            is_virtualized = true;
            if (strcmp(value, "vmware") == 0 || strcmp(value, "vm") == 0) {
                return true;
            }
        }
    }
#endif

    /* Special value "vm" or "container" matches any virtualization */
    if (is_virtualized) {
        if (strcmp(value, "vm") == 0 || strcmp(value, "container") == 0) {
            return true;
        }
    }

    return false;
}

static bool condition_ac_power(const char *value) {
    /* Check AC power status (platform-specific) */
    bool on_ac = false;
    bool power_detected = false;

#ifdef __linux__
    /* Check /sys/class/power_supply for AC adapters */
    DIR *dir = opendir("/sys/class/power_supply");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char type_path[512];
            snprintf(type_path, sizeof(type_path), "/sys/class/power_supply/%s/type", entry->d_name);

            FILE *f = fopen(type_path, "r");
            if (f) {
                char type[32];
                if (fgets(type, sizeof(type), f) && strstr(type, "Mains")) {
                    fclose(f);

                    char online_path[512];
                    snprintf(online_path, sizeof(online_path), "/sys/class/power_supply/%s/online", entry->d_name);
                    f = fopen(online_path, "r");
                    if (f) {
                        char online[8];
                        if (fgets(online, sizeof(online), f) && atoi(online) == 1) {
                            on_ac = true;
                        }
                        fclose(f);
                        power_detected = true;
                        break;
                    }
                } else {
                    fclose(f);
                }
            }
        }
        closedir(dir);
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    /* BSD: use ACPI via sysctl or /dev/acpi */
#ifdef __FreeBSD__
    /* FreeBSD: hw.acpi.acline sysctl (1 = on AC, 0 = on battery) */
    int acline = -1;
    size_t len = sizeof(acline);
    if (sysctlbyname("hw.acpi.acline", &acline, &len, NULL, 0) == 0) {
        power_detected = true;
        on_ac = (acline == 1);
    }
#elif defined(__OpenBSD__)
    /* OpenBSD: hw.sensors.acpiac0.indicator0 or check apm */
    /* Simple heuristic: check if /dev/apm exists and can be read */
    int apm_fd = open("/dev/apm", O_RDONLY);
    if (apm_fd >= 0) {
        /* APM structure varies; for simplicity, assume desktop (AC) if APM present */
        /* A full implementation would use ioctl(apm_fd, APM_IOC_GETPOWER, &info) */
        power_detected = true;
        on_ac = true;  /* Conservative default for OpenBSD */
        close(apm_fd);
    }
#elif defined(__NetBSD__)
    /* NetBSD: use envsys or apm */
    int apm_fd = open("/dev/apm", O_RDONLY);
    if (apm_fd >= 0) {
        power_detected = true;
        on_ac = true;  /* Conservative default for NetBSD */
        close(apm_fd);
    }
#endif
#elif defined(__APPLE__)
    /* macOS: use IOKit Power Sources API via sysctl or pmset */
    /* Simple heuristic: check hw.model to see if it's a laptop */
    char model[64] = {0};
    size_t len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, NULL, 0) == 0) {
        /* If model contains "Book" (MacBook), assume battery possible */
        if (strstr(model, "Book")) {
            /* For macOS, we'd need IOKit to properly check AC status */
            /* This is a simplified fallback - assume AC for desktops, battery unknown for laptops */
            power_detected = true;
            on_ac = false;  /* Conservative: assume on battery if laptop detected */
        } else {
            /* Desktop Mac - always on AC */
            power_detected = true;
            on_ac = true;
        }
    }
#endif

    /* If power detection failed, assume on AC (conservative default for desktops) */
    if (!power_detected) {
        on_ac = true;
    }

    /* Parse value: "true" means on AC, "false" means on battery */
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 || strcmp(value, "yes") == 0) {
        return on_ac;
    } else {
        return !on_ac;
    }
}

static bool condition_os_release(const char *value) {
    /* Parse /etc/os-release for key=value matching */
    const char *equals = strchr(value, '=');
    if (!equals) {
        return false;
    }

    size_t key_len = equals - value;
    char key[128];
    if (key_len >= sizeof(key)) {
        return false;
    }
    strncpy(key, value, key_len);
    key[key_len] = '\0';

    const char *expected_value = equals + 1;

    /* Try /etc/os-release first, then /usr/lib/os-release */
    const char *paths[] = {"/etc/os-release", "/usr/lib/os-release", NULL};
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) {
            continue;
        }

        char line[256];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';

            /* Skip comments and empty lines */
            if (line[0] == '#' || line[0] == '\0') {
                continue;
            }

            char *line_equals = strchr(line, '=');
            if (!line_equals) {
                continue;
            }

            *line_equals = '\0';
            const char *line_key = line;
            const char *line_value = line_equals + 1;

            /* Remove quotes from value */
            if (line_value[0] == '"') {
                line_value++;
                char *end_quote = strchr(line_value, '"');
                if (end_quote) {
                    *end_quote = '\0';
                }
            }

            if (strcmp(line_key, key) == 0 && strcmp(line_value, expected_value) == 0) {
                fclose(f);
                return true;
            }
        }

        fclose(f);
    }

    return false;
}

static bool condition_kernel_version(const char *value) {
    /* Compare kernel version (format varies by OS) */
    struct utsname uts;
    if (uname(&uts) < 0) {
        return false;
    }

    /* Parse comparison operator */
    const char *op = value;
    const char *version_str = value;

    if (strncmp(value, ">=", 2) == 0) {
        op = ">=";
        version_str = value + 2;
    } else if (strncmp(value, "<=", 2) == 0) {
        op = "<=";
        version_str = value + 2;
    } else if (value[0] == '>') {
        op = ">";
        version_str = value + 1;
    } else if (value[0] == '<') {
        op = "<";
        version_str = value + 1;
    } else if (value[0] == '=') {
        op = "=";
        version_str = value + 1;
    } else {
        op = "=";
    }

    /* Simple version comparison (major.minor.patch) */
    int kernel_maj = 0, kernel_min = 0, kernel_patch = 0;
    int target_maj = 0, target_min = 0, target_patch = 0;

    sscanf(uts.release, "%d.%d.%d", &kernel_maj, &kernel_min, &kernel_patch);
    sscanf(version_str, "%d.%d.%d", &target_maj, &target_min, &target_patch);

    int kernel_ver = kernel_maj * 1000000 + kernel_min * 1000 + kernel_patch;
    int target_ver = target_maj * 1000000 + target_min * 1000 + target_patch;

    if (strcmp(op, ">=") == 0) {
        return kernel_ver >= target_ver;
    } else if (strcmp(op, "<=") == 0) {
        return kernel_ver <= target_ver;
    } else if (strcmp(op, ">") == 0) {
        return kernel_ver > target_ver;
    } else if (strcmp(op, "<") == 0) {
        return kernel_ver < target_ver;
    } else {
        return kernel_ver == target_ver;
    }
}

static bool evaluate_single_condition(const struct unit_condition *cond) {
    switch (cond->type) {
    case CONDITION_PATH_EXISTS:
        return condition_path_exists(cond->value);
    case CONDITION_PATH_EXISTS_GLOB:
        return condition_path_exists_glob(cond->value);
    case CONDITION_PATH_IS_DIRECTORY:
        return condition_path_is_directory(cond->value);
    case CONDITION_PATH_IS_SYMBOLIC_LINK:
        return condition_path_is_symlink(cond->value);
    case CONDITION_PATH_IS_MOUNT_POINT:
        return condition_path_is_mount_point(cond->value);
    case CONDITION_PATH_IS_READ_WRITE:
        return condition_path_is_read_write(cond->value);
    case CONDITION_DIRECTORY_NOT_EMPTY:
        return condition_directory_not_empty(cond->value);
    case CONDITION_FILE_IS_EXECUTABLE:
        return condition_file_is_executable(cond->value);
    case CONDITION_FILE_NOT_EMPTY:
        return condition_file_not_empty(cond->value);
    case CONDITION_USER:
        return condition_user(cond->value);
    case CONDITION_GROUP:
        return condition_group(cond->value);
    case CONDITION_HOST:
        return condition_host(cond->value);
    case CONDITION_ARCHITECTURE:
        return condition_architecture(cond->value);
    case CONDITION_MEMORY:
        return condition_memory(cond->value);
    case CONDITION_CPUS:
        return condition_cpus(cond->value);
    case CONDITION_ENVIRONMENT:
        return condition_environment(cond->value);
    case CONDITION_VIRTUALIZATION:
        return condition_virtualization(cond->value);
    case CONDITION_AC_POWER:
        return condition_ac_power(cond->value);
    case CONDITION_OS_RELEASE:
        return condition_os_release(cond->value);
    case CONDITION_KERNEL_VERSION:
        return condition_kernel_version(cond->value);
    default:
        return false;
    }
}

static bool unit_conditions_met(struct unit_file *unit) {
    /* First check all assertions (loud failures) */
    for (int i = 0; i < unit->unit.condition_count; i++) {
        const struct unit_condition *cond = &unit->unit.conditions[i];
        if (!cond->is_assert) {
            continue;  /* Skip conditions for now */
        }

        bool result = evaluate_single_condition(cond);
        if (cond->negate) {
            result = !result;
        }

        if (!result) {
            const char *name = condition_type_name(cond->type, cond->is_assert);
            log_msg(LOG_ERR, unit->name,
                    "%s%s=%s failed, aborting start",
                    cond->negate ? "!" : "",
                    name,
                    cond->value);
            unit->state = STATE_FAILED;
            return false;
        }
    }

    /* Then check all conditions (silent skips) */
    for (int i = 0; i < unit->unit.condition_count; i++) {
        const struct unit_condition *cond = &unit->unit.conditions[i];
        if (cond->is_assert) {
            continue;  /* Already checked */
        }

        bool result = evaluate_single_condition(cond);
        if (cond->negate) {
            result = !result;
        }

        if (!result) {
            const char *name = condition_type_name(cond->type, cond->is_assert);
            log_info(unit->name,
                     "%s%s=%s failed, skipping start",
                     cond->negate ? "!" : "",
                     name,
                     cond->value);
            return false;
        }
    }

    return true;
}

static bool status_in_list(const int *list, int count, int status) {
    if (!list || count <= 0) {
        return false;
    }
    for (int i = 0; i < count; i++) {
        if (list[i] == status) {
            return true;
        }
    }
    return false;
}

static bool unit_has_active_dependents(struct unit_file *unit) {
    for (int i = 0; i < unit_count; i++) {
        struct unit_file *other = units[i];
        if (!other || other == unit) {
            continue;
        }

        if (other->state != STATE_ACTIVE && other->state != STATE_ACTIVATING) {
            continue;
        }

        for (int j = 0; j < other->unit.requires_count; j++) {
            if (dependency_matches(unit, other->unit.requires[j])) {
                return true;
            }
        }
        for (int j = 0; j < other->unit.wants_count; j++) {
            if (dependency_matches(unit, other->unit.wants[j])) {
                return true;
            }
        }
        for (int j = 0; j < other->unit.binds_to_count; j++) {
            if (dependency_matches(unit, other->unit.binds_to[j])) {
                return true;
            }
        }
        for (int j = 0; j < other->unit.part_of_count; j++) {
            if (dependency_matches(unit, other->unit.part_of[j])) {
                return true;
            }
        }
    }
    return false;
}

static void enforce_stop_when_unneeded(void) {
    if (stop_when_unneeded_guard) {
        return;
    }

    stop_when_unneeded_guard = true;

    bool changed;
    do {
        changed = false;
        for (int i = 0; i < unit_count; i++) {
            struct unit_file *unit = units[i];
            if (!unit) {
                continue;
            }

            if (!unit->unit.stop_when_unneeded) {
                continue;
            }

            if (unit->state != STATE_ACTIVE) {
                continue;
            }

            if (unit_has_active_dependents(unit)) {
                continue;
            }

            log_info(unit->name, "Stopping (StopWhenUnneeded=yes)");
            if (stop_unit_recursive(unit) == 0) {
                changed = true;
            } else {
                log_warn(unit->name, "Failed to stop despite StopWhenUnneeded=yes");
            }
        }
    } while (changed);

    stop_when_unneeded_guard = false;
}

static bool dependency_matches(struct unit_file *candidate, const char *name) {
    if (!candidate || !name) {
        return false;
    }
    if (strcmp(candidate->name, name) == 0) {
        return true;
    }
    return unit_provides(candidate, name);
}

static void stop_bound_dependents(struct unit_file *unit, const char *reason) {
    if (!unit) {
        return;
    }

    for (int i = 0; i < unit_count; i++) {
        struct unit_file *other = units[i];
        if (!other || other == unit) {
            continue;
        }

        bool binds = false;
        for (int j = 0; j < other->unit.binds_to_count; j++) {
            if (dependency_matches(unit, other->unit.binds_to[j])) {
                binds = true;
                break;
            }
        }

        bool part = false;
        for (int j = 0; j < other->unit.part_of_count; j++) {
            if (dependency_matches(unit, other->unit.part_of[j])) {
                part = true;
                break;
            }
        }

        if (!binds && !part) {
            continue;
        }

        if (other->state != STATE_ACTIVE &&
            other->state != STATE_DEACTIVATING &&
            other->state != STATE_ACTIVATING) {
            continue;
        }

        if (binds) {
            log_msg(LOG_INFO, other->name,
                    "stopping (BindsTo=%s) because %s", unit->name, reason);
        } else if (part) {
            log_msg(LOG_INFO, other->name,
                    "stopping (PartOf=%s) because %s", unit->name, reason);
        }

        stop_unit_recursive(other);
    }
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
        /* For RemainAfterExit=yes services, stay active after successful exit */
        if (unit->config.service.remain_after_exit) {
            unit->state = STATE_ACTIVE;
            log_debug(unit->name, "exited successfully, remaining active (RemainAfterExit=yes)");
        } else {
            unit->state = STATE_INACTIVE;
            /* Only show "Stopped" for long-running services, not oneshot */
            if (unit->config.service.type != SERVICE_ONESHOT) {
                log_service_stopped(unit->name, unit->unit.description);
            }
        }
    } else {
        unit->state = STATE_FAILED;
        char reason[128];
        snprintf(reason, sizeof(reason), "exited with status %d", exit_status);
        log_service_failed(unit->name, unit->unit.description, reason);
        trigger_on_failure(unit);
    }

    if (success && unit->type == UNIT_SERVICE) {
        notify_timer_daemon_inactive(unit->name);
    }

    if (unit->state != STATE_ACTIVE) {
        const char *reason = success ? "dependency became inactive"
                                     : "dependency failed";
        stop_bound_dependents(unit, reason);
        enforce_stop_when_unneeded();
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

    if (unit->type == UNIT_SERVICE) {
        if (status_in_list(unit->config.service.restart_prevent_statuses,
                           unit->config.service.restart_prevent_count,
                           exit_status)) {
            should_restart = false;
        } else if (status_in_list(unit->config.service.restart_force_statuses,
                                  unit->config.service.restart_force_count,
                                  exit_status)) {
            should_restart = true;
        }
    }

    if (should_restart && !shutdown_requested) {
        int restart_sec = unit->config.service.restart_sec;
        if (restart_sec <= 0) restart_sec = 1; /* Default 1 second */

        log_info("worker", "Restarting %s in %d seconds (restart count: %d)",
                 unit->name, restart_sec, unit->restart_count + 1);

        sleep(restart_sec);

        unit->restart_count++;
        log_service_starting(unit->name, unit->unit.description);
        if (start_service(unit) > 0) {
            log_service_started(unit->name, unit->unit.description);
        } else {
            log_service_failed(unit->name, unit->unit.description, "restart failed");
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
        log_error("worker", "control_socket_path returned NULL");
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        log_error("worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    if (debug_mode) {
        log_debug("worker", "Creating control socket at %s", path);
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

    /* fprintf(stderr, "worker: received command %s for unit %s\n",
            command_to_string(req.header.command), req.unit_name); */

    bool manual_request = !(req.header.flags & REQ_FLAG_INTERNAL);

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
        } else if (unit->unit.refuse_manual_start && manual_request) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message),
                     "Manual start refused (RefuseManualStart=yes)");
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
        } else if (unit->unit.refuse_manual_stop && manual_request) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message),
                     "Manual stop refused (RefuseManualStop=yes)");
        } else {
            if (stop_unit_recursive(unit) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to stop %s", req.unit_name);
            } else {
                snprintf(resp.message, sizeof(resp.message), "Stopped %s", req.unit_name);
                enforce_stop_when_unneeded();
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
        } else if (!unit->unit.allow_isolate) {
            resp.code = RESP_INVALID_COMMAND;
            snprintf(resp.message, sizeof(resp.message), "Unit %s does not allow isolation", req.unit_name);
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
        const char *action;

        /* Map control command to IPC request type and action name */
        if (req.header.command == CMD_POWEROFF) {
            shutdown_req.type = REQ_POWEROFF;
            action = "poweroff";
        } else if (req.header.command == CMD_REBOOT) {
            shutdown_req.type = REQ_REBOOT;
            action = "reboot";
        } else {
            shutdown_req.type = REQ_HALT;
            action = "halt";
        }

        /* Find shutdown.target */
        struct unit_file *shutdown_target = find_unit("shutdown.target");
        if (!shutdown_target) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "shutdown.target not found (required unit missing)");
            break;
        }

        /* Isolate to shutdown.target - this stops all services in proper order */
        log_info("worker", "Initiating %s via isolation to shutdown.target", action);
        unsigned int generation = next_isolate_generation();
        mark_isolate_closure(shutdown_target, generation);

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
            snprintf(resp.message, sizeof(resp.message), "Failed to stop units during shutdown");
            break;
        }

        /* Start shutdown.target - this runs After=shutdown.target units (swap, mountfs) */
        if (start_unit_recursive(shutdown_target) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to reach shutdown.target");
            break;
        }

        /* Shutdown sequence complete, now send final shutdown request to master */
        if (send_request(master_socket, &shutdown_req) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to send shutdown request to master");
        } else if (recv_response(master_socket, &shutdown_resp) < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to receive response from master");
        } else if (shutdown_resp.type == RESP_OK) {
            resp.code = RESP_SUCCESS;
            snprintf(resp.message, sizeof(resp.message), "System %s initiated", action);
        } else {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "%s", shutdown_resp.error_msg);
        }
        break;
    }

    case CMD_DUMP_LOGS: {
        /* Dump buffered logs to console */
        log_dump_buffer();
        resp.code = RESP_SUCCESS;
        snprintf(resp.message, sizeof(resp.message), "Log buffer dumped to console");
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
        /* fprintf(stderr, "worker: maximum recursion depth exceeded stopping %s\n", unit->name); */
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
        /* fprintf(stderr, "worker: circular dependency detected stopping %s\n", unit->name); */
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
    /* fprintf(stderr, "worker: stopping %s\n", unit->name); */

    for (int i = 0; i < unit_count; i++) {
        struct unit_file *other = units[i];
        if (other == unit || (other->state != STATE_ACTIVE && other->state != STATE_DEACTIVATING)) {
            continue;
        }

        bool depends_on_us = false;
        for (int j = 0; j < other->unit.requires_count; j++) {
            if (dependency_matches(unit, other->unit.requires[j])) {
                depends_on_us = true;
                break;
            }
        }
        if (!depends_on_us) {
            for (int j = 0; j < other->unit.wants_count; j++) {
                if (dependency_matches(unit, other->unit.wants[j])) {
                    depends_on_us = true;
                    break;
                }
            }
        }

        if (!depends_on_us) {
            for (int j = 0; j < other->unit.binds_to_count; j++) {
                if (dependency_matches(unit, other->unit.binds_to[j])) {
                    depends_on_us = true;
                    break;
                }
            }
        }

        if (!depends_on_us) {
            for (int j = 0; j < other->unit.part_of_count; j++) {
                if (dependency_matches(unit, other->unit.part_of[j])) {
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

    for (int i = 0; i < unit->unit.binds_to_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.binds_to[i]);
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
        /* fprintf(stderr, "worker: maximum recursion depth exceeded starting %s\n", unit->name); */
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
        log_service_failed(unit->name, unit->unit.description, "circular dependency detected");
        unit->state = STATE_FAILED;
        trigger_on_failure(unit);
        return -1;
    }

    if (unit->state == STATE_ACTIVE) {
        unit->start_visit_state = DEP_VISIT_DONE;
        return 0;
    }

    unit->start_visit_state = DEP_VISIT_IN_PROGRESS;

    if (!unit_conditions_met(unit)) {
        unit->state = STATE_INACTIVE;
        unit->start_visit_state = DEP_VISIT_DONE;
        return 0;
    }

    unit->state = STATE_ACTIVATING;
    log_service_starting(unit->name, unit->unit.description);

    /* Apply implicit dependencies if DefaultDependencies=yes */
    if (unit->unit.default_dependencies) {
        /* Services, timers, and sockets with DefaultDependencies get implicit After=basic.target */
        if (unit->type == UNIT_SERVICE || unit->type == UNIT_TIMER || unit->type == UNIT_SOCKET) {
            struct unit_file *basic = resolve_unit("basic.target");
            if (basic && basic->state != STATE_ACTIVE && basic->state != STATE_FAILED) {
                if (basic->state == STATE_INACTIVE) {
                    start_unit_recursive_depth(basic, depth + 1, generation);
                }
            }
        }
    }

    for (int i = 0; i < unit->unit.binds_to_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.binds_to[i]);
        if (dep && start_unit_recursive_depth(dep, depth + 1, generation) < 0) {
            char reason[256];
            snprintf(reason, sizeof(reason), "failed to start bound dependency %s",
                     unit->unit.binds_to[i]);
            log_service_failed(unit->name, unit->unit.description, reason);
            unit->state = STATE_FAILED;
            trigger_on_failure(unit);
            unit->start_visit_state = DEP_VISIT_NONE;
            return -1;
        }
    }

    for (int i = 0; i < unit->unit.requires_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.requires[i]);
        if (dep && start_unit_recursive_depth(dep, depth + 1, generation) < 0) {
            char reason[256];
            snprintf(reason, sizeof(reason), "failed to start required dependency %s", unit->unit.requires[i]);
            log_service_failed(unit->name, unit->unit.description, reason);
            unit->state = STATE_FAILED;
            trigger_on_failure(unit);
            unit->start_visit_state = DEP_VISIT_NONE;
            return -1;
        }
    }

    for (int i = 0; i < unit->unit.wants_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.wants[i]);
        if (dep) {
            start_unit_recursive_depth(dep, depth + 1, generation);
        }
    }

    for (int i = 0; i < unit->unit.after_count; i++) {
        struct unit_file *dep = resolve_unit(unit->unit.after[i]);
        if (dep && dep->state != STATE_ACTIVE && dep->state != STATE_FAILED) {
            if (dep->state == STATE_INACTIVE) {
                if (start_unit_recursive_depth(dep, depth + 1, generation) < 0) {
                    log_warn(unit->name, "After= dependency %s failed", unit->unit.after[i]);
                }
            }
        }
    }

    if (unit->type == UNIT_SERVICE) {
        if (start_service(unit) < 0) {
            log_service_failed(unit->name, unit->unit.description, "failed to start service");
            unit->state = STATE_FAILED;
            trigger_on_failure(unit);
            unit->start_visit_state = DEP_VISIT_NONE;
            return -1;
        }
        /* Service started successfully - log it */
        log_service_started(unit->name, unit->unit.description);
    } else if (unit->type == UNIT_TARGET) {
        unit->state = STATE_ACTIVE;
        log_target_reached(unit->name, unit->unit.description);
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

/* Trigger OnFailure= units when a unit fails */
static void trigger_on_failure(struct unit_file *unit) {
    if (!unit || unit->unit.on_failure_count == 0) {
        return;
    }

    log_info(unit->name, "triggering OnFailure units (%d)", unit->unit.on_failure_count);

    for (int i = 0; i < unit->unit.on_failure_count; i++) {
        const char *failure_unit_name = unit->unit.on_failure[i];
        struct unit_file *failure_unit = find_unit(failure_unit_name);

        if (!failure_unit) {
            log_warn(unit->name, "OnFailure unit %s not found", failure_unit_name);
            continue;
        }

        log_info(unit->name, "activating OnFailure unit: %s", failure_unit_name);
        if (start_unit_recursive(failure_unit) < 0) {
            log_warn(unit->name, "failed to activate OnFailure unit %s", failure_unit_name);
        }
    }
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
        /* fprintf(stderr, "supervisor-worker: usage: %s <ipc_fd>\n", argv[0]); */
        return 1;
    }

    /* Get IPC socket FD from command line */
    errno = 0;
    char *endptr = NULL;
    long parsed_fd = strtol(argv[1], &endptr, 10);
    if (errno != 0 || endptr == argv[1] || *endptr != '\0' ||
        parsed_fd < 0 || parsed_fd > INT_MAX) {
        log_error("worker", "invalid IPC fd argument '%s'", argv[1]);
        return 1;
    }

    master_socket = (int)parsed_fd;

    int fd_flags = fcntl(master_socket, F_GETFD);
    if (fd_flags < 0 || fcntl(master_socket, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        log_error("worker", "failed to reapply FD_CLOEXEC to IPC fd: %s", strerror(errno));
        return 1;
    }

    /* Initialize logging */
    log_init("supervisor-worker");
    log_enhanced_init("worker", NULL);
    log_debug("worker", "Logging initialized, IPC socket fd=%d", master_socket);

    const char *debug_env = getenv("INITD_DEBUG_SUPERVISOR");
    debug_mode = (debug_env && strcmp(debug_env, "0") != 0);
    if (debug_mode) {
        log_set_console_level(LOGLEVEL_DEBUG);
        log_set_file_level(LOGLEVEL_DEBUG);
    } else {
        log_set_console_level(LOGLEVEL_INFO);
        log_set_file_level(LOGLEVEL_INFO);
    }

    log_info("worker", "Starting (ipc_fd=%d)", master_socket);

    /* Setup signals */
    log_debug("worker", "Setting up signal handlers");
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    log_debug("worker", "Creating control socket");
    control_socket = create_control_socket();
    if (control_socket < 0) {
        log_error("worker", "failed to create control socket");
        return 1;
    }
    if (debug_mode) {
        const char *ctrl_path_dbg = control_socket_path(false);
        log_debug("worker", "control socket bound fd=%d path=%s",
                  control_socket, ctrl_path_dbg ? ctrl_path_dbg : "<null>");
    }

    log_debug("worker", "Creating status socket");
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
    log_debug("worker", "Found %zu units", unit_count);

    /* Determine target to boot */
    const char *target_name = getenv("INITD_TARGET");
    if (!target_name || target_name[0] == '\0') {
        target_name = "default.target";
    }

    log_info("worker", "Starting %s", target_name);
    struct unit_file *boot_target = find_unit(target_name);

    if (!boot_target && strcmp(target_name, "default.target") == 0) {
        /* Fallback to emergency.target if default.target not found */
        log_warn("worker", "default.target not found (required unit missing), falling back to emergency.target");
        boot_target = find_unit("emergency.target");
        target_name = "emergency.target";
    }

    if (boot_target) {
        log_debug("worker", "Activating target: %s", boot_target->name);
        if (start_unit_recursive(boot_target) < 0) {
            log_error("worker", "failed to start %s (OnFailure units will be triggered)", target_name);
        }
    } else {
        log_error("worker", "%s not found", target_name);
    }

    /* Main loop */
    log_debug("worker", "Entering main loop");
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
