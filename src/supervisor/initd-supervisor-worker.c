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
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

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
#include "../common/ipc.h"
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/parser.h"
#include "../common/scanner.h"
#include "../common/log.h"

static volatile sig_atomic_t shutdown_requested = 0;
static int master_socket = -1;
static int control_socket = -1;
static struct unit_file **units = NULL;
static int unit_count = 0;

/* Forward declarations */
static bool unit_provides(struct unit_file *unit, const char *service_name);
static int stop_unit_recursive(struct unit_file *unit);
static int start_unit_recursive(struct unit_file *unit);

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("supervisor-slave: sigaction SIGTERM");
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

    fprintf(stderr, "slave: enabling %s\n", unit->name);

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
        fprintf(stderr, "slave: failed to enable %s: %s\n", unit->name, resp.error_msg);
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

    fprintf(stderr, "slave: disabling %s\n", unit->name);

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
        fprintf(stderr, "slave: failed to disable %s: %s\n", unit->name, resp.error_msg);
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

    /* Check multi-user.target.wants */
    snprintf(symlink_path, sizeof(symlink_path),
             "/etc/initd/system/multi-user.target.wants/%s", unit->name);
    if (access(symlink_path, F_OK) == 0) return true;

    snprintf(symlink_path, sizeof(symlink_path),
             "/lib/initd/system/multi-user.target.wants/%s", unit->name);
    if (access(symlink_path, F_OK) == 0) return true;

    /* Check default.target.wants */
    snprintf(symlink_path, sizeof(symlink_path),
             "/etc/initd/system/default.target.wants/%s", unit->name);
    if (access(symlink_path, F_OK) == 0) return true;

    snprintf(symlink_path, sizeof(symlink_path),
             "/lib/initd/system/default.target.wants/%s", unit->name);
    if (access(symlink_path, F_OK) == 0) return true;

    /* Check if unit has WantedBy or RequiredBy */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        snprintf(symlink_path, sizeof(symlink_path),
                 "/etc/initd/system/%s.wants/%s", unit->install.wanted_by[i], unit->name);
        if (access(symlink_path, F_OK) == 0) return true;

        snprintf(symlink_path, sizeof(symlink_path),
                 "/lib/initd/system/%s.wants/%s", unit->install.wanted_by[i], unit->name);
        if (access(symlink_path, F_OK) == 0) return true;
    }

    for (int i = 0; i < unit->install.required_by_count; i++) {
        snprintf(symlink_path, sizeof(symlink_path),
                 "/etc/initd/system/%s.requires/%s", unit->install.required_by[i], unit->name);
        if (access(symlink_path, F_OK) == 0) return true;

        snprintf(symlink_path, sizeof(symlink_path),
                 "/lib/initd/system/%s.requires/%s", unit->install.required_by[i], unit->name);
        if (access(symlink_path, F_OK) == 0) return true;
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
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);

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

/* Request master to start a service */
static pid_t start_service(struct unit_file *unit) {
    struct priv_request req = {0};
    struct priv_response resp = {0};

    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);

    if (unit->type == UNIT_SERVICE) {
        strncpy(req.exec_path, unit->config.service.exec_start, sizeof(req.exec_path) - 1);

        /* Lookup user/group */
        if (lookup_user(unit->config.service.user, &req.run_uid, &req.run_gid) < 0) {
            fprintf(stderr, "slave: failed to lookup user %s\n", unit->config.service.user);
            return -1;
        }
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

/* Find unit by PID */
static struct unit_file *find_unit_by_pid(pid_t pid) {
    for (int i = 0; i < unit_count; i++) {
        if (units[i]->pid == pid) {
            return units[i];
        }
    }
    return NULL;
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
static int create_control_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("slave: socket");
        return -1;
    }

    /* Remove old socket if exists */
    unlink(CONTROL_SOCKET_PATH);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("slave: bind");
        close(fd);
        return -1;
    }

    /* Make socket accessible - use fchmod to avoid race condition */
    fchmod(fd, 0666);

    if (listen(fd, 5) < 0) {
        perror("slave: listen");
        close(fd);
        return -1;
    }

    fprintf(stderr, "slave: control socket listening on %s\n", CONTROL_SOCKET_PATH);
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

/* Handle control command */
static void handle_control_command(int client_fd) {
    struct control_request req = {0};
    struct control_response resp = {0};

    if (recv_control_request(client_fd, &req) < 0) {
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

        /* Send success response first */
        resp.code = RESP_SUCCESS;
        snprintf(resp.message, sizeof(resp.message), "Listing %d units", scanned_count);
        send_control_response(client_fd, &resp);

        /* Then send unit list */
        send_unit_list(client_fd, entries, scanned_count);

        free(entries);
        free_units(scanned_units, scanned_count);
        close(client_fd);
        return;
    }

    case CMD_RESTART:
    case CMD_RELOAD:
    case CMD_LIST_TIMERS:
    case CMD_DAEMON_RELOAD:
    case CMD_ISOLATE:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message), "Command %s not yet implemented",
                 command_to_string(req.header.command));
        break;

    default:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message), "Unknown command");
        break;
    }

    send_control_response(client_fd, &resp);
    close(client_fd);
}

/* Stop a unit (recursive, reverse dependency order) */
static int stop_unit_recursive(struct unit_file *unit) {
    if (!unit) return -1;
    if (unit->state == STATE_INACTIVE) return 0; /* Already stopped */

    /* First, stop units that depend on this one */
    for (int i = 0; i < unit_count; i++) {
        struct unit_file *other = units[i];
        if (other == unit || other->state != STATE_ACTIVE) continue;

        /* Check if 'other' depends on 'unit' */
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

        /* Stop dependent units first */
        if (depends_on_us) {
            stop_unit_recursive(other);
        }
    }

    /* Now stop this unit */
    fprintf(stderr, "slave: stopping %s\n", unit->name);

    if (unit->type == UNIT_SERVICE) {
        stop_service(unit);
    } else if (unit->type == UNIT_TARGET) {
        /* Targets don't run, just mark inactive */
        unit->state = STATE_INACTIVE;
    }

    return 0;
}

/* Start a unit and its dependencies (recursive) */
static int start_unit_recursive(struct unit_file *unit) {
    if (!unit) return -1;
    if (unit->state == STATE_ACTIVE) return 0; /* Already running */

    fprintf(stderr, "slave: starting %s\n", unit->name);

    /* Start dependencies first (Requires) */
    for (int i = 0; i < unit->unit.requires_count; i++) {
        struct unit_file *dep = find_unit(unit->unit.requires[i]);
        if (dep && start_unit_recursive(dep) < 0) {
            fprintf(stderr, "slave: failed to start required dependency %s\n", unit->unit.requires[i]);
            return -1;
        }
    }

    /* Start soft dependencies (Wants) */
    for (int i = 0; i < unit->unit.wants_count; i++) {
        struct unit_file *dep = find_unit(unit->unit.wants[i]);
        if (dep) {
            start_unit_recursive(dep); /* Don't fail on soft deps */
        }
    }

    /* Start the unit itself */
    if (unit->type == UNIT_SERVICE) {
        if (start_service(unit) < 0) {
            fprintf(stderr, "slave: failed to start %s\n", unit->name);
            unit->state = STATE_FAILED;
            return -1;
        }
    } else if (unit->type == UNIT_TARGET) {
        /* Targets don't run, just mark active */
        unit->state = STATE_ACTIVE;
    }

    return 0;
}

/* Main loop: manage services */
static int main_loop(void) {
    fprintf(stderr, "supervisor-slave: entering main loop\n");

    /* Defensive check: ensure sockets are valid */
    if (control_socket < 0 || master_socket < 0) {
        fprintf(stderr, "supervisor-slave: invalid socket in main_loop\n");
        return -1;
    }

    struct pollfd fds[2];
    fds[0].fd = control_socket;
    fds[0].events = POLLIN;
    fds[1].fd = master_socket;
    fds[1].events = POLLIN;

    while (!shutdown_requested) {
        /* Poll both control socket and master socket */
        int ret = poll(fds, 2, 1000); /* 1 second timeout */

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("slave: poll");
            break;
        }

        if (ret > 0) {
            /* Check for initctl control requests */
            if (fds[0].revents & POLLIN) {
                int client_fd = accept(control_socket, NULL, NULL);
                if (client_fd >= 0) {
                    handle_control_command(client_fd);
                }
            }

            /* Check for notifications from master */
            if (fds[1].revents & POLLIN) {
                struct priv_response notif = {0};
                if (recv_response(master_socket, &notif) == 0) {
                    if (notif.type == RESP_SERVICE_EXITED) {
                        handle_service_exit(notif.service_pid, notif.exit_status);
                    }
                } else {
                    fprintf(stderr, "slave: master socket closed\n");
                    break;
                }
            }
        }

        /* Timer expirations are handled by independent timer-daemon */
    }

    /* Shutdown sequence */
    fprintf(stderr, "supervisor-slave: shutting down services\n");

    /* Stop all active services in reverse dependency order */
    /* We iterate through all units and stop them; the recursive function
     * will handle dependency ordering */
    for (int i = 0; i < unit_count; i++) {
        if (units[i]->state == STATE_ACTIVE) {
            stop_unit_recursive(units[i]);
        }
    }

    fprintf(stderr, "supervisor-slave: all services stopped\n");

    /* Notify master we're done */
    notify_shutdown_complete();

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "supervisor-slave: usage: %s <ipc_fd>\n", argv[0]);
        return 1;
    }

    /* Get IPC socket FD from command line */
    master_socket = atoi(argv[1]);

    /* Initialize logging */
    log_init("supervisor-slave");

    log_msg(LOG_INFO, NULL, "starting (ipc_fd=%d)", master_socket);

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    control_socket = create_control_socket();
    if (control_socket < 0) {
        fprintf(stderr, "supervisor-slave: failed to create control socket\n");
        return 1;
    }

    /* Scan unit directories */
    fprintf(stderr, "supervisor-slave: scanning unit directories\n");
    if (scan_unit_directories(&units, &unit_count) < 0) {
        fprintf(stderr, "supervisor-slave: failed to scan unit directories\n");
        close(control_socket);
        unlink(CONTROL_SOCKET_PATH);
        return 1;
    }

    /* Start default.target */
    fprintf(stderr, "supervisor-slave: starting default.target\n");
    struct unit_file *default_target = find_unit("default.target");
    if (!default_target) {
        /* Fallback to multi-user.target */
        default_target = find_unit("multi-user.target");
    }

    if (default_target) {
        if (start_unit_recursive(default_target) < 0) {
            fprintf(stderr, "supervisor-slave: failed to start default target\n");
        }
    } else {
        fprintf(stderr, "supervisor-slave: no default target found\n");
    }

    /* Main loop */
    main_loop();

    /* Cleanup */
    free_units(units, unit_count);

    if (control_socket >= 0) {
        close(control_socket);
        unlink(CONTROL_SOCKET_PATH);
    }

    log_msg(LOG_INFO, NULL, "exiting");
    log_close();
    return 0;
}
