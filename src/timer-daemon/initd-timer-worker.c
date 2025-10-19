/* initd-timer-worker.c - Unprivileged timer worker
 *
 * Responsibilities:
 * - Parse .timer unit files
 * - Schedule timer events (calendar, monotonic, boot-relative)
 * - Activate services when timers fire
 * - Persist state for missed timers
 * - Accept control commands via Unix socket
 * - Send privileged requests to daemon via IPC
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <stdbool.h>
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/scanner.h"
#include "../common/parser.h"
#include "../common/timer-ipc.h"
#include "../common/path-security.h"
#include "../common/log-enhanced.h"
#include "calendar.h"

#define TIMER_STATE_DIR "/var/lib/initd/timers"

static int daemon_socket = -1;

/* Timer instance - runtime state for a loaded timer */
struct timer_instance {
    struct unit_file *unit;
    time_t next_run;        /* Next scheduled run (CLOCK_REALTIME) */
    time_t last_run;        /* Last actual run (for persistence) */
    time_t last_inactive;   /* Last time linked service became inactive */
    bool enabled;
    struct timer_instance *next;
};

static volatile sig_atomic_t shutdown_requested = 0;
static int control_socket = -1;
static int status_socket = -1;
static struct timer_instance *timers = NULL;

#ifdef UNIT_TEST
static void timer_daemon_test_clear_instances(void);
#endif

static void format_time_iso(time_t ts, char *buf, size_t len) {
    if (ts <= 0) {
        snprintf(buf, len, "n/a");
        return;
    }

    struct tm tm_buf;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
    if (localtime_r(&ts, &tm_buf) == NULL) {
        snprintf(buf, len, "n/a");
        return;
    }
#else
    struct tm *tmp = localtime(&ts);
    if (!tmp) {
        snprintf(buf, len, "n/a");
        return;
    }
    tm_buf = *tmp;
#endif

    if (strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        snprintf(buf, len, "n/a");
    }
}

static bool timer_unit_is_enabled(struct unit_file *unit) {
    char link_path[1024];
    struct stat st;

    if (!validate_unit_name(unit->name)) {
        return false;
    }

    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];
        if (!validate_target_name(target)) {
            continue;
        }
        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.wants/%s", target, unit->name);
        if (lstat(link_path, &st) == 0) {
            return true;
        }
    }

    for (int i = 0; i < unit->install.required_by_count; i++) {
        const char *target = unit->install.required_by[i];
        if (!validate_target_name(target)) {
            continue;
        }
        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.requires/%s", target, unit->name);
        if (lstat(link_path, &st) == 0) {
            return true;
        }
    }

    return false;
}

static void free_timer_instances(void) {
    struct timer_instance *t = timers;
    while (t) {
        struct timer_instance *next = t->next;
        if (t->unit) {
            free_unit_file(t->unit);
            free(t->unit);
        }
        free(t);
        t = next;
    }
    timers = NULL;
}

#ifdef UNIT_TEST
static void timer_daemon_test_clear_instances(void) {
    struct timer_instance *t = timers;
    while (t) {
        struct timer_instance *next = t->next;
        free(t);
        t = next;
    }
    timers = NULL;
}
#endif

static void timer_service_name(const struct timer_instance *timer, char *buf, size_t len) {
    const char *name = timer->unit->name;
    const char *dot = strrchr(name, '.');
    size_t base_len = strlen(name);
    if (dot && strcmp(dot, ".timer") == 0) {
        base_len = (size_t)(dot - name);
    }

    if (base_len + strlen(".service") + 1 > len) {
        snprintf(buf, len, "%s", name);
        return;
    }

    memcpy(buf, name, base_len);
    buf[base_len] = '\0';
    strcat(buf, ".service");
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
        log_error("timer-worker", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_error("timer-worker", "sigaction SIGINT: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Create control socket */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_control_socket(void) {
    const char *path = timer_socket_path(false);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        log_error("timer-worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("timer-worker", "socket: %s", strerror(errno));
        return -1;
    }

    /* Remove old socket if exists */
    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("timer-worker", "bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("timer-worker", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set permissions - use fchmod to avoid race condition */
    fchmod(fd, 0666);

    log_debug("timer-worker", "Control socket created at %s", path);
    return fd;
}

#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_status_socket(void) {
    const char *path = timer_socket_path(true);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        log_error("timer-worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("timer-worker", "status socket: %s", strerror(errno));
        return -1;
    }

    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("timer-worker", "bind status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("timer-worker", "listen status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (fchmod(fd, 0666) < 0) {
        log_error("timer-worker", "fchmod status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_debug("timer-worker", "Status socket created at %s", path);
    return fd;
}

/* Load timer state from persistence */
static void load_timer_state(struct timer_instance *timer) {
    char path[1024];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s.state", TIMER_STATE_DIR, timer->unit->name);

    f = fopen(path, "r");
    if (!f) {
        return; /* No saved state */
    }
    int fd = fileno(f);
    if (fd >= 0) {
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    long run = 0;
    long inactive = 0;
    int scanned = fscanf(f, "%ld %ld", &run, &inactive);
    if (scanned >= 1) {
        timer->last_run = run;
    } else {
        timer->last_run = 0;
    }

    if (scanned >= 2) {
        timer->last_inactive = inactive;
    } else {
        timer->last_inactive = 0;
    }

    fclose(f);
}

/* Save timer state for persistence */
static void save_timer_state(struct timer_instance *timer) {
    char path[1024];
    FILE *f;

    /* Ensure state directory exists */
    mkdir(TIMER_STATE_DIR, 0755);

    snprintf(path, sizeof(path), "%s/%s.state", TIMER_STATE_DIR, timer->unit->name);

    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "timer-daemon: failed to save state for %s: %s\n",
                timer->unit->name, strerror(errno));
        return;
    }
    int fd = fileno(f);
    if (fd >= 0) {
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    fprintf(f, "%ld %ld\n", (long)timer->last_run, (long)timer->last_inactive);
    fclose(f);
}

/* Boot time (set at startup) */
static time_t boot_time = 0;
static time_t daemon_start_time = 0;

/* Calculate next run time for a timer */
static time_t calculate_next_run(struct timer_instance *timer) {
    time_t now = time(NULL);
    struct timer_section *t = &timer->unit->config.timer;
    time_t next = 0;

    /* OnCalendar - calendar-based scheduling */
    if (t->on_calendar) {
        time_t calendar_next = calendar_next_run(t->on_calendar, now);
        /* First timer type: next is guaranteed to be 0, so just check validity */
        if (calendar_next > 0) {
            next = calendar_next;
        }
    }

    /* OnBootSec - seconds after boot */
    if (t->on_boot_sec > 0) {
        time_t boot_next = boot_time + t->on_boot_sec;
        if (boot_next > now && (next == 0 || boot_next < next)) {
            next = boot_next;
        }
    }

    /* OnStartupSec - seconds after daemon start */
    if (t->on_startup_sec > 0) {
        time_t startup_next = daemon_start_time + t->on_startup_sec;
        if (startup_next > now && (next == 0 || startup_next < next)) {
            next = startup_next;
        }
    }

    /* OnUnitActiveSec - monotonic timer (relative to last activation) */
    if (t->on_unit_active_sec > 0 && timer->last_run > 0) {
        time_t active_next = timer->last_run + t->on_unit_active_sec;
        if (active_next > now && (next == 0 || active_next < next)) {
            next = active_next;
        }
    }

    /* OnUnitInactiveSec - seconds after the service becomes inactive */
    if (t->on_unit_inactive_sec > 0 && timer->last_inactive > 0) {
        time_t inactive_next = timer->last_inactive + t->on_unit_inactive_sec;
        if (inactive_next > now && (next == 0 || inactive_next < next)) {
            next = inactive_next;
        }
    }

    /* If no timer matched and last_run is set, recalculate from last_run */
    if (next == 0 && t->on_calendar) {
        next = calendar_next_run(t->on_calendar, timer->last_run > 0 ? timer->last_run : now);
    }

    /* Apply randomized delay */
    if (next > 0 && t->randomized_delay_sec > 0) {
        int delay = rand() % t->randomized_delay_sec;
        next += delay;
    }

    /* If still no next time, default to 1 hour from now */
    if (next == 0) {
        next = now + 3600;
    }

    return next;
}

/* Try to activate service via supervisor */
static int activate_via_supervisor(const char *service_name) {
    int fd;
    struct sockaddr_un addr;
    struct control_request req = {0};
    struct control_response resp = {0};

    /* Connect to supervisor */
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Send start request */
    req.header.length = sizeof(req);
    req.header.command = CMD_START;
    strncpy(req.unit_name, service_name, sizeof(req.unit_name) - 1);

    if (send_control_request(fd, &req) < 0) {
        close(fd);
        return -1;
    }

    /* Receive response */
    if (recv_control_response(fd, &resp) < 0) {
        close(fd);
        return -1;
    }

    close(fd);

    if (resp.code == RESP_SUCCESS || resp.code == RESP_UNIT_ALREADY_ACTIVE) {
        return 0;
    }

    return -1;
}

/* Activate service directly via fork/exec */
static int activate_direct(const char *service_name) {
    /* Load service unit */
    char unit_path[1024];
    struct unit_file unit;

    /* Try to find the service unit file */
    const char *dirs[] = {
        "/etc/initd/system",
        "/lib/initd/system",
        "/etc/systemd/system",
        "/lib/systemd/system",
        NULL
    };

    bool found = false;
    for (int i = 0; dirs[i]; i++) {
        snprintf(unit_path, sizeof(unit_path), "%s/%s", dirs[i], service_name);
        if (parse_unit_file(unit_path, &unit) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "timer-daemon: service %s not found\n", service_name);
        return -1;
    }

    if (unit.type != UNIT_SERVICE) {
        fprintf(stderr, "timer-daemon: %s is not a service\n", service_name);
        free_unit_file(&unit);
        return -1;
    }

    if (!unit.config.service.exec_start) {
        fprintf(stderr, "timer-daemon: %s has no ExecStart\n", service_name);
        free_unit_file(&unit);
        return -1;
    }

    /* Fork and exec */
    pid_t pid = fork();
    if (pid < 0) {
        free_unit_file(&unit);
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        /* Parse ExecStart into argv */
        char *argv[64];
        int argc = 0;
        char *cmd = strdup(unit.config.service.exec_start);
        char *token = strtok(cmd, " ");

        while (token && argc < 63) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        argv[argc] = NULL;

        /* Check if we have a command to execute */
        if (argc == 0 || argv[0] == NULL) {
            fprintf(stderr, "timer-daemon: invalid ExecStart for %s\n", service_name);
            free(cmd);
            exit(1);
        }

        /* Execute */
        execvp(argv[0], argv);

        /* If we get here, exec failed */
        perror("timer-daemon: exec");
        exit(1);
    }

    /* Parent */
    free_unit_file(&unit);
    fprintf(stderr, "timer-daemon: started %s directly (pid %d)\n", service_name, pid);
    return 0;
}

/* Activate a service (try supervisor, fall back to direct) */
static int activate_service(const char *service_name) {
    fprintf(stderr, "timer-daemon: activating %s\n", service_name);

    /* Try supervisor first */
    if (activate_via_supervisor(service_name) == 0) {
        return 0;
    }

    /* Fall back to direct activation */
    fprintf(stderr, "timer-daemon: supervisor unavailable, activating directly\n");
    return activate_direct(service_name);
}

static int update_timers_for_inactive_service(const char *service_name, time_t now) {
    int updated = 0;

    for (struct timer_instance *t = timers; t; t = t->next) {
        char derived_service[MAX_UNIT_NAME + 16];
        timer_service_name(t, derived_service, sizeof(derived_service));

        if (strcmp(derived_service, service_name) != 0) {
            continue;
        }

        t->last_inactive = now;
        t->next_run = calculate_next_run(t);
        updated++;
    }

    return updated;
}

/* Handle timer firing */
static int fire_timer(struct timer_instance *timer) {
    if (!timer->enabled) {
        return -1;
    }

    /* Determine service to activate */
    /* Timer name: backup.timer -> activate backup.service */
    char service_name[MAX_UNIT_NAME + 16];
    timer_service_name(timer, service_name, sizeof(service_name));

    fprintf(stderr, "timer-daemon: timer %s fired\n", timer->unit->name);

    int result = activate_service(service_name);
    if (result == 0) {
        timer->last_run = time(NULL);
        save_timer_state(timer);
        timer->last_inactive = 0;
    }

    /* Calculate next run */
    timer->next_run = calculate_next_run(timer);
    fprintf(stderr, "timer-daemon: next run for %s at %ld\n",
            timer->unit->name, timer->next_run);
    return result;
}

/* Check for timers that need to fire */
static void check_timers(void) {
    time_t now = time(NULL);

    for (struct timer_instance *t = timers; t; t = t->next) {
        if (!t->enabled || t->next_run == 0) {
            continue;
        }

        if (now >= t->next_run) {
            (void)fire_timer(t);
        }
    }
}

/* Check if timer should run on startup (persistent + missed) */
static bool should_run_on_startup(struct timer_instance *timer) {
    struct timer_section *t = &timer->unit->config.timer;

    if (!timer->enabled) {
        return false;
    }

    if (!t->persistent || timer->last_run == 0) {
        return false;
    }

    /* Check if we missed a scheduled run */
    time_t now = time(NULL);
    time_t next_after_last = calculate_next_run(timer);

    /* If the next scheduled run after last_run is in the past, we missed it */
    return next_after_last < now;
}

/* Load all timer units */
static int load_timers(void) {
    struct unit_file **units = NULL;
    int count = 0;

    /* Scan for timer units */
    if (scan_unit_directories(&units, &count) < 0) {
        return -1;
    }

    /* Filter for timer units only */
    for (int i = 0; i < count; i++) {
        if (units[i]->type != UNIT_TIMER) {
            free_unit_file(units[i]);
            free(units[i]);
            continue;
        }

        struct timer_instance *instance = calloc(1, sizeof(struct timer_instance));
        if (!instance) {
            continue;
        }

        instance->unit = units[i];
        instance->enabled = timer_unit_is_enabled(units[i]);
        units[i]->enabled = instance->enabled;
        instance->last_run = 0;

        /* Load saved state */
        load_timer_state(instance);

        /* Check for missed persistent timers */
        if (!instance->enabled) {
            instance->next_run = 0;
        } else if (should_run_on_startup(instance)) {
            fprintf(stderr, "timer-daemon: %s has persistent missed run, scheduling immediate activation\n",
                    units[i]->name);
            instance->next_run = time(NULL) + 5;  /* Run in 5 seconds */
        } else {
            /* Calculate initial next run */
            instance->next_run = calculate_next_run(instance);
        }

        /* Add to list */
        instance->next = timers;
        timers = instance;

        fprintf(stderr, "timer-daemon: loaded %s, next run at %ld\n",
                units[i]->name, instance->next_run);
    }

    free(units);
    return 0;
}

static int reload_timers(void) {
    free_timer_instances();
    return load_timers();
}

/* Handle control command */
/* Find timer by unit name */
static struct timer_instance *find_timer(const char *unit_name) {
    for (struct timer_instance *t = timers; t; t = t->next) {
        if (strcmp(t->unit->name, unit_name) == 0) {
            return t;
        }
    }
    return NULL;
}

static bool timer_command_is_read_only(enum control_command cmd) {
    switch (cmd) {
    case CMD_STATUS:
    case CMD_IS_ACTIVE:
    case CMD_IS_ENABLED:
    case CMD_LIST_TIMERS:
        return true;
    default:
        return false;
    }
}

static void handle_control_command(int client_fd, bool read_only) {
    struct control_request req = {0};
    struct control_response resp = {0};

    if (recv_control_request(client_fd, &req) < 0) {
        close(client_fd);
        return;
    }

    if (read_only && !timer_command_is_read_only(req.header.command)) {
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

    fprintf(stderr, "timer-daemon: received command %s for unit %s\n",
            command_to_string(req.header.command), req.unit_name);

    /* Set default response */
    resp.header.length = sizeof(resp);
    resp.header.command = req.header.command;
    resp.code = RESP_SUCCESS;

    struct timer_instance *timer = find_timer(req.unit_name);

    switch (req.header.command) {
    case CMD_START:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            timer->enabled = true;
            timer->next_run = time(NULL);
            if (fire_timer(timer) == 0) {
                resp.pid = -1;
                resp.state = UNIT_STATE_ACTIVE;
                snprintf(resp.message, sizeof(resp.message), "Triggered %s", req.unit_name);
            } else {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Failed to trigger %s", req.unit_name);
            }
        }
        break;

    case CMD_STOP:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            timer->enabled = false;
            timer->next_run = 0;
            resp.pid = -1;
            resp.state = UNIT_STATE_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "Stopped %s", req.unit_name);
        }
        break;

    case CMD_ENABLE:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            /* Send enable request to daemon */
            struct timer_request daemon_req = {0};
            struct timer_response daemon_resp = {0};

            daemon_req.type = TIMER_REQ_ENABLE_UNIT;
            strncpy(daemon_req.unit_name, timer->unit->name, sizeof(daemon_req.unit_name) - 1);
            strncpy(daemon_req.unit_path, timer->unit->path, sizeof(daemon_req.unit_path) - 1);

            if (send_timer_request(daemon_socket, &daemon_req) < 0 ||
                recv_timer_response(daemon_socket, &daemon_resp) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "IPC error");
            } else if (daemon_resp.type == TIMER_RESP_ERROR) {
                resp.code = RESP_FAILURE;
                /* Truncate to fit in message buffer */
                char short_name[64];
                char short_msg[200];
                strncpy(short_name, req.unit_name, sizeof(short_name) - 1);
                short_name[sizeof(short_name) - 1] = '\0';
                strncpy(short_msg, daemon_resp.error_msg, sizeof(short_msg) - 1);
                short_msg[sizeof(short_msg) - 1] = '\0';
                snprintf(resp.message, sizeof(resp.message), "Failed to enable %s: %s",
                        short_name, short_msg);
            } else {
                timer->enabled = true;
                timer->unit->enabled = true;
                if (timer->unit->config.timer.persistent && should_run_on_startup(timer)) {
                    timer->next_run = time(NULL) + 5;
                } else {
                    timer->next_run = calculate_next_run(timer);
                }
                resp.pid = -1;
                resp.state = UNIT_STATE_ACTIVE;
                snprintf(resp.message, sizeof(resp.message), "Enabled %s", req.unit_name);
            }
        }
        break;

    case CMD_DISABLE:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            /* Send disable request to daemon */
            struct timer_request daemon_req = {0};
            struct timer_response daemon_resp = {0};

            daemon_req.type = TIMER_REQ_DISABLE_UNIT;
            strncpy(daemon_req.unit_name, timer->unit->name, sizeof(daemon_req.unit_name) - 1);
            strncpy(daemon_req.unit_path, timer->unit->path, sizeof(daemon_req.unit_path) - 1);

            if (send_timer_request(daemon_socket, &daemon_req) < 0 ||
                recv_timer_response(daemon_socket, &daemon_resp) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "IPC error");
            } else if (daemon_resp.type == TIMER_RESP_ERROR) {
                resp.code = RESP_FAILURE;
                /* Truncate to fit in message buffer */
                char short_name[64];
                char short_msg[200];
                strncpy(short_name, req.unit_name, sizeof(short_name) - 1);
                short_name[sizeof(short_name) - 1] = '\0';
                strncpy(short_msg, daemon_resp.error_msg, sizeof(short_msg) - 1);
                short_msg[sizeof(short_msg) - 1] = '\0';
                snprintf(resp.message, sizeof(resp.message), "Failed to disable %s: %s",
                        short_name, short_msg);
            } else {
                timer->enabled = false;
                timer->unit->enabled = false;
                timer->next_run = 0;
                resp.pid = -1;
                resp.state = UNIT_STATE_INACTIVE;
                snprintf(resp.message, sizeof(resp.message), "Disabled %s", req.unit_name);
            }
        }
        break;

    case CMD_IS_ENABLED:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            bool enabled = timer_unit_is_enabled(timer->unit);
            timer->unit->enabled = enabled;
            resp.state = enabled ? UNIT_STATE_ACTIVE : UNIT_STATE_INACTIVE;
            resp.code = enabled ? RESP_SUCCESS : RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "%s", enabled ? "enabled" : "disabled");
        }
        break;

    case CMD_STATUS:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            char next_buf[64];
            char last_buf[64];
            format_time_iso(timer->next_run, next_buf, sizeof(next_buf));
            format_time_iso(timer->last_run, last_buf, sizeof(last_buf));
            resp.state = timer->enabled ? UNIT_STATE_ACTIVE : UNIT_STATE_INACTIVE;
            resp.pid = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "%s: %s (next %s, last %s)",
                     timer->unit->name,
                     timer->enabled ? "active" : "inactive",
                     next_buf,
                     last_buf);
        }
        break;

    case CMD_IS_ACTIVE:
        if (!timer) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Timer %s not found", req.unit_name);
        } else {
            resp.state = timer->enabled ? UNIT_STATE_ACTIVE : UNIT_STATE_INACTIVE;
            resp.pid = -1;
            resp.code = timer->enabled ? RESP_SUCCESS : RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "%s", timer->enabled ? "active" : "inactive");
        }
        break;

    case CMD_DAEMON_RELOAD:
        if (reload_timers() < 0) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Failed to reload timers");
        } else {
            resp.pid = -1;
            snprintf(resp.message, sizeof(resp.message), "Reloaded timers");
        }
        break;

    case CMD_LIST_TIMERS: {
        /* Build timer list */
        int count = 0;
        for (struct timer_instance *t = timers; t; t = t->next) {
            count++;
        }

        struct timer_list_entry *entries = calloc(count, sizeof(struct timer_list_entry));
        if (!entries) {
            resp.code = RESP_FAILURE;
            snprintf(resp.message, sizeof(resp.message), "Out of memory");
            send_control_response(client_fd, &resp);
            close(client_fd);
            return;
        }

        int idx = 0;
        for (struct timer_instance *t = timers; t; t = t->next) {
            strncpy(entries[idx].name, t->unit->name, sizeof(entries[idx].name) - 1);

            /* Determine service name */
            char *dot = strrchr(t->unit->name, '.');
            if (dot) {
                size_t len = dot - t->unit->name;
                strncpy(entries[idx].unit, t->unit->name, len);
                entries[idx].unit[len] = '\0';
                strcat(entries[idx].unit, ".service");
            } else {
                snprintf(entries[idx].unit, sizeof(entries[idx].unit),
                        "%s.service", t->unit->name);
            }

            entries[idx].next_run = t->next_run;
            entries[idx].last_run = t->last_run;
            entries[idx].state = t->enabled ? UNIT_STATE_ACTIVE : UNIT_STATE_INACTIVE;
            strncpy(entries[idx].description, t->unit->unit.description,
                   sizeof(entries[idx].description) - 1);
            idx++;
        }

        /* Send response then timer list */
        snprintf(resp.message, sizeof(resp.message), "Listing %d timers", count);
        send_control_response(client_fd, &resp);
        send_timer_list(client_fd, entries, count);

        free(entries);
        close(client_fd);
        return;
    }

    case CMD_NOTIFY_INACTIVE: {
        time_t now = time(NULL);
        int updated = update_timers_for_inactive_service(req.unit_name, now);

        resp.pid = -1;

        if (updated == 0) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message),
                     "No timers linked to %s", req.unit_name);
        } else {
            resp.code = RESP_SUCCESS;
            resp.state = UNIT_STATE_INACTIVE;
            snprintf(resp.message, sizeof(resp.message),
                     "Updated %d timer(s) for %s", updated, req.unit_name);
        }
        break;
    }

    default:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message),
                 "Timer daemon: command not yet implemented");
        break;
    }

    send_control_response(client_fd, &resp);
    close(client_fd);
}

/* Main event loop */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int event_loop(void) {
    struct pollfd fds[2];
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

    while (!shutdown_requested) {
        /* Poll with 1 second timeout for timer checks */
        int ret = poll(fds, nfds, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("timer-daemon: poll");
            return -1;
        }

        /* Check timers every iteration */
        check_timers();

        /* Handle control connections */
        if (ret > 0 && (fds[idx_control].revents & POLLIN)) {
            int client_fd = accept(control_socket, NULL, NULL);
            if (client_fd >= 0) {
                handle_control_command(client_fd, false);
            }
        }

        if (ret > 0 && idx_status >= 0 && (fds[idx_status].revents & POLLIN)) {
            int client_fd = accept(status_socket, NULL, NULL);
            if (client_fd >= 0) {
                handle_control_command(client_fd, true);
            }
        }
    }

    return 0;
}

#ifdef UNIT_TEST
int timer_daemon_test_add_instance(struct unit_file *unit,
                                   time_t last_run,
                                   time_t last_inactive,
                                   bool enabled) {
    struct timer_instance *instance = calloc(1, sizeof(struct timer_instance));
    if (!instance) {
        return -1;
    }

    instance->unit = unit;
    instance->last_run = last_run;
    instance->last_inactive = last_inactive;
    instance->enabled = enabled;
    instance->next_run = calculate_next_run(instance);
    instance->next = timers;
    timers = instance;
    return 0;
}

void timer_daemon_test_reset(void) {
    timer_daemon_test_clear_instances();
}

void timer_daemon_test_set_time_base(time_t boot, time_t start) {
    boot_time = boot;
    daemon_start_time = start;
}

int timer_daemon_test_notify_inactive(const char *service_name, time_t now) {
    return update_timers_for_inactive_service(service_name, now);
}

time_t timer_daemon_test_get_next_run(const char *timer_name) {
    struct timer_instance *timer = find_timer(timer_name);
    if (!timer) {
        return 0;
    }
    return timer->next_run;
}

time_t timer_daemon_test_get_last_inactive(const char *timer_name) {
    struct timer_instance *timer = find_timer(timer_name);
    if (!timer) {
        return 0;
    }
    return timer->last_inactive;
}

void timer_daemon_test_handle_control_fd(int fd) {
    handle_control_command(fd, false);
}

void timer_daemon_test_handle_status_fd(int fd) {
    handle_control_command(fd, true);
}
#endif

/* Get system boot time */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static time_t get_boot_time(void) {
    FILE *f = fopen("/proc/uptime", "r");
    if (f) {
        int fd = fileno(f);
        if (fd >= 0) {
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        double uptime;
        if (fscanf(f, "%lf", &uptime) == 1) {
            fclose(f);
            return time(NULL) - (time_t)uptime;
        }
        fclose(f);
    }

    /* Fallback: assume boot time is now */
    return time(NULL);
}

#ifndef UNIT_TEST
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "initd-timer-worker: usage: %s <ipc_fd>\n", argv[0]);
        return 1;
    }

    /* Get IPC socket FD from command line */
    daemon_socket = atoi(argv[1]);

    /* Initialize enhanced logging */
    log_enhanced_init("timer-worker", "/var/log/initd/timer.log");
    log_set_console_level(LOGLEVEL_INFO);
    log_set_file_level(LOGLEVEL_DEBUG);

    log_info("timer-worker", "Starting (ipc_fd=%d)", daemon_socket);

    /* Initialize time tracking */
    boot_time = get_boot_time();
    daemon_start_time = time(NULL);
    srand(daemon_start_time);

    log_debug("timer-worker", "boot_time=%ld, start_time=%ld",
              boot_time, daemon_start_time);

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    control_socket = create_control_socket();
    if (control_socket < 0) {
        return 1;
    }

    status_socket = create_status_socket();
    if (status_socket < 0) {
        close(control_socket);
        const char *ctrl_path = timer_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        return 1;
    }

    /* Load timer units */
    if (load_timers() < 0) {
        log_error("timer-worker", "failed to load timers");
        close(control_socket);
        close(status_socket);
        const char *ctrl_path = timer_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        const char *status_path = timer_socket_path(true);
        if (status_path) {
            unlink(status_path);
        }
        return 1;
    }

    /* Run event loop */
    log_debug("timer-worker", "Entering event loop");
    event_loop();

    /* Cleanup */
    log_info("timer-worker", "Shutting down");
    close(control_socket);
    const char *ctrl_path = timer_socket_path(false);
    if (ctrl_path) {
        unlink(ctrl_path);
    }
    if (status_socket >= 0) {
        close(status_socket);
        const char *status_path = timer_socket_path(true);
        if (status_path) {
            unlink(status_path);
        }
    }
    log_enhanced_close();
    free_timer_instances();

    return 0;
}
#endif
