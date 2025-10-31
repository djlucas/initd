/* service-registry.c - Service registry implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "service-registry.h"

static struct service_record service_registry[MAX_SERVICES];

/* Restart tracking per unit (indexed by unit name hash, simple approach) */
static struct restart_tracker restart_trackers[MAX_SERVICES];
static time_t service_registry_boot_time;

/* Get monotonic time in seconds for restart tracking
 * Uses CLOCK_MONOTONIC which is unaffected by system clock changes */
static time_t get_monotonic_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        /* Fallback to wall clock if monotonic not available */
        return time(NULL);
    }
    return ts.tv_sec;
}

static int effective_window_sec(const struct restart_tracker *tracker) {
    int window = tracker->window_sec > 0 ? tracker->window_sec : RESTART_WINDOW_SEC;
    if (window < RESTART_WINDOW_SEC) {
        window = RESTART_WINDOW_SEC;
    }
    return window;
}

static int effective_max_restarts(const struct restart_tracker *tracker) {
    int max_restarts = tracker->max_restarts > 0 ? tracker->max_restarts : MAX_RESTARTS_PER_WINDOW;
    if (max_restarts < MAX_RESTARTS_PER_WINDOW) {
        max_restarts = MAX_RESTARTS_PER_WINDOW;
    }
    if (max_restarts > MAX_TRACKED_RESTARTS) {
        max_restarts = MAX_TRACKED_RESTARTS;
    }
    return max_restarts;
}

static int effective_min_interval(const struct restart_tracker *tracker) {
    int min_interval = tracker->min_restart_interval_sec > 0 ?
        tracker->min_restart_interval_sec : MIN_RESTART_INTERVAL_SEC;
    if (min_interval < MIN_RESTART_INTERVAL_SEC) {
        min_interval = MIN_RESTART_INTERVAL_SEC;
    }
    return min_interval;
}

static void release_restart_tracker(const char *unit_name);
/* Initialize the service registry */
void service_registry_init(void) {
    memset(service_registry, 0, sizeof(service_registry));
    memset(restart_trackers, 0, sizeof(restart_trackers));
    service_registry_boot_time = time(NULL);
}

/* Add a service to the registry */
int register_service(pid_t pid, const char *unit_name, const char *unit_path, int kill_mode,
                    int stdout_fd, int stderr_fd, int runtime_max_sec) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (!service_registry[i].in_use) {
            service_registry[i].pid = pid;
            service_registry[i].pgid = pid;  /* Child calls setsid(), so pgid == pid */
            service_registry[i].kill_mode = kill_mode;
            service_registry[i].in_use = 1;
            service_registry[i].stdout_fd = stdout_fd;
            service_registry[i].stderr_fd = stderr_fd;
            service_registry[i].start_time = time(NULL);
            service_registry[i].runtime_max_sec = runtime_max_sec;
            strncpy(service_registry[i].unit_name, unit_name, sizeof(service_registry[i].unit_name) - 1);
            service_registry[i].unit_name[sizeof(service_registry[i].unit_name) - 1] = '\0';
            if (unit_path) {
                strncpy(service_registry[i].unit_path, unit_path,
                        sizeof(service_registry[i].unit_path) - 1);
                service_registry[i].unit_path[sizeof(service_registry[i].unit_path) - 1] = '\0';
            } else {
                service_registry[i].unit_path[0] = '\0';
            }
            fprintf(stderr, "initd-supervisor: registered service %s (pid=%d, pgid=%d)\n",
                    unit_name, pid, service_registry[i].pgid);
            return 0;
        }
    }
    fprintf(stderr, "initd-supervisor: service registry full!\n");
    return -1;
}

/* Lookup a service in the registry */
struct service_record *lookup_service(pid_t pid) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (service_registry[i].in_use && service_registry[i].pid == pid) {
            return &service_registry[i];
        }
    }
    return NULL;
}

/* Remove a service from the registry */
void unregister_service(pid_t pid) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (service_registry[i].in_use && service_registry[i].pid == pid) {
            fprintf(stderr, "initd-supervisor: unregistered service %s (pid=%d)\n",
                    service_registry[i].unit_name, pid);
            char unit_name_copy[sizeof(service_registry[i].unit_name)];
            strncpy(unit_name_copy, service_registry[i].unit_name, sizeof(unit_name_copy));
            unit_name_copy[sizeof(unit_name_copy) - 1] = '\0';

            /* Close output pipes if open */
            if (service_registry[i].stdout_fd >= 0) {
                close(service_registry[i].stdout_fd);
                service_registry[i].stdout_fd = -1;
            }
            if (service_registry[i].stderr_fd >= 0) {
                close(service_registry[i].stderr_fd);
                service_registry[i].stderr_fd = -1;
            }

            service_registry[i].unit_path[0] = '\0';
            service_registry[i].in_use = 0;
            release_restart_tracker(unit_name_copy);
            return;
        }
    }
}

/* Get the number of registered services (for testing) */
#ifndef UNIT_TEST
static
#endif
int service_registry_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (service_registry[i].in_use) {
            count++;
        }
    }
    return count;
}

/* Lookup a service by unit name (for restart tracking) */
struct service_record *lookup_service_by_name(const char *unit_name) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (service_registry[i].in_use &&
            strcmp(service_registry[i].unit_name, unit_name) == 0) {
            return &service_registry[i];
        }
    }
    return NULL;
}

/* Simple hash function for unit name to restart tracker index */
static int hash_unit_name(const char *unit_name) {
    unsigned long hash = 5381;
    int c;
    while ((c = *unit_name++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % MAX_SERVICES;
}

/* Get restart tracker for a unit (creates if doesn't exist) */
static struct restart_tracker *get_restart_tracker(const char *unit_name) {
    if (!unit_name || unit_name[0] == '\0') {
        return NULL;
    }

    int idx = hash_unit_name(unit_name);

    for (int i = 0; i < MAX_SERVICES; i++) {
        int slot = (idx + i) % MAX_SERVICES;
        struct restart_tracker *tracker = &restart_trackers[slot];

        if (tracker->in_use) {
            if (strncmp(tracker->unit_name, unit_name, sizeof(tracker->unit_name)) == 0) {
                return tracker;
            }
            continue;
        }

        /* Claim unused slot */
        tracker->in_use = 1;
        tracker->attempt_count = 0;
        tracker->last_attempt = 0;  /* No prior attempts, allow immediate start */
        memset(tracker->attempts, 0, sizeof(tracker->attempts));
        tracker->window_sec = RESTART_WINDOW_SEC;
        tracker->max_restarts = MAX_RESTARTS_PER_WINDOW;
        tracker->min_restart_interval_sec = MIN_RESTART_INTERVAL_SEC;
        tracker->start_limit_action = START_LIMIT_ACTION_NONE;
        strncpy(tracker->unit_name, unit_name, sizeof(tracker->unit_name) - 1);
        tracker->unit_name[sizeof(tracker->unit_name) - 1] = '\0';
        return tracker;
    }

    return NULL;
}

static void release_restart_tracker(const char *unit_name) {
    if (!unit_name || unit_name[0] == '\0') {
        return;
    }

    int idx = hash_unit_name(unit_name);

    for (int i = 0; i < MAX_SERVICES; i++) {
        int slot = (idx + i) % MAX_SERVICES;
        struct restart_tracker *tracker = &restart_trackers[slot];

        if (tracker->in_use &&
            strncmp(tracker->unit_name, unit_name, sizeof(tracker->unit_name)) == 0) {
            memset(tracker, 0, sizeof(*tracker));
            return;
        }

        if (!tracker->in_use) {
            return;
        }
    }
}

/* DoS Prevention: Check if registry has capacity for new service */
int has_registry_capacity(void) {
    return service_registry_count() < MAX_SERVICES;
}

/* Get all service records for iteration */
struct service_record *get_all_services(int *count) {
    if (count) {
        *count = MAX_SERVICES;
    }
    return service_registry;
}

/* DoS Prevention: Check if a service restart should be allowed
 * Returns 1 if restart is allowed, 0 if rate limited */
int can_restart_service(const char *unit_name) {
    struct restart_tracker *tracker = get_restart_tracker(unit_name);
    if (!tracker) {
        fprintf(stderr, "initd-supervisor: [DoS Prevention] restart tracker table full, treating %s as denied\n",
                unit_name ? unit_name : "<null>");
        return 0;
    }
    time_t now = get_monotonic_time();
    int min_interval = effective_min_interval(tracker);
    int window_sec = effective_window_sec(tracker);
    int max_restarts = effective_max_restarts(tracker);

    /* Check minimum interval since last attempt */
    if (tracker->last_attempt > 0) {
        time_t elapsed = now - tracker->last_attempt;
        if (elapsed < min_interval) {
            fprintf(stderr, "initd-supervisor: [DoS Prevention] %s restart too soon "
                    "(%ld sec < %d sec minimum)\n",
                    unit_name, (long)elapsed, min_interval);
            return 0;  /* Rate limited: too fast */
        }
    }

    /* Clean up old attempts outside the time window */
    int valid_attempts = 0;
    for (int i = 0; i < tracker->attempt_count && i < MAX_TRACKED_RESTARTS; i++) {
        if (now - tracker->attempts[i] < window_sec) {
            /* Still within window, keep it */
            if (valid_attempts != i) {
                tracker->attempts[valid_attempts] = tracker->attempts[i];
            }
            valid_attempts++;
        }
    }
    tracker->attempt_count = valid_attempts;
    if (tracker->attempt_count > max_restarts) {
        tracker->attempt_count = max_restarts;
    }

    /* Check if we've exceeded max restarts in window */
    if (tracker->attempt_count >= max_restarts) {
        time_t oldest = tracker->attempts[0];
        time_t window_age = now - oldest;
        fprintf(stderr, "initd-supervisor: [DoS Prevention] %s exceeded restart limit "
                "(%d restarts in %ld sec < %d sec window)\n",
                unit_name, tracker->attempt_count, (long)window_age, window_sec);
        if (tracker->start_limit_action != START_LIMIT_ACTION_NONE) {
            fprintf(stderr, "initd-supervisor: StartLimitAction=%d requested but not implemented; ignoring\n",
                    tracker->start_limit_action);
        }
        return 0;  /* Rate limited: too many attempts */
    }

    return 1;  /* Allowed */
}

/* DoS Prevention: Record a restart attempt for rate limiting */
void record_restart_attempt(const char *unit_name) {
    struct restart_tracker *tracker = get_restart_tracker(unit_name);
    if (!tracker) {
        fprintf(stderr, "initd-supervisor: [DoS Prevention] restart tracker table full, tracking disabled for %s\n",
                unit_name ? unit_name : "<null>");
        return;
    }
    time_t now = get_monotonic_time();
    int max_restarts = effective_max_restarts(tracker);

    /* Record this attempt */
    if (tracker->attempt_count < max_restarts) {
        tracker->attempts[tracker->attempt_count] = now;
        tracker->attempt_count++;
    } else if (max_restarts > 0) {
        memmove(&tracker->attempts[0], &tracker->attempts[1],
                (size_t)(max_restarts - 1) * sizeof(time_t));
        tracker->attempts[max_restarts - 1] = now;
        tracker->attempt_count = max_restarts;
    }

    tracker->last_attempt = now;

    fprintf(stderr, "initd-supervisor: [DoS Prevention] %s restart attempt recorded "
            "(%d/%d in window)\n",
            unit_name, tracker->attempt_count, max_restarts);
}

void update_restart_limits(const char *unit_name,
                           int max_restarts,
                           int window_sec,
                           int min_interval_sec,
                           int start_limit_action) {
    struct restart_tracker *tracker = get_restart_tracker(unit_name);
    if (!tracker) {
        return;
    }

    if (max_restarts > 0 && max_restarts < MAX_RESTARTS_PER_WINDOW) {
        max_restarts = MAX_RESTARTS_PER_WINDOW;
    }
    if (max_restarts <= 0) {
        max_restarts = MAX_RESTARTS_PER_WINDOW;
    }
    if (max_restarts > MAX_TRACKED_RESTARTS) {
        max_restarts = MAX_TRACKED_RESTARTS;
    }
    tracker->max_restarts = max_restarts;
    if (tracker->attempt_count > tracker->max_restarts) {
        tracker->attempt_count = tracker->max_restarts;
    }

    if (window_sec > 0 && window_sec < RESTART_WINDOW_SEC) {
        window_sec = RESTART_WINDOW_SEC;
    }
    if (window_sec <= 0) {
        window_sec = RESTART_WINDOW_SEC;
    }
    tracker->window_sec = window_sec;

    if (min_interval_sec > 0 && min_interval_sec < MIN_RESTART_INTERVAL_SEC) {
        min_interval_sec = MIN_RESTART_INTERVAL_SEC;
    }
    if (min_interval_sec <= 0) {
        min_interval_sec = MIN_RESTART_INTERVAL_SEC;
    }
    tracker->min_restart_interval_sec = min_interval_sec;

    switch (start_limit_action) {
    case START_LIMIT_ACTION_REBOOT:
    case START_LIMIT_ACTION_REBOOT_FORCE:
    case START_LIMIT_ACTION_EXIT_FORCE:
    case START_LIMIT_ACTION_REBOOT_IMMEDIATE:
        tracker->start_limit_action = start_limit_action;
        break;
    default:
        tracker->start_limit_action = START_LIMIT_ACTION_NONE;
        break;
    }
}

int service_registry_update_pid(const char *unit_name, pid_t new_pid) {
    if (!unit_name || unit_name[0] == '\0' || new_pid <= 0) {
        return -1;
    }

    struct service_record *svc = lookup_service_by_name(unit_name);
    if (!svc) {
        return -1;
    }

    svc->pid = new_pid;
    svc->pgid = new_pid;
    return 0;
}

/* Check and enforce RuntimeMaxSec= timeouts
 * Returns PID of service to kill, or 0 if none
 */
pid_t check_runtime_timeout(char *unit_name_out, size_t unit_name_size) {
    time_t now = time(NULL);

    for (int i = 0; i < MAX_SERVICES; i++) {
        if (service_registry[i].in_use && service_registry[i].runtime_max_sec > 0) {
            time_t runtime = now - service_registry[i].start_time;
            if (runtime >= service_registry[i].runtime_max_sec) {
                if (unit_name_out && unit_name_size > 0) {
                    strncpy(unit_name_out, service_registry[i].unit_name, unit_name_size - 1);
                    unit_name_out[unit_name_size - 1] = '\0';
                }
                return service_registry[i].pid;
            }
        }
    }
    return 0;
}
