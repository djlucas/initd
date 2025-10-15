/* service-registry.c - Service registry implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "service-registry.h"

static struct service_record service_registry[MAX_SERVICES];

/* Restart tracking per unit (indexed by unit name hash, simple approach) */
static struct restart_tracker restart_trackers[MAX_SERVICES];

/* Initialize the service registry */
void service_registry_init(void) {
    memset(service_registry, 0, sizeof(service_registry));
    memset(restart_trackers, 0, sizeof(restart_trackers));
}

/* Add a service to the registry */
int register_service(pid_t pid, const char *unit_name, int kill_mode) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (!service_registry[i].in_use) {
            service_registry[i].pid = pid;
            service_registry[i].pgid = pid;  /* After setsid(), PID == PGID */
            service_registry[i].kill_mode = kill_mode;
            service_registry[i].in_use = 1;
            strncpy(service_registry[i].unit_name, unit_name, sizeof(service_registry[i].unit_name) - 1);
            service_registry[i].unit_name[sizeof(service_registry[i].unit_name) - 1] = '\0';
            fprintf(stderr, "supervisor-master: registered service %s (pid=%d, pgid=%d)\n",
                    unit_name, pid, pid);
            return 0;
        }
    }
    fprintf(stderr, "supervisor-master: service registry full!\n");
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
            fprintf(stderr, "supervisor-master: unregistered service %s (pid=%d)\n",
                    service_registry[i].unit_name, pid);
            service_registry[i].in_use = 0;
            return;
        }
    }
}

/* Get the number of registered services (for testing) */
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
    int idx = hash_unit_name(unit_name);
    return &restart_trackers[idx];
}

/* DoS Prevention: Check if registry has capacity for new service */
int has_registry_capacity(void) {
    return service_registry_count() < MAX_SERVICES;
}

/* DoS Prevention: Check if a service restart should be allowed
 * Returns 1 if restart is allowed, 0 if rate limited */
int can_restart_service(const char *unit_name) {
    struct restart_tracker *tracker = get_restart_tracker(unit_name);
    time_t now = time(NULL);

    /* Check minimum interval since last attempt */
    if (tracker->last_attempt > 0) {
        time_t elapsed = now - tracker->last_attempt;
        if (elapsed < MIN_RESTART_INTERVAL_SEC) {
            fprintf(stderr, "supervisor-master: [DoS Prevention] %s restart too soon "
                    "(%ld sec < %d sec minimum)\n",
                    unit_name, (long)elapsed, MIN_RESTART_INTERVAL_SEC);
            return 0;  /* Rate limited: too fast */
        }
    }

    /* Clean up old attempts outside the time window */
    int valid_attempts = 0;
    for (int i = 0; i < tracker->attempt_count && i < MAX_RESTARTS_PER_WINDOW; i++) {
        if (now - tracker->attempts[i] < RESTART_WINDOW_SEC) {
            /* Still within window, keep it */
            if (valid_attempts != i) {
                tracker->attempts[valid_attempts] = tracker->attempts[i];
            }
            valid_attempts++;
        }
    }
    tracker->attempt_count = valid_attempts;

    /* Check if we've exceeded max restarts in window */
    if (tracker->attempt_count >= MAX_RESTARTS_PER_WINDOW) {
        time_t oldest = tracker->attempts[0];
        time_t window_age = now - oldest;
        fprintf(stderr, "supervisor-master: [DoS Prevention] %s exceeded restart limit "
                "(%d restarts in %ld sec < %d sec window)\n",
                unit_name, tracker->attempt_count, (long)window_age, RESTART_WINDOW_SEC);
        return 0;  /* Rate limited: too many attempts */
    }

    return 1;  /* Allowed */
}

/* DoS Prevention: Record a restart attempt for rate limiting */
void record_restart_attempt(const char *unit_name) {
    struct restart_tracker *tracker = get_restart_tracker(unit_name);
    time_t now = time(NULL);

    /* Record this attempt */
    if (tracker->attempt_count < MAX_RESTARTS_PER_WINDOW) {
        tracker->attempts[tracker->attempt_count] = now;
        tracker->attempt_count++;
    }

    tracker->last_attempt = now;

    fprintf(stderr, "supervisor-master: [DoS Prevention] %s restart attempt recorded "
            "(%d/%d in window)\n",
            unit_name, tracker->attempt_count, MAX_RESTARTS_PER_WINDOW);
}
