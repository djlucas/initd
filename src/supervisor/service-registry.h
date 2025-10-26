/* service-registry.h - Service registry for tracking managed processes
 *
 * Maintains a registry of services started by the supervisor to prevent
 * arbitrary kill() attacks from compromised workers. Only services in
 * the registry can be stopped.
 *
 * Also provides resource exhaustion protection via:
 * - Max concurrent service limit (MAX_SERVICES)
 * - Per-service restart rate limiting
 * - Restart failure window tracking
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef SERVICE_REGISTRY_H
#define SERVICE_REGISTRY_H

#include <sys/types.h>
#include <time.h>
#include "../common/unit.h"

/* Resource limits for DoS prevention */
#define MAX_SERVICES 256            /* Maximum concurrent services */
#define MAX_RESTARTS_PER_WINDOW INITD_DEFAULT_START_LIMIT_BURST
#define RESTART_WINDOW_SEC INITD_DEFAULT_START_LIMIT_INTERVAL_SEC
#define MIN_RESTART_INTERVAL_SEC INITD_MIN_RESTART_INTERVAL_SEC
#define MAX_TRACKED_RESTARTS INITD_MAX_START_LIMIT_BURST_TRACK

/* Restart attempt tracking */
struct restart_tracker {
    time_t attempts[MAX_TRACKED_RESTARTS];     /* Timestamps of recent restart attempts */
    int attempt_count;                         /* Number of attempts in current window */
    time_t last_attempt;                       /* Timestamp of last restart attempt */
    int window_sec;                            /* Configured window in seconds */
    int max_restarts;                          /* Allowed restarts within window */
    int min_restart_interval_sec;              /* Minimum time between restarts */
    int start_limit_action;                    /* enum start_limit_action */
    char unit_name[256];
    int in_use;
};

struct service_record {
    pid_t pid;          /* Service PID */
    pid_t pgid;         /* Process group ID - POSIX portable */
    char unit_name[256];
    char unit_path[1024];
    int kill_mode;      /* KillMode from unit file */
    int in_use;         /* 1 if slot is active */
    int stdout_fd;      /* stdout pipe for output capture (-1 if none) */
    int stderr_fd;      /* stderr pipe for output capture (-1 if none) */
    struct restart_tracker restart_info;  /* DoS prevention: restart rate limiting */
#ifdef __linux__
    char cgroup_path[256];  /* Linux-only: cgroup v2 path (future use) */
#endif
};

/* Initialize the service registry */
void service_registry_init(void);

/* Add a service to the registry
 * Returns 0 on success, -1 if registry is full (DoS prevention)
 * stdout_fd and stderr_fd are pipe file descriptors for output capture (-1 if not used)
 */
int register_service(pid_t pid, const char *unit_name, const char *unit_path, int kill_mode,
                    int stdout_fd, int stderr_fd);

/* Lookup a service in the registry */
struct service_record *lookup_service(pid_t pid);

/* Lookup a service by unit name (for restart tracking) */
struct service_record *lookup_service_by_name(const char *unit_name);

/* Remove a service from the registry */
void unregister_service(pid_t pid);

/* Get the number of registered services (for testing) */
#ifdef UNIT_TEST
int service_registry_count(void);
#endif

/* DoS Prevention: Check if a service restart should be allowed
 * Returns 1 if restart is allowed, 0 if rate limited
 * Implements:
 * - Minimum restart interval (anti-spam)
 * - Maximum restarts per time window (anti-fork-bomb)
 */
int can_restart_service(const char *unit_name);

/* DoS Prevention: Record a restart attempt for rate limiting
 * Called before starting/restarting a service
 */
void record_restart_attempt(const char *unit_name);

void update_restart_limits(const char *unit_name,
                           int max_restarts,
                           int window_sec,
                           int min_interval_sec,
                           int start_limit_action);

int service_registry_update_pid(const char *unit_name, pid_t new_pid);

/* DoS Prevention: Check if registry has capacity for new service
 * Returns 1 if space available, 0 if at MAX_SERVICES limit
 */
int has_registry_capacity(void);

/* Get all service records (for pipe monitoring in main loop)
 * Returns pointer to internal registry array
 */
struct service_record *get_all_services(int *count);

#endif /* SERVICE_REGISTRY_H */
