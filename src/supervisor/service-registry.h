/* service-registry.h - Service registry for tracking managed processes
 *
 * Maintains a registry of services started by the supervisor to prevent
 * arbitrary kill() attacks from compromised workers. Only services in
 * the registry can be stopped.
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef SERVICE_REGISTRY_H
#define SERVICE_REGISTRY_H

#include <sys/types.h>

#define MAX_SERVICES 256

struct service_record {
    pid_t pid;          /* Service PID */
    pid_t pgid;         /* Process group ID - POSIX portable */
    char unit_name[256];
    int kill_mode;      /* KillMode from unit file */
    int in_use;         /* 1 if slot is active */
#ifdef __linux__
    char cgroup_path[256];  /* Linux-only: cgroup v2 path (future use) */
#endif
};

/* Initialize the service registry */
void service_registry_init(void);

/* Add a service to the registry */
int register_service(pid_t pid, const char *unit_name, int kill_mode);

/* Lookup a service in the registry */
struct service_record *lookup_service(pid_t pid);

/* Remove a service from the registry */
void unregister_service(pid_t pid);

/* Get the number of registered services (for testing) */
int service_registry_count(void);

#endif /* SERVICE_REGISTRY_H */
