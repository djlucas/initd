/* service-registry.c - Service registry implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include "service-registry.h"

static struct service_record service_registry[MAX_SERVICES];

/* Initialize the service registry */
void service_registry_init(void) {
    memset(service_registry, 0, sizeof(service_registry));
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
