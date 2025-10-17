/* parser.c - Unit file parser
 *
 * Parses systemd-compatible INI format unit files
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "unit.h"

#define MAX_LINE 1024

/* Current section being parsed */
enum parse_section {
    SECTION_NONE,
    SECTION_UNIT,
    SECTION_SERVICE,
    SECTION_TIMER,
    SECTION_SOCKET,
    SECTION_INSTALL
};

/* Trim whitespace from string */
static char *trim(char *str) {
    char *end;

    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

/* Parse space-separated list into array */
static int parse_list(char *value, char **array, int max_count) {
    int count = 0;
    char *token = strtok(value, " \t");

    while (token && count < max_count) {
        array[count++] = strdup(token);
        token = strtok(NULL, " \t");
    }

    return count;
}

/* Parse [Unit] section key/value */
static int parse_unit_key(struct unit_section *unit, const char *key, char *value) {
    if (strcmp(key, "Description") == 0) {
        strncpy(unit->description, value, sizeof(unit->description) - 1);
    } else if (strcmp(key, "After") == 0) {
        unit->after_count = parse_list(value, unit->after, MAX_DEPS);
    } else if (strcmp(key, "Before") == 0) {
        unit->before_count = parse_list(value, unit->before, MAX_DEPS);
    } else if (strcmp(key, "Requires") == 0) {
        unit->requires_count = parse_list(value, unit->requires, MAX_DEPS);
    } else if (strcmp(key, "Wants") == 0) {
        unit->wants_count = parse_list(value, unit->wants, MAX_DEPS);
    } else if (strcmp(key, "Conflicts") == 0) {
        unit->conflicts_count = parse_list(value, unit->conflicts, MAX_DEPS);
    } else if (strcmp(key, "Provides") == 0) {
        unit->provides_count = parse_list(value, unit->provides, MAX_DEPS);
    } else {
        return -1; /* Unknown key */
    }
    return 0;
}

/* Parse [Service] section key/value */
static int parse_service_key(struct service_section *service, const char *key, char *value) {
    if (strcmp(key, "Type") == 0) {
        if (strcmp(value, "simple") == 0) service->type = SERVICE_SIMPLE;
        else if (strcmp(value, "forking") == 0) service->type = SERVICE_FORKING;
        else if (strcmp(value, "oneshot") == 0) service->type = SERVICE_ONESHOT;
    } else if (strcmp(key, "ExecStart") == 0) {
        service->exec_start = strdup(value);
    } else if (strcmp(key, "ExecStop") == 0) {
        service->exec_stop = strdup(value);
    } else if (strcmp(key, "ExecReload") == 0) {
        service->exec_reload = strdup(value);
    } else if (strcmp(key, "ExecStartPre") == 0) {
        service->exec_start_pre = strdup(value);
    } else if (strcmp(key, "ExecStartPost") == 0) {
        service->exec_start_post = strdup(value);
    } else if (strcmp(key, "User") == 0) {
        strncpy(service->user, value, sizeof(service->user) - 1);
    } else if (strcmp(key, "Group") == 0) {
        strncpy(service->group, value, sizeof(service->group) - 1);
    } else if (strcmp(key, "WorkingDirectory") == 0) {
        strncpy(service->working_directory, value, sizeof(service->working_directory) - 1);
    } else if (strcmp(key, "Environment") == 0) {
        if (service->environment_count < MAX_ENV_VARS) {
            service->environment[service->environment_count++] = strdup(value);
        }
    } else if (strcmp(key, "EnvironmentFile") == 0) {
        service->environment_file = strdup(value);
    } else if (strcmp(key, "Restart") == 0) {
        if (strcmp(value, "no") == 0) service->restart = RESTART_NO;
        else if (strcmp(value, "always") == 0) service->restart = RESTART_ALWAYS;
        else if (strcmp(value, "on-failure") == 0) service->restart = RESTART_ON_FAILURE;
    } else if (strcmp(key, "RestartSec") == 0) {
        service->restart_sec = atoi(value);
    } else if (strcmp(key, "TimeoutStartSec") == 0) {
        service->timeout_start_sec = atoi(value);
    } else if (strcmp(key, "TimeoutStopSec") == 0) {
        service->timeout_stop_sec = atoi(value);
    } else if (strcmp(key, "RuntimeMaxSec") == 0) {
        service->runtime_max_sec = atoi(value);
    } else if (strcmp(key, "PrivateTmp") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0) {
            service->private_tmp = true;
        } else {
            service->private_tmp = false;
        }
    } else if (strcmp(key, "KillMode") == 0) {
        if (strcmp(value, "control-group") == 0) service->kill_mode = KILL_CONTROL_GROUP;
        else if (strcmp(value, "process") == 0) service->kill_mode = KILL_PROCESS;
        else if (strcmp(value, "mixed") == 0) service->kill_mode = KILL_MIXED;
        else if (strcmp(value, "none") == 0) service->kill_mode = KILL_NONE;
        else service->kill_mode = KILL_PROCESS; /* Default to process */
    } else if (strcmp(key, "LimitNOFILE") == 0) {
        if (strcmp(value, "infinity") == 0) {
            service->limit_nofile = 0; /* 0 = unlimited */
        } else {
            service->limit_nofile = atoi(value);
        }
    } else {
        return -1; /* Unknown key */
    }
    return 0;
}

/* Parse [Timer] section key/value */
static int parse_timer_key(struct timer_section *timer, const char *key, char *value) {
    if (strcmp(key, "OnCalendar") == 0) {
        timer->on_calendar = strdup(value);
    } else if (strcmp(key, "OnBootSec") == 0) {
        timer->on_boot_sec = atoi(value);
    } else if (strcmp(key, "OnStartupSec") == 0) {
        timer->on_startup_sec = atoi(value);
    } else if (strcmp(key, "OnUnitActiveSec") == 0) {
        timer->on_unit_active_sec = atoi(value);
    } else if (strcmp(key, "OnUnitInactiveSec") == 0) {
        timer->on_unit_inactive_sec = atoi(value);
    } else if (strcmp(key, "Persistent") == 0) {
        timer->persistent = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "RandomizedDelaySec") == 0) {
        timer->randomized_delay_sec = atoi(value);
    } else {
        return -1;
    }
    return 0;
}

/* Parse [Socket] section key/value */
static int parse_socket_key(struct socket_section *socket, const char *key, char *value) {
    if (strcmp(key, "ListenStream") == 0) {
        socket->listen_stream = strdup(value);
    } else if (strcmp(key, "ListenDatagram") == 0) {
        socket->listen_datagram = strdup(value);
    } else if (strcmp(key, "IdleTimeout") == 0) {
        socket->idle_timeout = atoi(value);
    } else {
        return -1;
    }
    return 0;
}

/* Parse [Install] section key/value */
static int parse_install_key(struct install_section *install, const char *key, char *value) {
    if (strcmp(key, "WantedBy") == 0) {
        install->wanted_by_count = parse_list(value, install->wanted_by, MAX_DEPS);
    } else if (strcmp(key, "RequiredBy") == 0) {
        install->required_by_count = parse_list(value, install->required_by, MAX_DEPS);
    } else {
        return -1;
    }
    return 0;
}

/* Determine unit type from filename */
static enum unit_type get_unit_type(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return UNIT_SERVICE; /* Default */

    if (strcmp(dot, ".service") == 0) return UNIT_SERVICE;
    if (strcmp(dot, ".target") == 0) return UNIT_TARGET;
    if (strcmp(dot, ".timer") == 0) return UNIT_TIMER;
    if (strcmp(dot, ".socket") == 0) return UNIT_SOCKET;

    return UNIT_SERVICE; /* Default */
}

/* Parse unit file */
int parse_unit_file(const char *path, struct unit_file *unit) {
    FILE *f;
    char line[MAX_LINE];
    enum parse_section current_section = SECTION_NONE;

    f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    int fd = fileno(f);
    if (fd >= 0) {
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    /* Initialize unit */
    memset(unit, 0, sizeof(*unit));
    strncpy(unit->path, path, sizeof(unit->path) - 1);

    /* Extract unit name from path */
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    strncpy(unit->name, name, sizeof(unit->name) - 1);

    /* Set defaults for new fields */
    unit->config.service.kill_mode = KILL_PROCESS;  /* Default: only kill main process */
    unit->config.service.limit_nofile = -1;         /* Default: not set (inherit system default) */
    unit->config.service.private_tmp = false;        /* Default: no private /tmp */
    unit->config.service.runtime_max_sec = 0;        /* Default: unlimited */

    /* Determine type from extension */
    unit->type = get_unit_type(name);

    /* Parse file */
    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        /* Check for section header */
        if (*trimmed == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *section_name = trimmed + 1;

                if (strcmp(section_name, "Unit") == 0) {
                    current_section = SECTION_UNIT;
                } else if (strcmp(section_name, "Service") == 0) {
                    current_section = SECTION_SERVICE;
                } else if (strcmp(section_name, "Timer") == 0) {
                    current_section = SECTION_TIMER;
                } else if (strcmp(section_name, "Socket") == 0) {
                    current_section = SECTION_SOCKET;
                } else if (strcmp(section_name, "Install") == 0) {
                    current_section = SECTION_INSTALL;
                } else {
                    current_section = SECTION_NONE;
                }
            }
            continue;
        }

        /* Parse key=value */
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);

        /* Dispatch to section parser */
        switch (current_section) {
        case SECTION_UNIT:
            parse_unit_key(&unit->unit, key, value);
            break;
        case SECTION_SERVICE:
            parse_service_key(&unit->config.service, key, value);
            break;
        case SECTION_TIMER:
            parse_timer_key(&unit->config.timer, key, value);
            break;
        case SECTION_SOCKET:
            parse_socket_key(&unit->config.socket, key, value);
            break;
        case SECTION_INSTALL:
            parse_install_key(&unit->install, key, value);
            break;
        default:
            break;
        }
    }

    fclose(f);
    return 0;
}

/* Validate unit file */
int validate_unit_file(const struct unit_file *unit) {
    /* Check for required fields based on type */
    if (unit->type == UNIT_SERVICE) {
        if (!unit->config.service.exec_start) {
            fprintf(stderr, "validate: %s: missing ExecStart\n", unit->name);
            return -1;
        }
    }

    /* Socket units need a listen directive */
    if (unit->type == UNIT_SOCKET) {
        if (!unit->config.socket.listen_stream && !unit->config.socket.listen_datagram) {
            fprintf(stderr, "validate: %s: missing Listen directive\n", unit->name);
            return -1;
        }
    }

    /* Timer units need at least one timer */
    if (unit->type == UNIT_TIMER) {
        if (!unit->config.timer.on_calendar &&
            unit->config.timer.on_boot_sec == 0 &&
            unit->config.timer.on_startup_sec == 0 &&
            unit->config.timer.on_unit_active_sec == 0 &&
            unit->config.timer.on_unit_inactive_sec == 0) {
            fprintf(stderr, "validate: %s: missing timer specification\n", unit->name);
            return -1;
        }
    }

    return 0;
}

/* Free unit file resources */
void free_unit_file(struct unit_file *unit) {
    /* Free [Unit] arrays */
    for (int i = 0; i < unit->unit.after_count; i++) free(unit->unit.after[i]);
    for (int i = 0; i < unit->unit.before_count; i++) free(unit->unit.before[i]);
    for (int i = 0; i < unit->unit.requires_count; i++) free(unit->unit.requires[i]);
    for (int i = 0; i < unit->unit.wants_count; i++) free(unit->unit.wants[i]);
    for (int i = 0; i < unit->unit.conflicts_count; i++) free(unit->unit.conflicts[i]);
    for (int i = 0; i < unit->unit.provides_count; i++) free(unit->unit.provides[i]);

    /* Free [Service] fields */
    if (unit->type == UNIT_SERVICE) {
        free(unit->config.service.exec_start);
        free(unit->config.service.exec_stop);
        free(unit->config.service.exec_reload);
        free(unit->config.service.exec_start_pre);
        free(unit->config.service.exec_start_post);
        free(unit->config.service.environment_file);
        for (int i = 0; i < unit->config.service.environment_count; i++) {
            free(unit->config.service.environment[i]);
        }
    }

    /* Free [Timer] fields */
    if (unit->type == UNIT_TIMER) {
        free(unit->config.timer.on_calendar);
    }

    /* Free [Socket] fields */
    if (unit->type == UNIT_SOCKET) {
        free(unit->config.socket.listen_stream);
        free(unit->config.socket.listen_datagram);
    }

    /* Free [Install] arrays */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        free(unit->install.wanted_by[i]);
    }
    for (int i = 0; i < unit->install.required_by_count; i++) {
        free(unit->install.required_by[i]);
    }
}
