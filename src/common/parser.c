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
#include <strings.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include "unit.h"

#define MAX_LINE 1024

/* Base64 decoding table */
static const unsigned char base64_decode_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
    ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57,
    ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
    ['+'] = 62, ['/'] = 63
};

/* Simple base64 decoder (RFC 2045) - ignores whitespace */
static size_t base64_decode(const char *input, size_t input_len, char *output, size_t output_max) {
    size_t out_pos = 0;
    unsigned char buffer[4];
    int buffer_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = (unsigned char)input[i];

        /* Skip whitespace */
        if (isspace(c)) continue;

        /* End on padding */
        if (c == '=') break;

        /* Invalid character */
        if (!isalnum(c) && c != '+' && c != '/') return 0;

        buffer[buffer_pos++] = base64_decode_table[c];

        if (buffer_pos == 4) {
            if (out_pos + 3 > output_max) return 0; /* Buffer too small */

            output[out_pos++] = (buffer[0] << 2) | (buffer[1] >> 4);
            output[out_pos++] = (buffer[1] << 4) | (buffer[2] >> 2);
            output[out_pos++] = (buffer[2] << 6) | buffer[3];

            buffer_pos = 0;
        }
    }

    /* Handle remaining bytes */
    if (buffer_pos >= 2) {
        if (out_pos + 1 > output_max) return 0;
        output[out_pos++] = (buffer[0] << 2) | (buffer[1] >> 4);

        if (buffer_pos >= 3) {
            if (out_pos + 1 > output_max) return 0;
            output[out_pos++] = (buffer[1] << 4) | (buffer[2] >> 2);
        }
    }

    return out_pos;
}

/* Parse resource limit value (handles "infinity" and numeric values) */
static long parse_limit_value(const char *value) {
    if (strcmp(value, "infinity") == 0) {
        return 0; /* 0 = unlimited */
    }
    return atol(value);
}

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

static bool parse_boolean(const char *value) {
    if (!value) return false;
    if (strcasecmp(value, "true") == 0) return true;
    if (strcasecmp(value, "yes") == 0) return true;
    if (strcasecmp(value, "on") == 0) return true;
    if (strcmp(value, "1") == 0) return true;
    return false;
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

static void append_string(char **array, int max_count, int *count, const char *value) {
    if (!array || !count || !value) {
        return;
    }
    if (*count >= max_count) {
        return;
    }
    array[*count] = strdup(value);
    if (array[*count]) {
        (*count)++;
    }
}

/* Add condition entry */
static int add_condition(struct unit_section *unit, enum unit_condition_type type, const char *value, bool is_assert) {
    if (unit->condition_count >= MAX_CONDITIONS || !value || value[0] == '\0') {
        return -1;
    }

    struct unit_condition *cond = &unit->conditions[unit->condition_count];
    const char *path = value;

    cond->negate = false;
    if (path[0] == '!' && path[1] != '\0') {
        cond->negate = true;
        path++;
    }

    cond->value = strdup(path);
    if (!cond->value) {
        return -1;
    }

    cond->type = type;
    cond->is_assert = is_assert;
    unit->condition_count++;
    return 0;
}

static void parse_status_list(const char *value, int *array, int *count) {
    if (!value || !array || !count) {
        return;
    }

    *count = 0;
    char *copy = strdup(value);
    if (!copy) {
        return;
    }

    char *saveptr = NULL;
    char *token = strtok_r(copy, " \t", &saveptr);
    while (token && *count < MAX_RESTART_STATUS) {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(token, &end, 0);
        if (errno == 0 && end && *end == '\0') {
            array[*count] = (int)parsed;
            (*count)++;
        }
        token = strtok_r(NULL, " \t", &saveptr);
    }

    free(copy);
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
    } else if (strcmp(key, "OnFailure") == 0) {
        unit->on_failure_count = parse_list(value, unit->on_failure, MAX_DEPS);
    } else if (strcmp(key, "BindsTo") == 0) {
        unit->binds_to_count = parse_list(value, unit->binds_to, MAX_DEPS);
    } else if (strcmp(key, "PartOf") == 0) {
        unit->part_of_count = parse_list(value, unit->part_of, MAX_DEPS);
    } else if (strcmp(key, "StopWhenUnneeded") == 0) {
        unit->stop_when_unneeded = parse_boolean(value);
    } else if (strcmp(key, "RefuseManualStart") == 0) {
        unit->refuse_manual_start = parse_boolean(value);
    } else if (strcmp(key, "RefuseManualStop") == 0) {
        unit->refuse_manual_stop = parse_boolean(value);
    } else if (strcmp(key, "AllowIsolate") == 0) {
        unit->allow_isolate = parse_boolean(value);
    } else if (strcmp(key, "DefaultDependencies") == 0) {
        unit->default_dependencies = parse_boolean(value);
    } else if (strcmp(key, "StartLimitIntervalSec") == 0) {
        unit->start_limit_interval_sec = atoi(value);
        unit->start_limit_interval_set = true;
    } else if (strcmp(key, "StartLimitBurst") == 0) {
        unit->start_limit_burst = atoi(value);
        unit->start_limit_burst_set = true;
    } else if (strcmp(key, "StartLimitAction") == 0) {
        if (strcasecmp(value, "reboot") == 0) {
            unit->start_limit_action = START_LIMIT_ACTION_REBOOT;
            unit->start_limit_action_set = true;
        } else if (strcasecmp(value, "reboot-force") == 0) {
            unit->start_limit_action = START_LIMIT_ACTION_REBOOT_FORCE;
            unit->start_limit_action_set = true;
        } else if (strcasecmp(value, "exit-force") == 0) {
            unit->start_limit_action = START_LIMIT_ACTION_EXIT_FORCE;
            unit->start_limit_action_set = true;
        } else if (strcasecmp(value, "reboot-immediate") == 0) {
            unit->start_limit_action = START_LIMIT_ACTION_REBOOT_IMMEDIATE;
            unit->start_limit_action_set = true;
        } else {
            unit->start_limit_action = START_LIMIT_ACTION_NONE;
            unit->start_limit_action_set = true;
        }
    } else if (strcmp(key, "ConditionPathExists") == 0) {
        add_condition(unit, CONDITION_PATH_EXISTS, value, false);
    } else if (strcmp(key, "ConditionPathExistsGlob") == 0) {
        add_condition(unit, CONDITION_PATH_EXISTS_GLOB, value, false);
    } else if (strcmp(key, "ConditionPathIsDirectory") == 0) {
        add_condition(unit, CONDITION_PATH_IS_DIRECTORY, value, false);
    } else if (strcmp(key, "ConditionPathIsSymbolicLink") == 0) {
        add_condition(unit, CONDITION_PATH_IS_SYMBOLIC_LINK, value, false);
    } else if (strcmp(key, "ConditionPathIsMountPoint") == 0) {
        add_condition(unit, CONDITION_PATH_IS_MOUNT_POINT, value, false);
    } else if (strcmp(key, "ConditionPathIsReadWrite") == 0) {
        add_condition(unit, CONDITION_PATH_IS_READ_WRITE, value, false);
    } else if (strcmp(key, "ConditionDirectoryNotEmpty") == 0) {
        add_condition(unit, CONDITION_DIRECTORY_NOT_EMPTY, value, false);
    } else if (strcmp(key, "ConditionFileIsExecutable") == 0) {
        add_condition(unit, CONDITION_FILE_IS_EXECUTABLE, value, false);
    } else if (strcmp(key, "ConditionFileNotEmpty") == 0) {
        add_condition(unit, CONDITION_FILE_NOT_EMPTY, value, false);
    } else if (strcmp(key, "ConditionUser") == 0) {
        add_condition(unit, CONDITION_USER, value, false);
    } else if (strcmp(key, "ConditionGroup") == 0) {
        add_condition(unit, CONDITION_GROUP, value, false);
    } else if (strcmp(key, "ConditionHost") == 0) {
        add_condition(unit, CONDITION_HOST, value, false);
    } else if (strcmp(key, "ConditionArchitecture") == 0) {
        add_condition(unit, CONDITION_ARCHITECTURE, value, false);
    } else if (strcmp(key, "ConditionMemory") == 0) {
        add_condition(unit, CONDITION_MEMORY, value, false);
    } else if (strcmp(key, "ConditionCPUs") == 0) {
        add_condition(unit, CONDITION_CPUS, value, false);
    } else if (strcmp(key, "ConditionEnvironment") == 0) {
        add_condition(unit, CONDITION_ENVIRONMENT, value, false);
    } else if (strcmp(key, "AssertPathExists") == 0) {
        add_condition(unit, CONDITION_PATH_EXISTS, value, true);
    } else if (strcmp(key, "AssertPathExistsGlob") == 0) {
        add_condition(unit, CONDITION_PATH_EXISTS_GLOB, value, true);
    } else if (strcmp(key, "AssertPathIsDirectory") == 0) {
        add_condition(unit, CONDITION_PATH_IS_DIRECTORY, value, true);
    } else if (strcmp(key, "AssertPathIsSymbolicLink") == 0) {
        add_condition(unit, CONDITION_PATH_IS_SYMBOLIC_LINK, value, true);
    } else if (strcmp(key, "AssertPathIsMountPoint") == 0) {
        add_condition(unit, CONDITION_PATH_IS_MOUNT_POINT, value, true);
    } else if (strcmp(key, "AssertPathIsReadWrite") == 0) {
        add_condition(unit, CONDITION_PATH_IS_READ_WRITE, value, true);
    } else if (strcmp(key, "AssertDirectoryNotEmpty") == 0) {
        add_condition(unit, CONDITION_DIRECTORY_NOT_EMPTY, value, true);
    } else if (strcmp(key, "AssertFileIsExecutable") == 0) {
        add_condition(unit, CONDITION_FILE_IS_EXECUTABLE, value, true);
    } else if (strcmp(key, "AssertFileNotEmpty") == 0) {
        add_condition(unit, CONDITION_FILE_NOT_EMPTY, value, true);
    } else if (strcmp(key, "AssertUser") == 0) {
        add_condition(unit, CONDITION_USER, value, true);
    } else if (strcmp(key, "AssertGroup") == 0) {
        add_condition(unit, CONDITION_GROUP, value, true);
    } else if (strcmp(key, "AssertHost") == 0) {
        add_condition(unit, CONDITION_HOST, value, true);
    } else if (strcmp(key, "AssertArchitecture") == 0) {
        add_condition(unit, CONDITION_ARCHITECTURE, value, true);
    } else if (strcmp(key, "AssertMemory") == 0) {
        add_condition(unit, CONDITION_MEMORY, value, true);
    } else if (strcmp(key, "AssertCPUs") == 0) {
        add_condition(unit, CONDITION_CPUS, value, true);
    } else if (strcmp(key, "AssertEnvironment") == 0) {
        add_condition(unit, CONDITION_ENVIRONMENT, value, true);
    } else if (strcmp(key, "ConditionVirtualization") == 0) {
        add_condition(unit, CONDITION_VIRTUALIZATION, value, false);
    } else if (strcmp(key, "AssertVirtualization") == 0) {
        add_condition(unit, CONDITION_VIRTUALIZATION, value, true);
    } else if (strcmp(key, "ConditionACPower") == 0) {
        add_condition(unit, CONDITION_AC_POWER, value, false);
    } else if (strcmp(key, "AssertACPower") == 0) {
        add_condition(unit, CONDITION_AC_POWER, value, true);
    } else if (strcmp(key, "ConditionOSRelease") == 0) {
        add_condition(unit, CONDITION_OS_RELEASE, value, false);
    } else if (strcmp(key, "AssertOSRelease") == 0) {
        add_condition(unit, CONDITION_OS_RELEASE, value, true);
    } else if (strcmp(key, "ConditionKernelVersion") == 0) {
        add_condition(unit, CONDITION_KERNEL_VERSION, value, false);
    } else if (strcmp(key, "AssertKernelVersion") == 0) {
        add_condition(unit, CONDITION_KERNEL_VERSION, value, true);
    } else if (strcmp(key, "ConditionKernelCommandLine") == 0) {
        add_condition(unit, CONDITION_KERNEL_COMMAND_LINE, value, false);
    } else if (strcmp(key, "AssertKernelCommandLine") == 0) {
        add_condition(unit, CONDITION_KERNEL_COMMAND_LINE, value, true);
    } else if (strcmp(key, "ConditionKernelModuleLoaded") == 0) {
        add_condition(unit, CONDITION_KERNEL_MODULE_LOADED, value, false);
    } else if (strcmp(key, "AssertKernelModuleLoaded") == 0) {
        add_condition(unit, CONDITION_KERNEL_MODULE_LOADED, value, true);
    } else if (strcmp(key, "ConditionSecurity") == 0) {
        add_condition(unit, CONDITION_SECURITY, value, false);
    } else if (strcmp(key, "AssertSecurity") == 0) {
        add_condition(unit, CONDITION_SECURITY, value, true);
    } else if (strcmp(key, "ConditionCapability") == 0) {
        add_condition(unit, CONDITION_CAPABILITY, value, false);
    } else if (strcmp(key, "AssertCapability") == 0) {
        add_condition(unit, CONDITION_CAPABILITY, value, true);
    } else if (strcmp(key, "ConditionControlGroupController") == 0) {
        add_condition(unit, CONDITION_CONTROL_GROUP_CONTROLLER, value, false);
    } else if (strcmp(key, "AssertControlGroupController") == 0) {
        add_condition(unit, CONDITION_CONTROL_GROUP_CONTROLLER, value, true);
    } else if (strcmp(key, "ConditionMemoryPressure") == 0) {
        add_condition(unit, CONDITION_MEMORY_PRESSURE, value, false);
    } else if (strcmp(key, "AssertMemoryPressure") == 0) {
        add_condition(unit, CONDITION_MEMORY_PRESSURE, value, true);
    } else if (strcmp(key, "ConditionCPUPressure") == 0) {
        add_condition(unit, CONDITION_CPU_PRESSURE, value, false);
    } else if (strcmp(key, "AssertCPUPressure") == 0) {
        add_condition(unit, CONDITION_CPU_PRESSURE, value, true);
    } else if (strcmp(key, "ConditionIOPressure") == 0) {
        add_condition(unit, CONDITION_IO_PRESSURE, value, false);
    } else if (strcmp(key, "AssertIOPressure") == 0) {
        add_condition(unit, CONDITION_IO_PRESSURE, value, true);
    } else if (strcmp(key, "ConditionPathIsEncrypted") == 0) {
        add_condition(unit, CONDITION_PATH_IS_ENCRYPTED, value, false);
    } else if (strcmp(key, "AssertPathIsEncrypted") == 0) {
        add_condition(unit, CONDITION_PATH_IS_ENCRYPTED, value, true);
    } else if (strcmp(key, "ConditionFirmware") == 0) {
        add_condition(unit, CONDITION_FIRMWARE, value, false);
    } else if (strcmp(key, "AssertFirmware") == 0) {
        add_condition(unit, CONDITION_FIRMWARE, value, true);
    } else if (strcmp(key, "ConditionCPUFeature") == 0) {
        add_condition(unit, CONDITION_CPU_FEATURE, value, false);
    } else if (strcmp(key, "AssertCPUFeature") == 0) {
        add_condition(unit, CONDITION_CPU_FEATURE, value, true);
    } else if (strcmp(key, "ConditionVersion") == 0) {
        add_condition(unit, CONDITION_VERSION, value, false);
    } else if (strcmp(key, "AssertVersion") == 0) {
        add_condition(unit, CONDITION_VERSION, value, true);
    } else if (strcmp(key, "ConditionCredential") == 0) {
        add_condition(unit, CONDITION_CREDENTIAL, value, false);
    } else if (strcmp(key, "AssertCredential") == 0) {
        add_condition(unit, CONDITION_CREDENTIAL, value, true);
    } else if (strcmp(key, "ConditionNeedsUpdate") == 0) {
        add_condition(unit, CONDITION_NEEDS_UPDATE, value, false);
    } else if (strcmp(key, "AssertNeedsUpdate") == 0) {
        add_condition(unit, CONDITION_NEEDS_UPDATE, value, true);
    } else if (strcmp(key, "ConditionFirstBoot") == 0) {
        add_condition(unit, CONDITION_FIRST_BOOT, value, false);
    } else if (strcmp(key, "AssertFirstBoot") == 0) {
        add_condition(unit, CONDITION_FIRST_BOOT, value, true);
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
        append_string(service->exec_start_list, MAX_EXEC_COMMANDS,
                      &service->exec_start_count, value);
        if (service->exec_start_count > 0) {
            service->exec_start = service->exec_start_list[service->exec_start_count - 1];
        }
    } else if (strcmp(key, "ExecStop") == 0) {
        service->exec_stop = strdup(value);
    } else if (strcmp(key, "ExecReload") == 0) {
        service->exec_reload = strdup(value);
    } else if (strcmp(key, "ExecStartPre") == 0) {
        service->exec_start_pre = strdup(value);
    } else if (strcmp(key, "ExecStartPost") == 0) {
        service->exec_start_post = strdup(value);
    } else if (strcmp(key, "ExecStopPost") == 0) {
        append_string(service->exec_stop_post, MAX_EXEC_COMMANDS,
                      &service->exec_stop_post_count, value);
    } else if (strcmp(key, "ExecCondition") == 0) {
        append_string(service->exec_condition, MAX_EXEC_COMMANDS,
                      &service->exec_condition_count, value);
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
    } else if (strcmp(key, "RemainAfterExit") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0) {
            service->remain_after_exit = true;
        } else {
            service->remain_after_exit = false;
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
    } else if (strcmp(key, "LimitCPU") == 0) {
        service->limit_cpu = parse_limit_value(value);
    } else if (strcmp(key, "LimitFSIZE") == 0) {
        service->limit_fsize = parse_limit_value(value);
    } else if (strcmp(key, "LimitDATA") == 0) {
        service->limit_data = parse_limit_value(value);
    } else if (strcmp(key, "LimitSTACK") == 0) {
        service->limit_stack = parse_limit_value(value);
    } else if (strcmp(key, "LimitCORE") == 0) {
        service->limit_core = parse_limit_value(value);
    } else if (strcmp(key, "LimitRSS") == 0) {
        service->limit_rss = parse_limit_value(value);
    } else if (strcmp(key, "LimitAS") == 0) {
        service->limit_as = parse_limit_value(value);
    } else if (strcmp(key, "LimitNPROC") == 0) {
        service->limit_nproc = parse_limit_value(value);
    } else if (strcmp(key, "LimitMEMLOCK") == 0) {
        service->limit_memlock = parse_limit_value(value);
    } else if (strcmp(key, "LimitLOCKS") == 0) {
        service->limit_locks = parse_limit_value(value);
    } else if (strcmp(key, "LimitSIGPENDING") == 0) {
        service->limit_sigpending = parse_limit_value(value);
    } else if (strcmp(key, "LimitMSGQUEUE") == 0) {
        service->limit_msgqueue = parse_limit_value(value);
    } else if (strcmp(key, "LimitNICE") == 0) {
        service->limit_nice = parse_limit_value(value);
    } else if (strcmp(key, "LimitRTPRIO") == 0) {
        service->limit_rtprio = parse_limit_value(value);
    } else if (strcmp(key, "LimitRTTIME") == 0) {
        service->limit_rttime = parse_limit_value(value);
    } else if (strcmp(key, "StandardInput") == 0) {
        if (strcmp(value, "null") == 0) service->standard_input = STDIO_NULL;
        else if (strcmp(value, "tty") == 0) service->standard_input = STDIO_TTY;
        else if (strcmp(value, "tty-force") == 0) service->standard_input = STDIO_TTY_FORCE;
        else if (strcmp(value, "socket") == 0) service->standard_input = STDIO_SOCKET;
        else if (strcmp(value, "data") == 0) service->standard_input = STDIO_DATA;
        else if (strncmp(value, "file:", 5) == 0) {
            service->standard_input = STDIO_FILE;
            strncpy(service->input_file, value + 5, sizeof(service->input_file) - 1);
            service->input_file[sizeof(service->input_file) - 1] = '\0';
        }
        else service->standard_input = STDIO_INHERIT; /* Default */
    } else if (strcmp(key, "StandardOutput") == 0) {
        if (strcmp(value, "null") == 0) service->standard_output = STDIO_NULL;
        else if (strcmp(value, "tty") == 0) service->standard_output = STDIO_TTY;
        else if (strcmp(value, "inherit") == 0) service->standard_output = STDIO_INHERIT;
        else if (strcmp(value, "journal") == 0) service->standard_output = STDIO_INHERIT; /* systemd compat: journal → syslog */
        else if (strcmp(value, "syslog") == 0) service->standard_output = STDIO_INHERIT; /* Already our default behavior */
        else if (strcmp(value, "socket") == 0) service->standard_output = STDIO_SOCKET;
        else if (strncmp(value, "file:", 5) == 0) {
            service->standard_output = STDIO_FILE;
            strncpy(service->output_file, value + 5, sizeof(service->output_file) - 1);
            service->output_file[sizeof(service->output_file) - 1] = '\0';
        }
        else service->standard_output = STDIO_INHERIT; /* Default */
    } else if (strcmp(key, "StandardError") == 0) {
        if (strcmp(value, "null") == 0) service->standard_error = STDIO_NULL;
        else if (strcmp(value, "tty") == 0) service->standard_error = STDIO_TTY;
        else if (strcmp(value, "inherit") == 0) service->standard_error = STDIO_INHERIT;
        else if (strcmp(value, "journal") == 0) service->standard_error = STDIO_INHERIT; /* systemd compat: journal → syslog */
        else if (strcmp(value, "syslog") == 0) service->standard_error = STDIO_INHERIT; /* Already our default behavior */
        else if (strcmp(value, "socket") == 0) service->standard_error = STDIO_SOCKET;
        else if (strncmp(value, "file:", 5) == 0) {
            service->standard_error = STDIO_FILE;
            strncpy(service->error_file, value + 5, sizeof(service->error_file) - 1);
            service->error_file[sizeof(service->error_file) - 1] = '\0';
        }
        else service->standard_error = STDIO_INHERIT; /* Default */
    } else if (strcmp(key, "TTYPath") == 0) {
        strncpy(service->tty_path, value, sizeof(service->tty_path) - 1);
        service->tty_path[sizeof(service->tty_path) - 1] = '\0';
    } else if (strcmp(key, "StandardInputText") == 0) {
        /* Append text to input_data buffer with newline */
        size_t value_len = strlen(value);
        size_t new_size = service->input_data_size + value_len + 1; /* +1 for newline */
        char *new_data = realloc(service->input_data, new_size + 1); /* +1 for null terminator */
        if (new_data) {
            service->input_data = new_data;
            memcpy(service->input_data + service->input_data_size, value, value_len);
            service->input_data[service->input_data_size + value_len] = '\n';
            service->input_data_size = new_size;
            service->input_data[service->input_data_size] = '\0';
        }
    } else if (strcmp(key, "StandardInputData") == 0) {
        /* Decode base64 and append to input_data buffer */
        /* For now, implement a simple base64 decoder */
        size_t value_len = strlen(value);
        size_t decoded_max_size = (value_len * 3) / 4 + 1;
        char *decoded = malloc(decoded_max_size);
        if (decoded) {
            size_t decoded_size = base64_decode(value, value_len, decoded, decoded_max_size);
            if (decoded_size > 0) {
                char *new_data = realloc(service->input_data, service->input_data_size + decoded_size + 1);
                if (new_data) {
                    service->input_data = new_data;
                    memcpy(service->input_data + service->input_data_size, decoded, decoded_size);
                    service->input_data_size += decoded_size;
                    service->input_data[service->input_data_size] = '\0';
                }
            }
            free(decoded);
        }
    } else if (strcmp(key, "RestartPreventExitStatus") == 0) {
        parse_status_list(value, service->restart_prevent_statuses, &service->restart_prevent_count);
    } else if (strcmp(key, "RestartForceExitStatus") == 0) {
        parse_status_list(value, service->restart_force_statuses, &service->restart_force_count);
    } else if (strcmp(key, "PIDFile") == 0) {
        service->pid_file = strdup(value);
    } else if (strcmp(key, "SyslogIdentifier") == 0) {
        strncpy(service->syslog_identifier, value, sizeof(service->syslog_identifier) - 1);
        service->syslog_identifier[sizeof(service->syslog_identifier) - 1] = '\0';
    } else if (strcmp(key, "SyslogFacility") == 0) {
        /* Parse facility name to LOG_* constant */
        if (strcmp(value, "daemon") == 0) service->syslog_facility = LOG_DAEMON;
        else if (strcmp(value, "user") == 0) service->syslog_facility = LOG_USER;
        else if (strcmp(value, "local0") == 0) service->syslog_facility = LOG_LOCAL0;
        else if (strcmp(value, "local1") == 0) service->syslog_facility = LOG_LOCAL1;
        else if (strcmp(value, "local2") == 0) service->syslog_facility = LOG_LOCAL2;
        else if (strcmp(value, "local3") == 0) service->syslog_facility = LOG_LOCAL3;
        else if (strcmp(value, "local4") == 0) service->syslog_facility = LOG_LOCAL4;
        else if (strcmp(value, "local5") == 0) service->syslog_facility = LOG_LOCAL5;
        else if (strcmp(value, "local6") == 0) service->syslog_facility = LOG_LOCAL6;
        else if (strcmp(value, "local7") == 0) service->syslog_facility = LOG_LOCAL7;
        else service->syslog_facility = LOG_DAEMON; /* Default */
    } else if (strcmp(key, "SyslogLevel") == 0) {
        /* Parse level name to LOG_* constant */
        if (strcmp(value, "emerg") == 0) service->syslog_level = LOG_EMERG;
        else if (strcmp(value, "alert") == 0) service->syslog_level = LOG_ALERT;
        else if (strcmp(value, "crit") == 0) service->syslog_level = LOG_CRIT;
        else if (strcmp(value, "err") == 0) service->syslog_level = LOG_ERR;
        else if (strcmp(value, "warning") == 0) service->syslog_level = LOG_WARNING;
        else if (strcmp(value, "notice") == 0) service->syslog_level = LOG_NOTICE;
        else if (strcmp(value, "info") == 0) service->syslog_level = LOG_INFO;
        else if (strcmp(value, "debug") == 0) service->syslog_level = LOG_DEBUG;
        else service->syslog_level = LOG_INFO; /* Default */
    } else if (strcmp(key, "SyslogLevelPrefix") == 0) {
        service->syslog_level_prefix = parse_boolean(value);
    } else if (strcmp(key, "LogLevelMax") == 0) {
        /* Parse level name to LOG_* constant (same as SyslogLevel) */
        if (strcmp(value, "emerg") == 0) service->log_level_max = LOG_EMERG;
        else if (strcmp(value, "alert") == 0) service->log_level_max = LOG_ALERT;
        else if (strcmp(value, "crit") == 0) service->log_level_max = LOG_CRIT;
        else if (strcmp(value, "err") == 0) service->log_level_max = LOG_ERR;
        else if (strcmp(value, "warning") == 0) service->log_level_max = LOG_WARNING;
        else if (strcmp(value, "notice") == 0) service->log_level_max = LOG_NOTICE;
        else if (strcmp(value, "info") == 0) service->log_level_max = LOG_INFO;
        else if (strcmp(value, "debug") == 0) service->log_level_max = LOG_DEBUG;
        else {
            /* Try parsing as numeric value (0-7) */
            int level = atoi(value);
            if (level >= 0 && level <= 7) {
                service->log_level_max = level;
            } else {
                service->log_level_max = LOG_DEBUG; /* Default: allow all */
            }
        }
    } else if (strcmp(key, "UMask") == 0) {
        /* Parse octal umask value */
        char *endptr;
        long mask = strtol(value, &endptr, 8);
        if (*endptr == '\0' && mask >= 0 && mask <= 0777) {
            service->umask_value = (mode_t)mask;
        }
    } else if (strcmp(key, "NoNewPrivileges") == 0) {
        service->no_new_privs = parse_boolean(value);
    } else if (strcmp(key, "RootDirectory") == 0) {
        strncpy(service->root_directory, value, sizeof(service->root_directory) - 1);
        service->root_directory[sizeof(service->root_directory) - 1] = '\0';
    } else if (strcmp(key, "RootImage") == 0) {
        strncpy(service->root_image, value, sizeof(service->root_image) - 1);
        service->root_image[sizeof(service->root_image) - 1] = '\0';
    } else if (strcmp(key, "RestartMaxDelaySec") == 0) {
        service->restart_max_delay_sec = atoi(value);
    } else if (strcmp(key, "RestrictSUIDSGID") == 0) {
        service->restrict_suid_sgid = parse_boolean(value);
    } else if (strcmp(key, "MemoryLimit") == 0) {
        service->memory_limit = parse_limit_value(value);
    } else if (strcmp(key, "TimeoutAbortSec") == 0) {
        service->timeout_abort_sec = atoi(value);
    } else if (strcmp(key, "TimeoutStartFailureMode") == 0) {
        if (strcmp(value, "terminate") == 0) {
            service->timeout_start_failure_mode = 0;
        } else if (strcmp(value, "abort") == 0) {
            service->timeout_start_failure_mode = 1;
        } else if (strcmp(value, "kill") == 0) {
            service->timeout_start_failure_mode = 2;
        }
    } else if (strcmp(key, "ProtectSystem") == 0) {
        if (strcmp(value, "no") == 0 || strcmp(value, "false") == 0) {
            service->protect_system = 0;
        } else if (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0) {
            service->protect_system = 1;
        } else if (strcmp(value, "full") == 0) {
            service->protect_system = 2;
        } else if (strcmp(value, "strict") == 0) {
            service->protect_system = 3;
        }
    } else if (strcmp(key, "ProtectHome") == 0) {
        if (strcmp(value, "no") == 0 || strcmp(value, "false") == 0) {
            service->protect_home = 0;
        } else if (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0) {
            service->protect_home = 1;
        } else if (strcmp(value, "read-only") == 0) {
            service->protect_home = 2;
        } else if (strcmp(value, "tmpfs") == 0) {
            service->protect_home = 3;
        }
    } else if (strcmp(key, "PrivateDevices") == 0) {
        service->private_devices = parse_boolean(value);
    } else if (strcmp(key, "ProtectKernelTunables") == 0) {
        service->protect_kernel_tunables = parse_boolean(value);
    } else if (strcmp(key, "ProtectControlGroups") == 0) {
        service->protect_control_groups = parse_boolean(value);
    } else if (strcmp(key, "MountFlags") == 0) {
        if (strcmp(value, "shared") == 0) {
            service->mount_flags = 0;
        } else if (strcmp(value, "slave") == 0) {
            service->mount_flags = 1;
        } else if (strcmp(value, "private") == 0) {
            service->mount_flags = 2;
        }
    } else if (strcmp(key, "DynamicUser") == 0) {
        service->dynamic_user = parse_boolean(value);
    } else if (strcmp(key, "DeviceAllow") == 0) {
        /* Format: DeviceAllow=/dev/sda rwm or DeviceAllow=block-* r */
        if (service->device_allow_count >= MAX_DEVICE_ALLOW) {
            return -1; /* Too many DeviceAllow entries */
        }

        /* Parse device path and permissions */
        char *space = strchr(value, ' ');
        if (!space) {
            return -1; /* Invalid format */
        }

        struct device_allow *entry = &service->device_allow[service->device_allow_count];
        size_t path_len = space - value;
        if (path_len >= MAX_PATH) {
            return -1; /* Path too long */
        }

        strncpy(entry->path, value, path_len);
        entry->path[path_len] = '\0';

        /* Parse permissions (r, w, m) */
        const char *perms = space + 1;
        entry->read = (strchr(perms, 'r') != NULL);
        entry->write = (strchr(perms, 'w') != NULL);
        entry->mknod = (strchr(perms, 'm') != NULL);

        service->device_allow_count++;
    } else if (strcmp(key, "CapabilityBoundingSet") == 0) {
        /* Parse space-separated capability names: CAP_NET_ADMIN CAP_SYS_TIME */
        char *value_copy = strdup(value);
        if (!value_copy) return -1;

        char *token = strtok(value_copy, " ");
        while (token && service->capability_bounding_set_count < MAX_CAPABILITIES) {
            service->capability_bounding_set[service->capability_bounding_set_count] = strdup(token);
            if (!service->capability_bounding_set[service->capability_bounding_set_count]) {
                free(value_copy);
                return -1;
            }
            service->capability_bounding_set_count++;
            token = strtok(NULL, " ");
        }
        free(value_copy);
    } else if (strcmp(key, "AmbientCapabilities") == 0) {
        /* Parse space-separated capability names: CAP_NET_BIND_SERVICE CAP_NET_RAW */
        char *value_copy = strdup(value);
        if (!value_copy) return -1;

        char *token = strtok(value_copy, " ");
        while (token && service->ambient_capabilities_count < MAX_CAPABILITIES) {
            service->ambient_capabilities[service->ambient_capabilities_count] = strdup(token);
            if (!service->ambient_capabilities[service->ambient_capabilities_count]) {
                free(value_copy);
                return -1;
            }
            service->ambient_capabilities_count++;
            token = strtok(NULL, " ");
        }
        free(value_copy);
    } else {
        return -1; /* Unknown key */
    }
    return 0;
}

/* Parse [Timer] section key/value */
static int parse_timer_key(struct timer_section *timer, const char *key, char *value) {
    if (strcmp(key, "OnCalendar") == 0) {
        if (timer->on_calendar_count < MAX_CALENDAR_ENTRIES) {
            timer->on_calendar[timer->on_calendar_count++] = strdup(value);
        }
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
    } else if (strcmp(key, "AccuracySec") == 0) {
        timer->accuracy_sec = atoi(value);
    } else if (strcmp(key, "Unit") == 0) {
        timer->unit = strdup(value);
    } else if (strcmp(key, "FixedRandomDelay") == 0) {
        timer->fixed_random_delay = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "RemainAfterElapse") == 0) {
        timer->remain_after_elapse = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "WakeSystem") == 0) {
        timer->wake_system = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "OnClockChange") == 0) {
        timer->on_clock_change = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "OnTimezoneChange") == 0) {
        timer->on_timezone_change = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
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
    } else if (strcmp(key, "Accept") == 0) {
        socket->accept = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0);
    } else if (strcmp(key, "SocketMode") == 0) {
        socket->socket_mode = (mode_t)strtol(value, NULL, 8);  /* Octal */
    } else if (strcmp(key, "DirectoryMode") == 0) {
        socket->directory_mode = (mode_t)strtol(value, NULL, 8);  /* Octal */
    } else if (strcmp(key, "Backlog") == 0) {
        socket->backlog = atoi(value);
    } else if (strcmp(key, "Service") == 0) {
        socket->service = strdup(value);
    } else if (strcmp(key, "KeepAlive") == 0) {
        socket->keep_alive = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "SendBuffer") == 0) {
        socket->send_buffer = atoi(value);
    } else if (strcmp(key, "ReceiveBuffer") == 0) {
        socket->receive_buffer = atoi(value);
    } else if (strcmp(key, "Broadcast") == 0) {
        socket->broadcast = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "IPTOS") == 0) {
        socket->ip_tos = atoi(value);
    } else if (strcmp(key, "IPTTL") == 0) {
        socket->ip_ttl = atoi(value);
    } else if (strcmp(key, "RemoveOnStop") == 0) {
        socket->remove_on_stop = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "Symlinks") == 0) {
        socket->symlinks_count = parse_list(value, socket->symlinks, MAX_DEPS);
    } else if (strcmp(key, "SocketUser") == 0) {
        strncpy(socket->socket_user, value, sizeof(socket->socket_user) - 1);
    } else if (strcmp(key, "SocketGroup") == 0) {
        strncpy(socket->socket_group, value, sizeof(socket->socket_group) - 1);
    } else if (strcmp(key, "KeepAliveTimeSec") == 0) {
        socket->keep_alive_time = atoi(value);
    } else if (strcmp(key, "KeepAliveIntervalSec") == 0) {
        socket->keep_alive_interval = atoi(value);
    } else if (strcmp(key, "KeepAliveProbes") == 0) {
        socket->keep_alive_count = atoi(value);
    } else if (strcmp(key, "ReusePort") == 0) {
        socket->reuse_port = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "FreeBind") == 0) {
        socket->free_bind = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "Transparent") == 0) {
        socket->transparent = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "TCPCongestion") == 0) {
        socket->tcp_congestion = strdup(value);
    } else if (strcmp(key, "ExecStartPre") == 0) {
        socket->exec_start_pre = strdup(value);
    } else if (strcmp(key, "ExecStartPost") == 0) {
        socket->exec_start_post = strdup(value);
    } else if (strcmp(key, "ExecStopPost") == 0) {
        socket->exec_stop_post = strdup(value);
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
    } else if (strcmp(key, "Also") == 0) {
        install->also_count = parse_list(value, install->also, MAX_INSTALL_ENTRIES);
    } else if (strcmp(key, "Alias") == 0) {
        install->alias_count = parse_list(value, install->alias, MAX_INSTALL_ENTRIES);
    } else if (strcmp(key, "DefaultInstance") == 0) {
        strncpy(install->default_instance, value, sizeof(install->default_instance) - 1);
        install->default_instance[sizeof(install->default_instance) - 1] = '\0';
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
    unit->config.service.limit_cpu = -1;
    unit->config.service.limit_fsize = -1;
    unit->config.service.limit_data = -1;
    unit->config.service.limit_stack = -1;
    unit->config.service.limit_core = -1;
    unit->config.service.limit_rss = -1;
    unit->config.service.limit_as = -1;
    unit->config.service.limit_nproc = -1;
    unit->config.service.limit_memlock = -1;
    unit->config.service.limit_locks = -1;
    unit->config.service.limit_sigpending = -1;
    unit->config.service.limit_msgqueue = -1;
    unit->config.service.limit_nice = -1;
    unit->config.service.limit_rtprio = -1;
    unit->config.service.limit_rttime = -1;
    unit->config.service.private_tmp = false;        /* Default: no private /tmp */
    unit->config.service.runtime_max_sec = 0;        /* Default: unlimited */
    unit->unit.default_dependencies = true;          /* Default: implicit dependencies enabled */
    unit->config.service.restart_max_delay_sec = 0;  /* Default: not set (no exponential backoff) */
    unit->config.service.restrict_suid_sgid = false; /* Default: allow suid/sgid */
    unit->config.service.memory_limit = -1;          /* Default: not set */
    unit->config.service.timeout_abort_sec = 0;      /* Default: use TimeoutStopSec */
    unit->config.service.timeout_start_failure_mode = 0;  /* Default: terminate */
    unit->config.service.protect_system = 0;         /* Default: no protection */
    unit->config.service.protect_home = 0;           /* Default: no protection */
    unit->config.service.private_devices = false;    /* Default: use host /dev */
    unit->config.service.protect_kernel_tunables = false; /* Default: writable /proc/sys, /sys */
    unit->config.service.protect_control_groups = false;  /* Default: writable /sys/fs/cgroup */
    unit->config.service.mount_flags = 2;            /* Default: private (most restrictive) */
    unit->config.service.dynamic_user = false;       /* Default: use configured User=/Group= */
    unit->config.service.device_allow_count = 0;     /* Default: no device whitelist */
    unit->config.service.log_level_max = -1;         /* Default: not set (no filtering) */
    unit->config.service.capability_bounding_set_count = 0;  /* Default: no capability restrictions */
    unit->config.service.ambient_capabilities_count = 0;     /* Default: no ambient capabilities */

    /* Timer defaults */
    unit->config.timer.accuracy_sec = 60;  /* Default: 1 minute (systemd default) */
    unit->config.timer.remain_after_elapse = true;  /* Default: true (systemd default) */

    /* Socket defaults */
    unit->config.socket.socket_mode = 0666;        /* Default: rw-rw-rw- */
    unit->config.socket.directory_mode = 0755;     /* Default: rwxr-xr-x */
    unit->config.socket.backlog = SOMAXCONN;       /* Default: system maximum */
    unit->config.socket.send_buffer = -1;          /* Default: not set */
    unit->config.socket.receive_buffer = -1;       /* Default: not set */
    unit->config.socket.ip_tos = -1;               /* Default: not set */
    unit->config.socket.ip_ttl = -1;               /* Default: not set */
    unit->config.socket.keep_alive_time = -1;      /* Default: not set */
    unit->config.socket.keep_alive_interval = -1;  /* Default: not set */
    unit->config.socket.keep_alive_count = -1;     /* Default: not set */

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

    /* Apply implicit dependencies for DefaultDependencies=yes */
    if (unit->unit.default_dependencies) {
        /* Services, timers, and sockets get implicit Conflicts=shutdown.target Before=shutdown.target */
        if (unit->type == UNIT_SERVICE || unit->type == UNIT_TIMER || unit->type == UNIT_SOCKET) {
            /* Add implicit Conflicts=shutdown.target */
            if (unit->unit.conflicts_count < MAX_DEPS) {
                unit->unit.conflicts[unit->unit.conflicts_count] = strdup("shutdown.target");
                if (unit->unit.conflicts[unit->unit.conflicts_count]) {
                    unit->unit.conflicts_count++;
                }
            }
            /* Add implicit Before=shutdown.target */
            if (unit->unit.before_count < MAX_DEPS) {
                unit->unit.before[unit->unit.before_count] = strdup("shutdown.target");
                if (unit->unit.before[unit->unit.before_count]) {
                    unit->unit.before_count++;
                }
            }
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
        if (unit->config.timer.on_calendar_count == 0 &&
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
    for (int i = 0; i < unit->unit.on_failure_count; i++) free(unit->unit.on_failure[i]);
    for (int i = 0; i < unit->unit.binds_to_count; i++) free(unit->unit.binds_to[i]);
    for (int i = 0; i < unit->unit.part_of_count; i++) free(unit->unit.part_of[i]);
    for (int i = 0; i < unit->unit.condition_count; i++) {
        free(unit->unit.conditions[i].value);
    }

    /* Free [Service] fields */
    if (unit->type == UNIT_SERVICE) {
        for (int i = 0; i < unit->config.service.exec_start_count; i++) {
            free(unit->config.service.exec_start_list[i]);
            unit->config.service.exec_start_list[i] = NULL;
        }
        unit->config.service.exec_start = NULL;
        free(unit->config.service.exec_stop);
        free(unit->config.service.exec_reload);
        free(unit->config.service.exec_start_pre);
        free(unit->config.service.exec_start_post);
        for (int i = 0; i < unit->config.service.exec_stop_post_count; i++) {
            free(unit->config.service.exec_stop_post[i]);
            unit->config.service.exec_stop_post[i] = NULL;
        }
        for (int i = 0; i < unit->config.service.exec_condition_count; i++) {
            free(unit->config.service.exec_condition[i]);
            unit->config.service.exec_condition[i] = NULL;
        }
        free(unit->config.service.environment_file);
        for (int i = 0; i < unit->config.service.environment_count; i++) {
            free(unit->config.service.environment[i]);
        }
        free(unit->config.service.pid_file);
        for (int i = 0; i < unit->config.service.capability_bounding_set_count; i++) {
            free(unit->config.service.capability_bounding_set[i]);
        }
        for (int i = 0; i < unit->config.service.ambient_capabilities_count; i++) {
            free(unit->config.service.ambient_capabilities[i]);
        }
    }

    /* Free [Timer] fields */
    if (unit->type == UNIT_TIMER) {
        for (int i = 0; i < unit->config.timer.on_calendar_count; i++) {
            free(unit->config.timer.on_calendar[i]);
        }
        free(unit->config.timer.unit);
    }

    /* Free [Socket] fields */
    if (unit->type == UNIT_SOCKET) {
        free(unit->config.socket.listen_stream);
        free(unit->config.socket.listen_datagram);
        free(unit->config.socket.service);
        for (int i = 0; i < unit->config.socket.symlinks_count; i++) {
            free(unit->config.socket.symlinks[i]);
        }
        free(unit->config.socket.tcp_congestion);
        free(unit->config.socket.exec_start_pre);
        free(unit->config.socket.exec_start_post);
        free(unit->config.socket.exec_stop_post);
    }

    /* Free [Install] arrays */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        free(unit->install.wanted_by[i]);
    }
    for (int i = 0; i < unit->install.required_by_count; i++) {
        free(unit->install.required_by[i]);
    }
    for (int i = 0; i < unit->install.also_count; i++) {
        free(unit->install.also[i]);
    }
    for (int i = 0; i < unit->install.alias_count; i++) {
        free(unit->install.alias[i]);
    }
}
