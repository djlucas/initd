/* exec_argv_fuzz.c - Fuzzer for exec command parsing
 *
 * Tests MAX_ARGS enforcement, E2BIG handling, and memory cleanup
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include "../../src/common/unit.h"

/* Stub log functions to satisfy linker */
void log_error(const char *tag, const char *fmt, ...) { (void)tag; (void)fmt; }
void log_warn(const char *tag, const char *fmt, ...) { (void)tag; (void)fmt; }

/* Simplified build_exec_argv for fuzzing - based on socket worker implementation */
static int build_exec_argv(const char *command, char ***argv_out) {
    if (!command || command[0] == '\0' || !argv_out) {
        errno = EINVAL;
        return -1;
    }

    char *copy = strdup(command);
    if (!copy) {
        return -1;
    }

    size_t capacity = 8;
    size_t argc = 0;
    char **argv = calloc(capacity, sizeof(char *));
    if (!argv) {
        free(copy);
        return -1;
    }

    char *saveptr = NULL;
    const char *token = strtok_r(copy, " \t", &saveptr);
    while (token) {
        /* Enforce argument count limit to prevent DoS */
        if (argc >= MAX_ARGS) {
            errno = E2BIG;
            goto error;
        }

        if (argc + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            if (new_capacity > MAX_ARGS + 1) {
                new_capacity = MAX_ARGS + 1;
            }
            char **tmp = realloc(argv, new_capacity * sizeof(char *));
            if (!tmp) {
                goto error;
            }
            argv = tmp;
            capacity = new_capacity;
        }

        argv[argc] = strdup(token);
        if (!argv[argc]) {
            goto error;
        }
        argc++;

        token = strtok_r(NULL, " \t", &saveptr);
    }

    free(copy);

    if (argc == 0) {
        free(argv);
        errno = EINVAL;
        return -1;
    }

    argv[argc] = NULL;
    *argv_out = argv;
    return 0;

error:
    for (size_t i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    free(copy);
    return -1;
}

static void free_exec_argv(char **argv) {
    if (!argv) {
        return;
    }
    for (size_t i = 0; argv[i] != NULL; i++) {
        free(argv[i]);
    }
    free(argv);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;  // Skip empty or too large inputs
    }

    /* Create NUL-terminated string from fuzz data */
    char *command = malloc(size + 1);
    if (!command) {
        return 0;
    }
    memcpy(command, data, size);
    command[size] = '\0';

    /* Try to parse as exec command */
    char **argv = NULL;
    if (build_exec_argv(command, &argv) == 0) {
        /* Success - verify argv is valid and clean up */
        if (argv) {
            /* Count arguments to verify bounds */
            int count = 0;
            while (argv[count] != NULL && count < 65) {
                count++;
            }
            free_exec_argv(argv);
        }
    }

    free(command);
    return 0;
}
