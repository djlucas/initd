/* scanner.c - Unit directory scanner
 *
 * Scans unit directories and loads unit files
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include "unit.h"
#include "parser.h"

#ifndef UNIT_DIRS
#define UNIT_DIRS "/etc/initd/system:/lib/initd/system:/etc/systemd/system:/lib/systemd/system"
#endif

/* Forward declarations */
static int scan_directory(const char *dir_path, struct unit_file **units, int *count);
int scan_unit_directories_filtered(struct unit_file ***units_out, int *count_out, int include_systemd);

/* Check if file has valid unit extension */
static int is_unit_file(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;

    return (strcmp(dot, ".service") == 0 ||
            strcmp(dot, ".target") == 0 ||
            strcmp(dot, ".timer") == 0 ||
            strcmp(dot, ".socket") == 0);
}

/* Scan a single directory for unit files */
static int scan_directory(const char *dir_path, struct unit_file **units, int *count) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];

    dir = opendir(dir_path);
    if (!dir) {
        /* Directory may not exist, not an error */
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (!is_unit_file(entry->d_name)) {
            continue;
        }

        /* Build full path */
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        /* Check if we already loaded this unit (from higher priority dir) */
        int exists = 0;
        for (int i = 0; i < *count; i++) {
            if (strcmp(units[i]->name, entry->d_name) == 0) {
                exists = 1;
                break;
            }
        }

        if (exists) {
            continue; /* Skip, already have this unit from higher priority dir */
        }

        /* Allocate new unit */
        struct unit_file *unit = calloc(1, sizeof(struct unit_file));
        if (!unit) {
            closedir(dir);
            return -1;
        }

        /* Parse unit file */
        if (parse_unit_file(path, unit) < 0) {
            fprintf(stderr, "scanner: failed to parse %s\n", path);
            free(unit);
            continue;
        }

        /* Validate unit file */
        if (validate_unit_file(unit) < 0) {
            fprintf(stderr, "scanner: invalid unit file %s\n", path);
            free_unit_file(unit);
            free(unit);
            continue;
        }

        /* Add to list */
        units[*count] = unit;
        (*count)++;

        /* Link into list */
        if (*count > 1) {
            units[*count - 2]->next = unit;
        }
    }

    closedir(dir);
    return 0;
}

/* Scan all unit directories and load unit files */
int scan_unit_directories(struct unit_file ***units_out, int *count_out) {
    return scan_unit_directories_filtered(units_out, count_out, 1);
}

/* Scan unit directories with flag to include/exclude systemd dirs */
int scan_unit_directories_filtered(struct unit_file ***units_out, int *count_out, int include_systemd) {
    const char *dirs_str = include_systemd ? UNIT_DIRS : "/etc/initd/system:/lib/initd/system";
    char *dirs = strdup(dirs_str);
    char *dir;
    struct unit_file **units;
    int count = 0;
    int capacity = 128;

    /* Allocate initial array */
    units = calloc(capacity, sizeof(struct unit_file *));
    if (!units) {
        free(dirs);
        return -1;
    }

    /* Scan each directory in priority order */
    dir = strtok(dirs, ":");
    while (dir) {
        fprintf(stderr, "scanner: scanning %s\n", dir);

        if (scan_directory(dir, units, &count) < 0) {
            free(dirs);
            free(units);
            return -1;
        }

        /* Grow array if needed */
        if (count >= capacity - 1) {
            capacity *= 2;
            struct unit_file **tmp = realloc(units, capacity * sizeof(struct unit_file *));
            if (!tmp) {
                free(dirs);
                free(units);
                return -1;
            }
            units = tmp;
        }

        dir = strtok(NULL, ":");
    }

    free(dirs);

    fprintf(stderr, "scanner: loaded %d units\n", count);

    *units_out = units;
    *count_out = count;
    return 0;
}

/* Free all loaded units */
void free_units(struct unit_file **units, int count) {
    for (int i = 0; i < count; i++) {
        free_unit_file(units[i]);
        free(units[i]);
    }
    free(units);
}
