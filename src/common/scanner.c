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
#include <unistd.h>
#include "unit.h"
#include "parser.h"
#include "log.h"

#ifndef UNIT_DIRS
#define UNIT_DIRS "/etc/initd/system:/lib/initd/system:/etc/systemd/system:/lib/systemd/system"
#endif

/* Forward declarations */
static int scan_directory(const char *dir_path, struct unit_file **units, int *count);
int scan_unit_directories_filtered(struct unit_file ***units_out, int *count_out, int include_systemd);

/* Convert systemd unit to initd by copying to /lib/initd/system */
int convert_systemd_unit(struct unit_file *unit) {
    char initd_path[MAX_PATH];
    char systemd_path[MAX_PATH];
    FILE *in, *out;
    char buffer[4096];
    size_t bytes;

    /* Check if this is a systemd unit */
    if (strstr(unit->path, "/systemd/") == NULL) {
        return 0; /* Not a systemd unit, no conversion needed */
    }

    /* Copy original path */
    strncpy(systemd_path, unit->path, sizeof(systemd_path) - 1);

    /* Create initd path */
    snprintf(initd_path, sizeof(initd_path), "/lib/initd/system/%s", unit->name);

    /* Check if already converted */
    if (access(initd_path, F_OK) == 0) {
        /* Update unit path to initd version */
        strncpy(unit->path, initd_path, sizeof(unit->path) - 1);
        log_msg(LOG_INFO, unit->name, "using existing converted unit at %s", initd_path);
        return 0;
    }

    /* Open files */
    in = fopen(systemd_path, "r");
    if (!in) {
        log_msg(LOG_ERR, unit->name, "failed to open %s: %s", systemd_path, strerror(errno));
        return -1;
    }

    out = fopen(initd_path, "w");
    if (!out) {
        log_msg(LOG_ERR, unit->name, "failed to create %s: %s", initd_path, strerror(errno));
        fclose(in);
        return -1;
    }

    /* Copy file as-is */
    while ((bytes = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, bytes, out) != bytes) {
            log_msg(LOG_ERR, unit->name, "failed to write to %s: %s", initd_path, strerror(errno));
            fclose(in);
            fclose(out);
            unlink(initd_path);
            return -1;
        }
    }

    fclose(in);
    fclose(out);

    /* Update unit path */
    strncpy(unit->path, initd_path, sizeof(unit->path) - 1);

    log_msg(LOG_INFO, unit->name, "converted systemd unit from %s to %s", systemd_path, initd_path);
    return 0;
}

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

/* Enable a unit (create symlinks in target wants directories) */
int enable_unit(struct unit_file *unit) {
    char link_path[1536];  /* Room for path + "/" + unit name */
    char target_dir[1024];

    /* Convert systemd unit if needed */
    if (convert_systemd_unit(unit) < 0) {
        return -1;
    }

    /* Process WantedBy */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        /* Create target wants directory */
        snprintf(target_dir, sizeof(target_dir), "/etc/initd/system/%s.wants", target);
        mkdir(target_dir, 0755);

        /* Create symlink */
        snprintf(link_path, sizeof(link_path), "%s/%s", target_dir, unit->name);

        if (symlink(unit->path, link_path) < 0) {
            if (errno == EEXIST) {
                /* Already enabled */
                continue;
            }
            log_msg(LOG_ERR, unit->name, "failed to create symlink %s: %s",
                    link_path, strerror(errno));
            return -1;
        }

        log_msg(LOG_INFO, unit->name, "created symlink %s → %s",
                link_path, unit->path);
    }

    /* Process RequiredBy */
    for (int i = 0; i < unit->install.required_by_count; i++) {
        const char *target = unit->install.required_by[i];

        /* Create target requires directory */
        snprintf(target_dir, sizeof(target_dir), "/etc/initd/system/%s.requires", target);
        mkdir(target_dir, 0755);

        /* Create symlink */
        snprintf(link_path, sizeof(link_path), "%s/%s", target_dir, unit->name);

        if (symlink(unit->path, link_path) < 0) {
            if (errno == EEXIST) {
                continue;
            }
            log_msg(LOG_ERR, unit->name, "failed to create symlink %s: %s",
                    link_path, strerror(errno));
            return -1;
        }

        log_msg(LOG_INFO, unit->name, "created symlink %s → %s",
                link_path, unit->path);
    }

    unit->enabled = true;
    return 0;
}

/* Disable a unit (remove symlinks) */
int disable_unit(struct unit_file *unit) {
    char link_path[1024];

    /* Remove from WantedBy targets */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.wants/%s", target, unit->name);

        if (unlink(link_path) < 0) {
            if (errno == ENOENT) {
                /* Not enabled */
                continue;
            }
            log_msg(LOG_ERR, unit->name, "failed to remove symlink %s: %s",
                    link_path, strerror(errno));
            return -1;
        }

        log_msg(LOG_INFO, unit->name, "removed symlink %s", link_path);
    }

    /* Remove from RequiredBy targets */
    for (int i = 0; i < unit->install.required_by_count; i++) {
        const char *target = unit->install.required_by[i];

        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.requires/%s", target, unit->name);

        if (unlink(link_path) < 0) {
            if (errno == ENOENT) {
                continue;
            }
            log_msg(LOG_ERR, unit->name, "failed to remove symlink %s: %s",
                    link_path, strerror(errno));
            return -1;
        }

        log_msg(LOG_INFO, unit->name, "removed symlink %s", link_path);
    }

    unit->enabled = false;
    return 0;
}

/* Check if unit is enabled */
bool is_unit_enabled(struct unit_file *unit) {
    char link_path[1024];
    struct stat st;

    /* Check if any WantedBy symlink exists */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.wants/%s", target, unit->name);

        if (lstat(link_path, &st) == 0) {
            return true;
        }
    }

    /* Check if any RequiredBy symlink exists */
    for (int i = 0; i < unit->install.required_by_count; i++) {
        const char *target = unit->install.required_by[i];

        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.requires/%s", target, unit->name);

        if (lstat(link_path, &st) == 0) {
            return true;
        }
    }

    return false;
}
