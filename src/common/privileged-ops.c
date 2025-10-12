/* privileged-ops.c - Privileged operations for daemons
 *
 * Operations that require root privileges (file writes, symlink creation)
 * Only linked into privileged daemon processes, NOT workers
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#endif
#include "privileged-ops.h"
#include "unit.h"
#include "log.h"

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

    /* Check for read error (not just EOF) */
    if (ferror(in)) {
        log_msg(LOG_ERR, unit->name, "failed to read from %s: %s", systemd_path, strerror(errno));
        fclose(in);
        fclose(out);
        unlink(initd_path);
        return -1;
    }

    fclose(in);
    fclose(out);

    /* Update unit path */
    strncpy(unit->path, initd_path, sizeof(unit->path) - 1);

    log_msg(LOG_INFO, unit->name, "converted systemd unit from %s to %s", systemd_path, initd_path);
    return 0;
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

/* Setup service environment before exec (PrivateTmp, LimitNOFILE, etc.)
 * Called in child process before exec, while still running as root
 * Returns 0 on success, -1 on error
 */
int setup_service_environment(const struct service_section *service) {
#ifdef __linux__
    /* PrivateTmp - Create private mount namespace with tmpfs /tmp */
    if (service->private_tmp) {
        if (unshare(CLONE_NEWNS) < 0) {
            log_msg(LOG_ERR, "init", "Failed to create mount namespace for PrivateTmp: %s", strerror(errno));
            return -1;
        }

        /* Mount private tmpfs on /tmp */
        if (mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777,size=1G") < 0) {
            log_msg(LOG_ERR, "init", "Failed to mount private /tmp: %s", strerror(errno));
            return -1;
        }

        log_msg(LOG_INFO, "init", "Created private /tmp for service");
    }
#else
    /* TODO: On non-Linux, create real directory: mkdir /tmp/initd-<service>-<pid> and chdir() to it */
    if (service->private_tmp) {
        log_msg(LOG_WARNING, "init", "PrivateTmp not supported on this platform, ignoring");
    }
#endif

    /* LimitNOFILE - Set file descriptor limit */
    if (service->limit_nofile >= 0) {
        struct rlimit rlim;

        if (service->limit_nofile == 0) {
            /* infinity - set to maximum */
            rlim.rlim_cur = RLIM_INFINITY;
            rlim.rlim_max = RLIM_INFINITY;
        } else {
            rlim.rlim_cur = service->limit_nofile;
            rlim.rlim_max = service->limit_nofile;
        }

        if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
            log_msg(LOG_ERR, "init", "Failed to set RLIMIT_NOFILE to %d: %s",
                     service->limit_nofile, strerror(errno));
            return -1;
        }

        if (service->limit_nofile == 0) {
            log_msg(LOG_INFO, "init", "Set RLIMIT_NOFILE to infinity");
        } else {
            log_msg(LOG_INFO, "init", "Set RLIMIT_NOFILE to %d", service->limit_nofile);
        }
    }

    return 0;
}
