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
#include <pwd.h>
#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#endif
#include "privileged-ops.h"
#include "unit.h"
#include "log.h"
#include "path-security.h"

/* Convert systemd unit to initd by copying to /lib/initd/system */
int convert_systemd_unit(struct unit_file *unit) {
    char initd_path[MAX_PATH];
    char systemd_path[MAX_PATH];
    struct stat st;

    /* SECURITY: Validate unit name first - reject path traversal attempts */
    if (!validate_unit_name(unit->name)) {
        log_msg(LOG_ERR, unit->name, "invalid unit name (possible path traversal attempt)");
        errno = EINVAL;
        return -1;
    }

    /* Check if this is a systemd unit */
    if (strstr(unit->path, "/systemd/") == NULL) {
        return 0; /* Not a systemd unit, no conversion needed */
    }

    /* SECURITY: Validate source path is in an allowed systemd directory */
    if (!validate_path_in_directory(unit->path, "/lib/systemd/system") &&
        !validate_path_in_directory(unit->path, "/usr/lib/systemd/system") &&
        !validate_path_in_directory(unit->path, "/etc/systemd/system")) {
        log_msg(LOG_ERR, unit->name, "source path %s is not in an allowed systemd directory", unit->path);
        errno = EACCES;
        return -1;
    }

    /* Copy original path */
    strncpy(systemd_path, unit->path, sizeof(systemd_path) - 1);
    systemd_path[sizeof(systemd_path) - 1] = '\0';

    /* Create initd path using validated unit name */
    snprintf(initd_path, sizeof(initd_path), "/lib/initd/system/%s", unit->name);

    /* Ensure destination directories exist */
    if (mkdir("/lib/initd", 0755) < 0 && errno != EEXIST) {
        log_msg(LOG_ERR, unit->name, "failed to create /lib/initd: %s", strerror(errno));
        return -1;
    }
    if (mkdir("/lib/initd/system", 0755) < 0 && errno != EEXIST) {
        log_msg(LOG_ERR, unit->name, "failed to create /lib/initd/system: %s", strerror(errno));
        return -1;
    }

    /* SECURITY: Use lstat instead of access to prevent TOCTOU */
    if (lstat(initd_path, &st) == 0) {
        /* File exists - verify it's a regular file, not a symlink */
        if (!S_ISREG(st.st_mode)) {
            log_msg(LOG_ERR, unit->name, "existing file %s is not a regular file", initd_path);
            errno = EINVAL;
            return -1;
        }

        /* Update unit path to initd version */
        strncpy(unit->path, initd_path, sizeof(unit->path) - 1);
        unit->path[sizeof(unit->path) - 1] = '\0';
        log_msg(LOG_INFO, unit->name, "using existing converted unit at %s", initd_path);
        return 0;
    }

    /* SECURITY: Use secure_copy_file which uses O_NOFOLLOW and mkostemp */
    if (secure_copy_file(systemd_path, initd_path, 0644) < 0) {
        log_msg(LOG_ERR, unit->name, "failed to copy %s to %s: %s",
                systemd_path, initd_path, strerror(errno));
        return -1;
    }

    /* Update unit path */
    strncpy(unit->path, initd_path, sizeof(unit->path) - 1);
    unit->path[sizeof(unit->path) - 1] = '\0';

    log_msg(LOG_INFO, unit->name, "converted systemd unit from %s to %s", systemd_path, initd_path);
    return 0;
}

/* Enable a unit (create symlinks in target wants directories) */
int enable_unit(struct unit_file *unit) {
    char link_path[1536];  /* Room for path + "/" + unit name */
    char target_dir[1024];

    /* SECURITY: Validate unit name */
    if (!validate_unit_name(unit->name)) {
        log_msg(LOG_ERR, unit->name, "invalid unit name (possible path traversal attempt)");
        errno = EINVAL;
        return -1;
    }

    /* Convert systemd unit if needed */
    if (convert_systemd_unit(unit) < 0) {
        return -1;
    }

    /* SECURITY: Validate unit->path is in allowed directory */
    if (!validate_path_in_directory(unit->path, "/lib/initd/system") &&
        !validate_path_in_directory(unit->path, "/etc/initd/system") &&
        !validate_path_in_directory(unit->path, "/usr/lib/initd/system")) {
        log_msg(LOG_ERR, unit->name, "unit path %s is not in an allowed directory", unit->path);
        errno = EACCES;
        return -1;
    }

    /* Process WantedBy */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            log_msg(LOG_ERR, unit->name, "invalid target name: %s", target);
            continue;  /* Skip this target but don't fail the whole operation */
        }

        /* Create target wants directory */
        snprintf(target_dir, sizeof(target_dir), "/etc/initd/system/%s.wants", target);
        mkdir(target_dir, 0755);

        /* Create symlink using validated components */
        snprintf(link_path, sizeof(link_path), "%s/%s", target_dir, unit->name);

        /* SECURITY: Use secure_create_symlink with validation */
        if (secure_create_symlink(unit->path, link_path) < 0) {
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

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            log_msg(LOG_ERR, unit->name, "invalid target name: %s", target);
            continue;
        }

        /* Create target requires directory */
        snprintf(target_dir, sizeof(target_dir), "/etc/initd/system/%s.requires", target);
        mkdir(target_dir, 0755);

        /* Create symlink using validated components */
        snprintf(link_path, sizeof(link_path), "%s/%s", target_dir, unit->name);

        /* SECURITY: Use secure_create_symlink with validation */
        if (secure_create_symlink(unit->path, link_path) < 0) {
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

    /* SECURITY: Validate unit name */
    if (!validate_unit_name(unit->name)) {
        log_msg(LOG_ERR, unit->name, "invalid unit name (possible path traversal attempt)");
        errno = EINVAL;
        return -1;
    }

    /* Remove from WantedBy targets */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            log_msg(LOG_ERR, unit->name, "invalid target name: %s", target);
            continue;
        }

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

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            log_msg(LOG_ERR, unit->name, "invalid target name: %s", target);
            continue;
        }

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

    /* SECURITY: Validate unit name */
    if (!validate_unit_name(unit->name)) {
        return false;
    }

    /* Check if any WantedBy symlink exists */
    for (int i = 0; i < unit->install.wanted_by_count; i++) {
        const char *target = unit->install.wanted_by[i];

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            continue;
        }

        snprintf(link_path, sizeof(link_path),
                 "/etc/initd/system/%s.wants/%s", target, unit->name);

        if (lstat(link_path, &st) == 0) {
            return true;
        }
    }

    /* Check if any RequiredBy symlink exists */
    for (int i = 0; i < unit->install.required_by_count; i++) {
        const char *target = unit->install.required_by[i];

        /* SECURITY: Validate target name */
        if (!validate_target_name(target)) {
            continue;
        }

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
    if (service->private_tmp) {
        char template[] = "/tmp/initd-privateXXXXXX";
        char pathbuf[sizeof(template)];
        char *dir_path = NULL;
        struct passwd *pw = NULL;

        strncpy(pathbuf, template, sizeof(pathbuf) - 1);
        pathbuf[sizeof(pathbuf) - 1] = '\0';

        dir_path = mkdtemp(pathbuf);
        if (!dir_path) {
            log_msg(LOG_ERR, "init", "Failed to create PrivateTmp directory: %s", strerror(errno));
            return -1;
        }

        /* mkdtemp() already creates with mode 0700, use fd-based operations to avoid TOCTOU */
        if (service->user[0] != '\0') {
            pw = getpwnam(service->user);
            if (pw) {
                int dir_fd = open(dir_path, O_DIRECTORY | O_RDONLY);
                if (dir_fd < 0) {
                    log_msg(LOG_WARNING, "init", "Failed to open PrivateTmp directory: %s", strerror(errno));
                } else {
                    if (fchown(dir_fd, pw->pw_uid, pw->pw_gid) < 0) {
                        log_msg(LOG_WARNING, "init", "Failed to chown PrivateTmp directory to %s: %s",
                                service->user, strerror(errno));
                    }
                    if (fchmod(dir_fd, 0700) < 0) {
                        log_msg(LOG_WARNING, "init", "Failed to chmod PrivateTmp directory: %s", strerror(errno));
                    }
                    close(dir_fd);
                }
            } else {
                log_msg(LOG_WARNING, "init", "Cannot resolve user '%s' for PrivateTmp ownership", service->user);
            }
        }

        if (chdir(dir_path) < 0) {
            log_msg(LOG_ERR, "init", "Failed to chdir to PrivateTmp directory %s: %s",
                    dir_path, strerror(errno));
            rmdir(dir_path);
            return -1;
        }

        /* Override TMPDIR so libc temp helpers use the private tree */
        if (setenv("TMPDIR", dir_path, 1) < 0) {
            log_msg(LOG_WARNING, "init", "Failed to set TMPDIR to %s: %s",
                    dir_path, strerror(errno));
        }

        log_msg(LOG_INFO, "init", "Created private tmp directory at %s", dir_path);
    }
#endif

    /* Helper macro for setting resource limits */
#define SET_RLIMIT(name, rlimit_const, value, warn_msg) \
    if (value >= 0) { \
        if (warn_msg) { \
            log_msg(LOG_WARNING, "init", "%s", warn_msg); \
        } \
        struct rlimit rlim; \
        if (value == 0) { \
            rlim.rlim_cur = RLIM_INFINITY; \
            rlim.rlim_max = RLIM_INFINITY; \
        } else { \
            rlim.rlim_cur = (rlim_t)value; \
            rlim.rlim_max = (rlim_t)value; \
        } \
        if (setrlimit(rlimit_const, &rlim) < 0) { \
            log_msg(LOG_ERR, "init", "Failed to set " name ": %s", strerror(errno)); \
            return -1; \
        } \
    }

    /* LimitNOFILE - Set file descriptor limit */
    SET_RLIMIT("RLIMIT_NOFILE", RLIMIT_NOFILE, service->limit_nofile, NULL);

    /* LimitCPU - CPU time limit */
    SET_RLIMIT("RLIMIT_CPU", RLIMIT_CPU, service->limit_cpu, NULL);

    /* LimitFSIZE - File size limit */
    SET_RLIMIT("RLIMIT_FSIZE", RLIMIT_FSIZE, service->limit_fsize, NULL);

    /* LimitDATA - Data segment size limit */
    SET_RLIMIT("RLIMIT_DATA", RLIMIT_DATA, service->limit_data, NULL);

    /* LimitSTACK - Stack size limit */
    SET_RLIMIT("RLIMIT_STACK", RLIMIT_STACK, service->limit_stack, NULL);

    /* LimitCORE - Core dump size limit */
    SET_RLIMIT("RLIMIT_CORE", RLIMIT_CORE, service->limit_core, NULL);

    /* LimitRSS - Resident set size (deprecated on Linux) */
#ifdef __linux__
    SET_RLIMIT("RLIMIT_RSS", RLIMIT_RSS, service->limit_rss, "LimitRSS= is deprecated on Linux");
#else
    SET_RLIMIT("RLIMIT_RSS", RLIMIT_RSS, service->limit_rss, NULL);
#endif

    /* LimitAS - Address space limit */
    SET_RLIMIT("RLIMIT_AS", RLIMIT_AS, service->limit_as, NULL);

    /* LimitNPROC - Process limit */
    SET_RLIMIT("RLIMIT_NPROC", RLIMIT_NPROC, service->limit_nproc, NULL);

    /* LimitMEMLOCK - Locked memory limit */
    SET_RLIMIT("RLIMIT_MEMLOCK", RLIMIT_MEMLOCK, service->limit_memlock, NULL);

    /* LimitLOCKS - File locks (obsolete on Linux) */
#ifdef __linux__
    SET_RLIMIT("RLIMIT_LOCKS", RLIMIT_LOCKS, service->limit_locks, "LimitLOCKS= is obsolete on Linux (since kernel 2.4.25)");
#else
    SET_RLIMIT("RLIMIT_LOCKS", RLIMIT_LOCKS, service->limit_locks, NULL);
#endif

    /* Linux-only limits */
#ifdef __linux__
    /* LimitSIGPENDING - Pending signals limit (Linux only) */
    SET_RLIMIT("RLIMIT_SIGPENDING", RLIMIT_SIGPENDING, service->limit_sigpending, NULL);

    /* LimitMSGQUEUE - Message queue bytes (Linux only) */
    SET_RLIMIT("RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE, service->limit_msgqueue, NULL);

    /* LimitNICE - Nice priority (Linux only) */
    SET_RLIMIT("RLIMIT_NICE", RLIMIT_NICE, service->limit_nice, NULL);

    /* LimitRTPRIO - Real-time priority (Linux only) */
    SET_RLIMIT("RLIMIT_RTPRIO", RLIMIT_RTPRIO, service->limit_rtprio, NULL);

    /* LimitRTTIME - Real-time CPU time (Linux only) */
    SET_RLIMIT("RLIMIT_RTTIME", RLIMIT_RTTIME, service->limit_rttime, NULL);
#else
    /* Warn if Linux-only limits are used on other platforms */
    if (service->limit_sigpending >= 0) {
        log_msg(LOG_WARNING, "init", "LimitSIGPENDING= not supported on this platform");
    }
    if (service->limit_msgqueue >= 0) {
        log_msg(LOG_WARNING, "init", "LimitMSGQUEUE= not supported on this platform");
    }
    if (service->limit_nice >= 0) {
        log_msg(LOG_WARNING, "init", "LimitNICE= not supported on this platform");
    }
    if (service->limit_rtprio >= 0) {
        log_msg(LOG_WARNING, "init", "LimitRTPRIO= not supported on this platform");
    }
    if (service->limit_rttime >= 0) {
        log_msg(LOG_WARNING, "init", "LimitRTTIME= not supported on this platform");
    }
#endif

    /* MemoryLimit - alias for address space limit (portable) */
    SET_RLIMIT("RLIMIT_AS", RLIMIT_AS, service->memory_limit, NULL);

#undef SET_RLIMIT

    return 0;
}
