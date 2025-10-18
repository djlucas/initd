/* path-security.c - Secure path validation implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <ctype.h>
#include "path-security.h"

/* Validate that a unit name is safe (no path separators, no .., no control chars) */
bool validate_unit_name(const char *name) {
    if (!name || name[0] == '\0') {
        return false;
    }

    /* Reject if it starts with '.' */
    if (name[0] == '.') {
        return false;
    }

    /* Check each character */
    for (const char *p = name; *p != '\0'; p++) {
        /* Reject path separators */
        if (*p == '/' || *p == '\\') {
            return false;
        }

        /* Reject control characters */
        if (iscntrl((unsigned char)*p)) {
            return false;
        }

        /* Reject NUL byte */
        if (*p == '\0') {
            return false;
        }
    }

    /* Reject ".." */
    if (strcmp(name, "..") == 0) {
        return false;
    }

    /* Reject if it contains ".." anywhere */
    if (strstr(name, "..") != NULL) {
        return false;
    }

    /* Must end with .service, .target, .timer, or .socket */
    size_t len = strlen(name);
    if (len < 8) {  /* Minimum: "x.service" = 9 chars */
        return false;
    }

    if (strcmp(name + len - 8, ".service") != 0 &&
        strcmp(name + len - 7, ".target") != 0 &&
        strcmp(name + len - 6, ".timer") != 0 &&
        strcmp(name + len - 7, ".socket") != 0) {
        return false;
    }

    return true;
}

/* Validate that a target name is safe (for WantedBy, RequiredBy) */
bool validate_target_name(const char *target) {
    /* Target names follow the same rules as unit names */
    return validate_unit_name(target);
}

/* Validate that a path is within an allowed directory (no symlinks, no traversal) */
bool validate_path_in_directory(const char *path, const char *allowed_dir) {
    char real_path[PATH_MAX];
    char real_allowed[PATH_MAX];

    if (!path || !allowed_dir) {
        return false;
    }

    /* Resolve the allowed directory to canonical form */
    if (realpath(allowed_dir, real_allowed) == NULL) {
        /* If allowed_dir doesn't exist, that's an error */
        return false;
    }

    /* Resolve the path to canonical form - this follows symlinks and resolves .. */
    /* IMPORTANT: realpath() will fail if the file doesn't exist, which is actually
     * what we want for security - we don't want to create files via symlinks */
    if (realpath(path, real_path) == NULL) {
        /* If file doesn't exist, we can't validate it safely */
        /* For new file creation, we need to validate the parent directory */
        char parent_dir[PATH_MAX];
        char *last_slash;

        strncpy(parent_dir, path, sizeof(parent_dir) - 1);
        parent_dir[sizeof(parent_dir) - 1] = '\0';

        last_slash = strrchr(parent_dir, '/');
        if (!last_slash) {
            return false;  /* Not an absolute path */
        }

        if (last_slash == parent_dir) {
            /* Path is /filename - parent is root */
            strcpy(parent_dir, "/");
        } else {
            *last_slash = '\0';
        }

        /* Validate parent directory */
        if (realpath(parent_dir, real_path) == NULL) {
            return false;
        }

        /* Append the filename back */
        size_t parent_len = strlen(real_path);
        if (parent_len >= PATH_MAX - 1) {
            return false;
        }

        if (real_path[parent_len - 1] != '/') {
            strncat(real_path, "/", PATH_MAX - parent_len - 1);
            parent_len++;
        }

        strncat(real_path, last_slash + 1, PATH_MAX - parent_len - 1);
    }

    /* Ensure allowed directory ends with / for comparison */
    size_t allowed_len = strlen(real_allowed);
    if (real_allowed[allowed_len - 1] != '/') {
        if (allowed_len >= PATH_MAX - 1) {
            return false;
        }
        strcat(real_allowed, "/");
        allowed_len++;
    }

    /* Check if real_path starts with real_allowed */
    if (strncmp(real_path, real_allowed, allowed_len) != 0) {
        return false;
    }

    return true;
}

/* Securely copy a file using fd operations (O_NOFOLLOW, mkostemp, rename) */
int secure_copy_file(const char *src_path, const char *dst_path, mode_t mode) {
    int src_fd = -1;
    int dst_fd = -1;
    char temp_path[PATH_MAX];
    char buffer[8192];
    ssize_t bytes_read, bytes_written;
    struct stat st;
    int result = -1;

    /* Initialize temp_path to avoid undefined behavior in cleanup path */
    temp_path[0] = '\0';

    /* Open source file with O_NOFOLLOW to prevent symlink attacks */
    src_fd = open(src_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (src_fd < 0) {
        return -1;
    }

    /* Verify source is a regular file (not a symlink, device, etc.) */
    if (fstat(src_fd, &st) < 0) {
        goto cleanup;
    }

    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        goto cleanup;
    }

    /* Create temporary file in the same directory as destination */
    snprintf(temp_path, sizeof(temp_path), "%s.XXXXXX", dst_path);

    dst_fd = mkostemp(temp_path, O_CLOEXEC);
    if (dst_fd < 0) {
        goto cleanup;
    }

    /* Set permissions on temp file */
    if (fchmod(dst_fd, mode) < 0) {
        goto cleanup;
    }

    /* Copy data */
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        char *p = buffer;
        while (bytes_read > 0) {
            bytes_written = write(dst_fd, p, bytes_read);
            if (bytes_written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                goto cleanup;
            }
            bytes_read -= bytes_written;
            p += bytes_written;
        }
    }

    if (bytes_read < 0) {
        goto cleanup;
    }

    /* Sync to disk before rename */
    if (fsync(dst_fd) < 0) {
        goto cleanup;
    }

    /* Atomically rename temp file to destination */
    if (rename(temp_path, dst_path) < 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (src_fd >= 0) {
        close(src_fd);
    }
    if (dst_fd >= 0) {
        close(dst_fd);
    }
    if (result != 0 && temp_path[0] != '\0') {
        unlink(temp_path);
    }

    return result;
}

/* Securely create a symlink after validating all components */
int secure_create_symlink(const char *target, const char *linkpath) {
    struct stat st;

    if (!target || !linkpath) {
        errno = EINVAL;
        return -1;
    }

    /* Validate paths don't contain suspicious patterns */
    if (strstr(target, "..") != NULL || strstr(linkpath, "..") != NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Check if link already exists - use lstat to not follow symlinks */
    if (lstat(linkpath, &st) == 0) {
        /* Link already exists */
        errno = EEXIST;
        return -1;
    }

    /* Create the symlink */
    if (symlink(target, linkpath) < 0) {
        return -1;
    }

    return 0;
}
