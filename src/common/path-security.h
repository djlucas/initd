/* path-security.h - Secure path validation and operations
 *
 * Provides functions to prevent path traversal, symlink attacks, and TOCTOU
 * vulnerabilities in privileged operations.
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef PATH_SECURITY_H
#define PATH_SECURITY_H

#include <stdbool.h>

/* Validate that a path is within an allowed directory (no symlinks, no traversal) */
bool validate_path_in_directory(const char *path, const char *allowed_dir);

/* Validate that a unit name is safe (no path separators, no .., no control chars) */
bool validate_unit_name(const char *name);

/* Validate that a target name is safe (for WantedBy, RequiredBy) */
bool validate_target_name(const char *target);

/* Securely copy a file using fd operations (O_NOFOLLOW, mkostemp, rename) */
int secure_copy_file(const char *src_path, const char *dst_path, mode_t mode);

/* Securely create a symlink after validating all components */
int secure_create_symlink(const char *target, const char *linkpath);

#endif /* PATH_SECURITY_H */
