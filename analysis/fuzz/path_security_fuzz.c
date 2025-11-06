/* path_security_fuzz.c - Fuzzer for path validation
 *
 * Tests symlink detection, .. handling, and directory traversal prevention
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "../../src/common/path-security.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > PATH_MAX) {
        return 0;  // Skip empty or too large inputs
    }

    /* Create NUL-terminated string from fuzz data */
    char *path = malloc(size + 1);
    if (!path) {
        return 0;
    }
    memcpy(path, data, size);
    path[size] = '\0';

    /* Test path validation against common allowed directories */
    const char *allowed_dirs[] = {
        "/etc/initd/system",
        "/lib/initd/system",
        "/run/initd",
        "/tmp",
        "/var/run",
        NULL
    };

    for (int i = 0; allowed_dirs[i] != NULL; i++) {
        /* Test if path would be accepted as valid */
        (void)validate_path_in_directory(path, allowed_dirs[i]);
    }

    free(path);
    return 0;
}
