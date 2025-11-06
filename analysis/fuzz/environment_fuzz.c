/* environment_fuzz.c - Fuzzer for environment variable parsing
 *
 * Tests KEY=VALUE validation, 32KB limit, and NUL byte checks
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../src/common/parser.h"

/* Helper to simulate environment parsing in unit file context */
static void test_environment_directive(const char *value) {
    /* Create a minimal unit file with Environment= directive */
    char template[] = "/tmp/fuzz-env-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return;
    }

    /* Write minimal unit file with Environment= directive */
    const char *header = "[Service]\nType=simple\nExecStart=/bin/true\nEnvironment=";
    write(fd, header, strlen(header));
    write(fd, value, strlen(value));
    write(fd, "\n", 1);
    close(fd);

    /* Try to parse it */
    struct unit_file unit = {0};
    parse_unit_file(template, &unit);

    /* Cleanup */
    free_unit_file(&unit);
    unlink(template);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;  // Skip empty or too large inputs
    }

    /* Create NUL-terminated string from fuzz data */
    char *env_value = malloc(size + 1);
    if (!env_value) {
        return 0;
    }
    memcpy(env_value, data, size);
    env_value[size] = '\0';

    /* Test environment variable parsing */
    test_environment_directive(env_value);

    free(env_value);
    return 0;
}
