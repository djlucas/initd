/* parser_fuzz.c - Fuzzer for unit file parser
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../src/common/parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;  // Skip empty or too large inputs
    }

    /* Create temporary file with fuzz data */
    char template[] = "/tmp/fuzz-unit-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return 0;
    }

    write(fd, data, size);
    close(fd);

    /* Try to parse it */
    struct unit_file unit = {0};
    parse_unit_file(template, &unit);
    
    /* Cleanup */
    free_unit_file(&unit);
    unlink(template);

    return 0;
}
