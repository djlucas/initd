#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../src/timer-daemon/calendar.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0 || size > 4096) {
        return 0;
    }

    char *input = malloc(size + 1);
    if (!input) {
        return 0;
    }

    memcpy(input, data, size);
    input[size] = '\0';

    /* Validate expression; only evaluate next run if it parses. */
    if (calendar_validate(input)) {
        time_t now = time(NULL);
        (void)calendar_next_run(input, now);
    }

    free(input);
    return 0;
}
