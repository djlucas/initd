/* timer_ipc_fuzz.c - Fuzzer for timer daemon IPC protocol
 *
 * Exercises recv_timer_request/response with arbitrary data to ensure the
 * timer IPC layer handles malformed frames safely.
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../../src/common/timer-ipc.h"

static void fuzz_as_request(const uint8_t *data, size_t size) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return;
    }

    /* Best-effort write; ignore short writes */
    (void)write(fds[0], data, size);
    close(fds[0]);

    struct timer_request req = {0};
    (void)recv_timer_request(fds[1], &req);
    close(fds[1]);
}

static void fuzz_as_response(const uint8_t *data, size_t size) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return;
    }

    (void)write(fds[0], data, size);
    close(fds[0]);

    struct timer_response resp = {0};
    (void)recv_timer_response(fds[1], &resp);
    close(fds[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    fuzz_as_request(data, size);
    fuzz_as_response(data, size);

    return 0;
}
