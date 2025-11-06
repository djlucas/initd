/* priv_ipc_fuzz.c - Fuzzer for supervisor master/worker IPC protocol
 *
 * Exercises recv_request/recv_response to ensure the privileged IPC path
 * tolerates malformed frames without crashing or misbehaving.
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../../src/common/ipc.h"

static void fuzz_as_request(const uint8_t *data, size_t size) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return;
    }

    (void)write(fds[0], data, size);
    close(fds[0]);

    struct priv_request req = {0};
    if (recv_request(fds[1], &req) == 0) {
        free_request(&req);
    }
    close(fds[1]);
}

static void fuzz_as_response(const uint8_t *data, size_t size) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return;
    }

    (void)write(fds[0], data, size);
    close(fds[0]);

    struct priv_response resp = {0};
    (void)recv_response(fds[1], &resp);
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
