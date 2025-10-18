/* ipc_fuzz.c - Fuzzer for supervisor IPC protocol
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../../src/common/ipc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(enum priv_request_type)) {
        return 0;  // Too small to be valid
    }

    /* Create a socketpair to simulate IPC */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return 0;
    }

    /* Write fuzz data to socket */
    write(fds[0], data, size);
    close(fds[0]);

    /* Try to receive as IPC request */
    struct priv_request req = {0};
    recv_request(fds[1], &req);
    
    /* Cleanup */
    free_request(&req);
    close(fds[1]);

    return 0;
}
