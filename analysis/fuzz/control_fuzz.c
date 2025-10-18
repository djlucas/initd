/* control_fuzz.c - Fuzzer for control protocol
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../../src/common/control.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(struct msg_header)) {
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

    /* Try to receive as control request */
    struct control_request req = {0};
    recv_control_request(fds[1], &req);

    close(fds[1]);
    return 0;
}
