/* socket_ipc_fuzz.c - Fuzzer for socket/timer IPC protocol
 *
 * Tests the privileged daemon IPC that handles chown, enable, disable operations
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../../src/common/socket-ipc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(enum socket_request_type)) {
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

    /* Try to receive as socket request */
    struct socket_request req = {0};
    recv_socket_request(fds[1], &req);

    /* Also try as socket response */
    lseek(fds[1], 0, SEEK_SET);
    struct socket_response resp = {0};
    recv_socket_response(fds[1], &resp);

    close(fds[1]);
    return 0;
}
