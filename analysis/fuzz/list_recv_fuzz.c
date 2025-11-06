/* list_recv_fuzz.c - Fuzzer for IPC list receivers
 *
 * Tests MAX_IPC_LIST_COUNT enforcement and NUL-termination in all list types
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
    if (size < sizeof(uint32_t)) {
        return 0;  // Need at least a count field
    }

    /* Create a socketpair to simulate IPC */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return 0;
    }

    /* Write fuzz data to socket */
    write(fds[0], data, size);
    close(fds[0]);

    /* Try to receive as unit list */
    struct unit_list_entry *unit_entries = NULL;
    size_t unit_count = 0;
    if (recv_unit_list(fds[1], &unit_entries, &unit_count) == 0) {
        free(unit_entries);
    }

    /* Reopen socket for next test */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return 0;
    }
    write(fds[0], data, size);
    close(fds[0]);

    /* Try to receive as timer list */
    struct timer_list_entry *timer_entries = NULL;
    size_t timer_count = 0;
    if (recv_timer_list(fds[1], &timer_entries, &timer_count) == 0) {
        free(timer_entries);
    }
    close(fds[1]);

    /* Reopen socket for socket list test */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return 0;
    }
    write(fds[0], data, size);
    close(fds[0]);

    /* Try to receive as socket list */
    struct socket_list_entry *socket_entries = NULL;
    size_t socket_count = 0;
    if (recv_socket_list(fds[1], &socket_entries, &socket_count) == 0) {
        free(socket_entries);
    }
    close(fds[1]);

    return 0;
}
