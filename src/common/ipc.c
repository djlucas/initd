/* ipc.c - IPC protocol implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "ipc.h"

/* Send a request over socket */
int send_request(int fd, const struct priv_request *req) {
    ssize_t n = write(fd, req, sizeof(*req));
    if (n != sizeof(*req)) {
        return -1;
    }
    return 0;
}

/* Receive a request from socket */
int recv_request(int fd, struct priv_request *req) {
    ssize_t n = read(fd, req, sizeof(*req));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*req)) {
        return -1;
    }
    return 0;
}

/* Send a response over socket */
int send_response(int fd, const struct priv_response *resp) {
    ssize_t n = write(fd, resp, sizeof(*resp));
    if (n != sizeof(*resp)) {
        return -1;
    }
    return 0;
}

/* Receive a response from socket */
int recv_response(int fd, struct priv_response *resp) {
    ssize_t n = read(fd, resp, sizeof(*resp));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*resp)) {
        return -1;
    }
    return 0;
}
