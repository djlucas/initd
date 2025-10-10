/* timer-ipc.c - IPC protocol between timer daemon and worker
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "timer-ipc.h"

/* Send request from worker to daemon */
int send_timer_request(int fd, const struct timer_request *req) {
    ssize_t n = write(fd, req, sizeof(*req));
    if (n < 0) {
        return -1;
    }
    if ((size_t)n != sizeof(*req)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

/* Receive request in daemon from worker */
int recv_timer_request(int fd, struct timer_request *req) {
    ssize_t n = read(fd, req, sizeof(*req));
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        errno = EPIPE; /* Worker closed connection */
        return -1;
    }
    if ((size_t)n != sizeof(*req)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

/* Send response from daemon to worker */
int send_timer_response(int fd, const struct timer_response *resp) {
    ssize_t n = write(fd, resp, sizeof(*resp));
    if (n < 0) {
        return -1;
    }
    if ((size_t)n != sizeof(*resp)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

/* Receive response in worker from daemon */
int recv_timer_response(int fd, struct timer_response *resp) {
    ssize_t n = read(fd, resp, sizeof(*resp));
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        errno = EPIPE; /* Daemon closed connection */
        return -1;
    }
    if ((size_t)n != sizeof(*resp)) {
        errno = EIO;
        return -1;
    }
    return 0;
}
