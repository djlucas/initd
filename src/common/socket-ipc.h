/* socket-ipc.h - IPC protocol between socket daemon and worker
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef SOCKET_IPC_H
#define SOCKET_IPC_H

#include <stdint.h>
#include <sys/types.h>
#include "unit.h"

/* Request types from worker to daemon */
enum socket_request_type {
    SOCKET_REQ_ENABLE_UNIT,     /* Enable a socket unit */
    SOCKET_REQ_DISABLE_UNIT,    /* Disable a socket unit */
    SOCKET_REQ_CONVERT_UNIT     /* Convert systemd unit to initd */
};

/* Request structure */
struct socket_request {
    enum socket_request_type type;
    char unit_name[MAX_UNIT_NAME];
    char unit_path[MAX_PATH];
};

/* Response types from daemon to worker */
enum socket_response_type {
    SOCKET_RESP_OK,
    SOCKET_RESP_ERROR
};

/* Response structure */
struct socket_response {
    enum socket_response_type type;
    int error_code;             /* errno if type == SOCKET_RESP_ERROR */
    char error_msg[256];        /* For SOCKET_RESP_ERROR */
    char converted_path[MAX_PATH]; /* For SOCKET_REQ_CONVERT_UNIT */
};

/* IPC functions */
int send_socket_request(int fd, const struct socket_request *req);
int recv_socket_request(int fd, struct socket_request *req);
int send_socket_response(int fd, const struct socket_response *resp);
int recv_socket_response(int fd, struct socket_response *resp);

#endif /* SOCKET_IPC_H */
