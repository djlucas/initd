/* ipc.h - IPC protocol between supervisor master and slave
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef IPC_H
#define IPC_H

#include <stdint.h>
#include <sys/types.h>

/* Request types from worker to daemon */
enum priv_request_type {
    REQ_START_SERVICE,      /* Fork and exec a service */
    REQ_STOP_SERVICE,       /* Kill a service */
    REQ_ENABLE_UNIT,        /* Enable a unit */
    REQ_DISABLE_UNIT,       /* Disable a unit */
    REQ_CONVERT_UNIT,       /* Convert systemd unit to initd */
    REQ_SHUTDOWN_COMPLETE   /* Worker finished shutdown */
};

/* Request structure */
struct priv_request {
    enum priv_request_type type;
    pid_t service_pid;      /* For STOP_SERVICE */
    char unit_name[256];    /* For START_SERVICE, ENABLE_UNIT, DISABLE_UNIT, CONVERT_UNIT */
    char unit_path[1024];   /* For ENABLE_UNIT, DISABLE_UNIT, CONVERT_UNIT */
    char exec_path[1024];   /* For START_SERVICE */
    char **exec_args;       /* For START_SERVICE (NULL-terminated) */
    uid_t run_uid;          /* User to run as */
    gid_t run_gid;          /* Group to run as */
};

/* Response types from daemon to worker */
enum priv_response_type {
    RESP_OK,
    RESP_ERROR,
    RESP_SERVICE_STARTED,   /* Contains PID */
    RESP_SERVICE_STOPPED,
    RESP_SERVICE_EXITED,    /* Notification: service exited */
    RESP_UNIT_ENABLED,      /* Unit enabled successfully */
    RESP_UNIT_DISABLED,     /* Unit disabled successfully */
    RESP_UNIT_CONVERTED     /* Unit converted successfully */
};

/* Response structure */
struct priv_response {
    enum priv_response_type type;
    int error_code;         /* errno if type == RESP_ERROR */
    pid_t service_pid;      /* For RESP_SERVICE_STARTED/EXITED */
    int exit_status;        /* For RESP_SERVICE_EXITED */
    char error_msg[256];    /* For RESP_ERROR */
    char converted_path[1024]; /* For RESP_UNIT_CONVERTED */
};

/* IPC functions */
int send_request(int fd, const struct priv_request *req);
int recv_request(int fd, struct priv_request *req);
int send_response(int fd, const struct priv_response *resp);
int recv_response(int fd, struct priv_response *resp);

#endif /* IPC_H */
