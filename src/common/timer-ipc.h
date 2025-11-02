/* timer-ipc.h - IPC protocol between timer daemon and worker
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef TIMER_IPC_H
#define TIMER_IPC_H

#include <stdint.h>
#include <sys/types.h>
#include "unit.h"

/* Request types from worker to daemon */
enum timer_request_type {
    TIMER_REQ_ENABLE_UNIT,      /* Enable a timer unit */
    TIMER_REQ_DISABLE_UNIT,     /* Disable a timer unit */
    TIMER_REQ_CONVERT_UNIT,     /* Convert systemd unit to initd */
    TIMER_REQ_SET_WAKE_ALARM    /* Set RTC wake alarm for WakeSystem= */
};

/* Request structure */
struct timer_request {
    enum timer_request_type type;
    char unit_name[MAX_UNIT_NAME];
    char unit_path[MAX_PATH];
    time_t wake_time;           /* For TIMER_REQ_SET_WAKE_ALARM */
};

/* Response types from daemon to worker */
enum timer_response_type {
    TIMER_RESP_OK,
    TIMER_RESP_ERROR
};

/* Response structure */
struct timer_response {
    enum timer_response_type type;
    int error_code;             /* errno if type == TIMER_RESP_ERROR */
    char error_msg[256];        /* For TIMER_RESP_ERROR */
    char converted_path[MAX_PATH]; /* For TIMER_REQ_CONVERT_UNIT */
};

/* IPC functions */
int send_timer_request(int fd, const struct timer_request *req);
int recv_timer_request(int fd, struct timer_request *req);
int send_timer_response(int fd, const struct timer_response *resp);
int recv_timer_response(int fd, struct timer_response *resp);

#endif /* TIMER_IPC_H */
