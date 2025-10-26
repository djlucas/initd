/* ipc.c - IPC protocol implementation with proper serialization
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
#include <stdint.h>
#include "ipc.h"

/* Robust write that handles partial writes and EINTR */
static ssize_t writen(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t left = n;

    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on signal interruption */
            }
            return -1;
        }
        left -= w;
        p += w;
    }
    return n;
}

/* Robust read that handles partial reads and EINTR */
static ssize_t readn(int fd, void *buf, size_t n) {
    char *p = buf;
    size_t left = n;

    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on signal interruption */
            }
            return -1;
        }
        if (r == 0) {
            return 0;  /* EOF */
        }
        left -= r;
        p += r;
    }
    return n;
}

/* Wire format for requests (no pointers, only POD types) */
struct priv_request_wire {
    uint32_t type;              /* enum priv_request_type */
    int32_t  service_pid;       /* For STOP_SERVICE */
    char     unit_name[256];    /* NUL-terminated */
    char     unit_path[1024];   /* NUL-terminated */
    char     exec_path[1024];   /* NUL-terminated */
    uint32_t run_uid;
    uint32_t run_gid;
    uint8_t  private_tmp;
    int32_t  limit_nofile;
    int32_t  kill_mode;
    int32_t  standard_input;
    int32_t  standard_output;
    int32_t  standard_error;
    char     tty_path[1024];    /* NUL-terminated */
    int32_t  start_limit_interval_sec;
    int32_t  start_limit_burst;
    int32_t  start_limit_action;
    int32_t  restart_prevent_statuses[MAX_RESTART_STATUS];
    int32_t  restart_force_statuses[MAX_RESTART_STATUS];
    uint32_t restart_prevent_count;
    uint32_t restart_force_count;
    uint32_t arg_count;         /* Number of arguments */
    uint32_t args_total_len;    /* Total bytes of packed args */
    /* Followed by args_total_len bytes of concatenated NUL-terminated args */
};

/* Wire format for responses (no pointers) */
struct priv_response_wire {
    uint32_t type;              /* enum priv_response_type */
    int32_t  error_code;
    int32_t  service_pid;
    int32_t  exit_status;
    char     error_msg[256];    /* NUL-terminated */
    char     converted_path[1024]; /* NUL-terminated */
};

/* Send a request over socket */
int send_request(int fd, const struct priv_request *req) {
    struct priv_request_wire wire;

    /* Zero-initialize to avoid sending uninitialized padding bytes */
    memset(&wire, 0, sizeof(wire));

    /* Pack fixed fields */
    wire.type = req->type;
    wire.service_pid = req->service_pid;

    /* Copy and ensure NUL-termination */
    strncpy(wire.unit_name, req->unit_name, sizeof(wire.unit_name) - 1);
    wire.unit_name[sizeof(wire.unit_name) - 1] = '\0';

    strncpy(wire.unit_path, req->unit_path, sizeof(wire.unit_path) - 1);
    wire.unit_path[sizeof(wire.unit_path) - 1] = '\0';

    strncpy(wire.exec_path, req->exec_path, sizeof(wire.exec_path) - 1);
    wire.exec_path[sizeof(wire.exec_path) - 1] = '\0';

    wire.run_uid = req->run_uid;
    wire.run_gid = req->run_gid;
    wire.private_tmp = req->private_tmp ? 1 : 0;
    wire.limit_nofile = req->limit_nofile;
    wire.kill_mode = req->kill_mode;
    wire.standard_input = req->standard_input;
    wire.standard_output = req->standard_output;
    wire.standard_error = req->standard_error;

    strncpy(wire.tty_path, req->tty_path, sizeof(wire.tty_path) - 1);
    wire.tty_path[sizeof(wire.tty_path) - 1] = '\0';

    wire.start_limit_interval_sec = req->start_limit_interval_sec;
    wire.start_limit_burst = req->start_limit_burst;
    wire.start_limit_action = req->start_limit_action;
    wire.restart_prevent_count = req->restart_prevent_count;
    wire.restart_force_count = req->restart_force_count;
    for (int i = 0; i < MAX_RESTART_STATUS; i++) {
        wire.restart_prevent_statuses[i] = req->restart_prevent_statuses[i];
        wire.restart_force_statuses[i] = req->restart_force_statuses[i];
    }

    /* Pack exec_args */
    wire.arg_count = 0;
    wire.args_total_len = 0;

    if (req->exec_args) {
        /* Count args and calculate total length */
        for (int i = 0; req->exec_args[i] != NULL; i++) {
            if (wire.arg_count >= 1024) {
                errno = EINVAL;
                return -1;
            }

            size_t len = strlen(req->exec_args[i]) + 1; /* include NUL */
            if (len > 1024 * 1024) {
                errno = EINVAL;
                return -1;
            }

            if (wire.args_total_len > UINT32_MAX - len) {
                errno = EOVERFLOW;
                return -1;
            }

            wire.arg_count++;
            wire.args_total_len += (uint32_t)len;
        }
    }

    /* Send wire header */
    if (writen(fd, &wire, sizeof(wire)) != sizeof(wire)) {
        return -1;
    }

    /* Send packed args if any */
    if (wire.args_total_len > 0) {
        if (wire.args_total_len > 1024 * 1024) {
            errno = EINVAL;
            return -1;
        }

        char *args_buf = malloc(wire.args_total_len);
        if (!args_buf) {
            return -1;
        }

        char *p = args_buf;
        for (uint32_t i = 0; i < wire.arg_count; i++) {
            size_t len = strlen(req->exec_args[i]) + 1;
            if (len > wire.args_total_len - (size_t)(p - args_buf)) {
                free(args_buf);
                errno = EINVAL;
                return -1;
            }
            memcpy(p, req->exec_args[i], len);
            p += len;
        }

        ssize_t result = writen(fd, args_buf, wire.args_total_len);
        free(args_buf);

        if (result != (ssize_t)wire.args_total_len) {
            return -1;
        }
    }

    return 0;
}

/* Receive a request from socket */
int recv_request(int fd, struct priv_request *req) {
    struct priv_request_wire wire;

    /* Read wire header */
    ssize_t n = readn(fd, &wire, sizeof(wire));
    if (n == 0) {
        return -1;  /* EOF */
    }
    if (n != sizeof(wire)) {
        return -1;
    }

    /* Validate wire header */
    if (wire.type > REQ_SHUTDOWN_COMPLETE) {
        return -1;  /* Invalid request type */
    }

    /* Ensure NUL-termination */
    wire.unit_name[sizeof(wire.unit_name) - 1] = '\0';
    wire.unit_path[sizeof(wire.unit_path) - 1] = '\0';
    wire.exec_path[sizeof(wire.exec_path) - 1] = '\0';
    wire.tty_path[sizeof(wire.tty_path) - 1] = '\0';

    /* Unpack fixed fields */
    req->type = wire.type;
    req->service_pid = wire.service_pid;
    strncpy(req->unit_name, wire.unit_name, sizeof(req->unit_name));
    strncpy(req->unit_path, wire.unit_path, sizeof(req->unit_path));
    strncpy(req->exec_path, wire.exec_path, sizeof(req->exec_path));
    req->run_uid = wire.run_uid;
    req->run_gid = wire.run_gid;
    req->private_tmp = wire.private_tmp;
    req->limit_nofile = wire.limit_nofile;
    req->kill_mode = wire.kill_mode;
    req->standard_input = wire.standard_input;
    req->standard_output = wire.standard_output;
    req->standard_error = wire.standard_error;
    strncpy(req->tty_path, wire.tty_path, sizeof(req->tty_path));
    req->start_limit_interval_sec = wire.start_limit_interval_sec;
    req->start_limit_burst = wire.start_limit_burst;
    req->start_limit_action = wire.start_limit_action;
    req->restart_prevent_count = (int)wire.restart_prevent_count;
    if (req->restart_prevent_count > MAX_RESTART_STATUS) {
        req->restart_prevent_count = MAX_RESTART_STATUS;
    }
    req->restart_force_count = (int)wire.restart_force_count;
    if (req->restart_force_count > MAX_RESTART_STATUS) {
        req->restart_force_count = MAX_RESTART_STATUS;
    }
    for (int i = 0; i < MAX_RESTART_STATUS; i++) {
        req->restart_prevent_statuses[i] = wire.restart_prevent_statuses[i];
        req->restart_force_statuses[i] = wire.restart_force_statuses[i];
    }

    /* Unpack exec_args */
    req->exec_args = NULL;

    if (wire.arg_count > 0) {
        /* Sanity check */
        if (wire.arg_count > 1024 || wire.args_total_len > 1024 * 1024) {
            return -1;  /* Unreasonable size */
        }

        /* Allocate args buffer */
        char *args_buf = calloc(1, wire.args_total_len);
        if (!args_buf) {
            return -1;
        }

        /* Read packed args */
        if (readn(fd, args_buf, wire.args_total_len) != (ssize_t)wire.args_total_len) {
            free(args_buf);
            return -1;
        }

        /* Allocate argv array (NULL-terminated) */
        req->exec_args = calloc(wire.arg_count + 1, sizeof(char *));
        if (!req->exec_args) {
            free(args_buf);
            return -1;
        }

        /* Parse concatenated NUL-terminated strings */
        char *p = args_buf;
        size_t remaining = wire.args_total_len;

        for (uint32_t i = 0; i < wire.arg_count; i++) {
            /* Find NUL terminator */
            size_t len = strnlen(p, remaining);
            if (len >= remaining) {
                /* Missing NUL terminator */
                free(args_buf);
                free(req->exec_args);
                req->exec_args = NULL;
                return -1;
            }

            /* Duplicate string */
            req->exec_args[i] = strdup(p);
            if (!req->exec_args[i]) {
                /* Cleanup on failure */
                for (uint32_t j = 0; j < i; j++) {
                    free(req->exec_args[j]);
                }
                free(req->exec_args);
                free(args_buf);
                req->exec_args = NULL;
                return -1;
            }

            p += len + 1;  /* Skip string + NUL */
            remaining -= len + 1;
        }

        free(args_buf);
        req->exec_args[wire.arg_count] = NULL;  /* NULL-terminate argv */
    }

    return 0;
}

/* Send a response over socket */
int send_response(int fd, const struct priv_response *resp) {
    struct priv_response_wire wire;

    /* Zero-initialize to avoid sending uninitialized padding bytes */
    memset(&wire, 0, sizeof(wire));

    /* Pack fields */
    wire.type = resp->type;
    wire.error_code = resp->error_code;
    wire.service_pid = resp->service_pid;
    wire.exit_status = resp->exit_status;

    /* Copy and ensure NUL-termination */
    strncpy(wire.error_msg, resp->error_msg, sizeof(wire.error_msg) - 1);
    wire.error_msg[sizeof(wire.error_msg) - 1] = '\0';

    strncpy(wire.converted_path, resp->converted_path, sizeof(wire.converted_path) - 1);
    wire.converted_path[sizeof(wire.converted_path) - 1] = '\0';

    /* Send wire struct */
    if (writen(fd, &wire, sizeof(wire)) != sizeof(wire)) {
        return -1;
    }

    return 0;
}

/* Receive a response from socket */
int recv_response(int fd, struct priv_response *resp) {
    struct priv_response_wire wire;

    /* Read wire struct */
    ssize_t n = readn(fd, &wire, sizeof(wire));
    if (n == 0) {
        return -1;  /* EOF */
    }
    if (n != sizeof(wire)) {
        return -1;
    }

    /* Validate */
    if (wire.type > RESP_SERVICE_RELOADED) {
        return -1;  /* Invalid response type */
    }

    /* Ensure NUL-termination */
    wire.error_msg[sizeof(wire.error_msg) - 1] = '\0';
    wire.converted_path[sizeof(wire.converted_path) - 1] = '\0';

    /* Unpack */
    resp->type = wire.type;
    resp->error_code = wire.error_code;
    resp->service_pid = wire.service_pid;
    resp->exit_status = wire.exit_status;
    strncpy(resp->error_msg, wire.error_msg, sizeof(resp->error_msg));
    strncpy(resp->converted_path, wire.converted_path, sizeof(resp->converted_path));

    return 0;
}

/* Free dynamically allocated fields in a request */
void free_request(struct priv_request *req) {
    if (!req) {
        return;
    }

    if (req->exec_args) {
        for (int i = 0; req->exec_args[i] != NULL; i++) {
            free(req->exec_args[i]);
        }
        free(req->exec_args);
        req->exec_args = NULL;
    }
}
