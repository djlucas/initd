/* control.c - Control protocol implementation
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
#include <sys/socket.h>
#include <sys/un.h>
#include "control.h"

/* Send a control request */
int send_control_request(int fd, const struct control_request *req) {
    ssize_t n = write(fd, req, sizeof(*req));
    if (n != sizeof(*req)) {
        return -1;
    }
    return 0;
}

/* Receive a control request */
int recv_control_request(int fd, struct control_request *req) {
    ssize_t n = read(fd, req, sizeof(*req));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*req)) {
        return -1;
    }
    return 0;
}

/* Send a control response */
int send_control_response(int fd, const struct control_response *resp) {
    ssize_t n = write(fd, resp, sizeof(*resp));
    if (n != sizeof(*resp)) {
        return -1;
    }
    return 0;
}

/* Receive a control response */
int recv_control_response(int fd, struct control_response *resp) {
    ssize_t n = read(fd, resp, sizeof(*resp));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*resp)) {
        return -1;
    }
    return 0;
}

/* Connect to supervisor control socket */
int connect_to_supervisor(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

/* Connect to timer daemon control socket */
int connect_to_timer_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TIMER_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

/* Connect to socket activator control socket */
int connect_to_socket_activator(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_ACTIVATOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

/* Convert unit state to string */
const char *state_to_string(enum unit_state_response state) {
    switch (state) {
    case UNIT_STATE_INACTIVE:     return "inactive";
    case UNIT_STATE_ACTIVATING:   return "activating";
    case UNIT_STATE_ACTIVE:       return "active";
    case UNIT_STATE_DEACTIVATING: return "deactivating";
    case UNIT_STATE_FAILED:       return "failed";
    case UNIT_STATE_UNKNOWN:      return "unknown";
    default:                      return "invalid";
    }
}

/* Convert command to string */
const char *command_to_string(enum control_command cmd) {
    switch (cmd) {
    case CMD_START:         return "start";
    case CMD_STOP:          return "stop";
    case CMD_RESTART:       return "restart";
    case CMD_RELOAD:        return "reload";
    case CMD_ENABLE:        return "enable";
    case CMD_DISABLE:       return "disable";
    case CMD_STATUS:        return "status";
    case CMD_IS_ACTIVE:     return "is-active";
    case CMD_IS_ENABLED:    return "is-enabled";
    case CMD_LIST_UNITS:    return "list-units";
    case CMD_LIST_TIMERS:   return "list-timers";
    case CMD_LIST_SOCKETS:  return "list-sockets";
    case CMD_DAEMON_RELOAD: return "daemon-reload";
    case CMD_ISOLATE:       return "isolate";
    default:                return "unknown";
    }
}

/* Send unit list */
int send_unit_list(int fd, const struct unit_list_entry *entries, size_t count) {
    /* Send count first */
    uint32_t count32 = (uint32_t)count;
    ssize_t n = write(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    /* Send entries */
    if (count > 0) {
        size_t total = count * sizeof(struct unit_list_entry);
        n = write(fd, entries, total);
        if (n != (ssize_t)total) {
            return -1;
        }
    }

    return 0;
}

/* Receive unit list */
int recv_unit_list(int fd, struct unit_list_entry **entries, size_t *count) {
    /* Receive count */
    uint32_t count32;
    ssize_t n = read(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    *count = count32;

    /* No entries? */
    if (*count == 0) {
        *entries = NULL;
        return 0;
    }

    /* Allocate entries */
    *entries = malloc(*count * sizeof(struct unit_list_entry));
    if (!*entries) {
        return -1;
    }

    /* Receive entries */
    size_t total = *count * sizeof(struct unit_list_entry);
    n = read(fd, *entries, total);
    if (n != (ssize_t)total) {
        free(*entries);
        *entries = NULL;
        return -1;
    }

    return 0;
}

/* Send timer list */
int send_timer_list(int fd, const struct timer_list_entry *entries, size_t count) {
    /* Send count first */
    uint32_t count32 = (uint32_t)count;
    ssize_t n = write(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    /* Send entries */
    if (count > 0) {
        size_t total = count * sizeof(struct timer_list_entry);
        n = write(fd, entries, total);
        if (n != (ssize_t)total) {
            return -1;
        }
    }

    return 0;
}

/* Receive timer list */
int recv_timer_list(int fd, struct timer_list_entry **entries, size_t *count) {
    /* Receive count */
    uint32_t count32;
    ssize_t n = read(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    *count = count32;

    /* No entries? */
    if (*count == 0) {
        *entries = NULL;
        return 0;
    }

    /* Allocate entries */
    *entries = malloc(*count * sizeof(struct timer_list_entry));
    if (!*entries) {
        return -1;
    }

    /* Receive entries */
    size_t total = *count * sizeof(struct timer_list_entry);
    n = read(fd, *entries, total);
    if (n != (ssize_t)total) {
        free(*entries);
        *entries = NULL;
        return -1;
    }

    return 0;
}

/* Send socket list */
int send_socket_list(int fd, const struct socket_list_entry *entries, size_t count) {
    /* Send count first */
    uint32_t count32 = count;
    ssize_t n = write(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    /* Send entries */
    if (count > 0) {
        size_t total = count * sizeof(struct socket_list_entry);
        n = write(fd, entries, total);
        if (n != (ssize_t)total) {
            return -1;
        }
    }

    return 0;
}

/* Receive socket list */
int recv_socket_list(int fd, struct socket_list_entry **entries, size_t *count) {
    /* Receive count */
    uint32_t count32;
    ssize_t n = read(fd, &count32, sizeof(count32));
    if (n != sizeof(count32)) {
        return -1;
    }

    *count = count32;

    /* No entries? */
    if (*count == 0) {
        *entries = NULL;
        return 0;
    }

    /* Allocate entries */
    *entries = malloc(*count * sizeof(struct socket_list_entry));
    if (!*entries) {
        return -1;
    }

    /* Receive entries */
    size_t total = *count * sizeof(struct socket_list_entry);
    n = read(fd, *entries, total);
    if (n != (ssize_t)total) {
        free(*entries);
        *entries = NULL;
        return -1;
    }

    return 0;
}
