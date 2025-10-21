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
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "control.h"

static char runtime_dir_buf[PATH_MAX];
static bool runtime_dir_initialized = false;

static char control_path_buf[PATH_MAX];
static bool control_path_initialized = false;
static char control_status_path_buf[PATH_MAX];
static bool control_status_path_initialized = false;

static char timer_path_buf[PATH_MAX];
static bool timer_path_initialized = false;
static char timer_status_path_buf[PATH_MAX];
static bool timer_status_path_initialized = false;

static char socket_path_buf[PATH_MAX];
static bool socket_path_initialized = false;
static char socket_status_path_buf[PATH_MAX];
static bool socket_status_path_initialized = false;

static void invalidate_path_caches(void) {
    control_path_initialized = false;
    control_status_path_initialized = false;
    timer_path_initialized = false;
    timer_status_path_initialized = false;
    socket_path_initialized = false;
    socket_status_path_initialized = false;
}

static int set_runtime_dir_internal(const char *path) {
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    size_t len = strnlen(path, PATH_MAX);
    if (len == PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(runtime_dir_buf, path, len);
    runtime_dir_buf[len] = '\0';

    /* Strip trailing slashes while keeping root intact */
    while (len > 1 && runtime_dir_buf[len - 1] == '/') {
        runtime_dir_buf[--len] = '\0';
    }

    runtime_dir_initialized = true;
    invalidate_path_caches();
    return 0;
}

static const char *initd_runtime_dir(void) {
    if (!runtime_dir_initialized) {
        const char *env = getenv(INITD_RUNTIME_DIR_ENV);
        if (!env || env[0] == '\0') {
            env = INITD_RUNTIME_DEFAULT;
        }
        if (set_runtime_dir_internal(env) < 0) {
            /* Fallback to default if env is invalid */
            set_runtime_dir_internal(INITD_RUNTIME_DEFAULT);
        }
    }
    return runtime_dir_buf;
}

int initd_set_runtime_dir(const char *path) {
    const char *target = path;
    if (!target || target[0] == '\0') {
        const char *env = getenv(INITD_RUNTIME_DIR_ENV);
        target = (env && env[0] != '\0') ? env : INITD_RUNTIME_DEFAULT;
    }
    return set_runtime_dir_internal(target);
}

int initd_ensure_runtime_dir(void) {
    const char *dir = initd_runtime_dir();
    if (!dir) {
        return -1;
    }

    if (mkdir(dir, 0755) < 0) {
        if (errno == EEXIST) {
            return 0;
        }
        return -1;
    }
    return 0;
}

int initd_default_user_runtime_dir(char *buf, size_t len) {
    if (!buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    int written = -1;

#ifdef __linux__
    /* On Linux, check if /run/user/$UID exists */
    unsigned int uid = (unsigned int)getuid();
    char run_user_dir[PATH_MAX];
    snprintf(run_user_dir, sizeof(run_user_dir), "/run/user/%u", uid);
    struct stat st;
    if (stat(run_user_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        written = snprintf(buf, len, "%s/initd", run_user_dir);
    }
#endif

    /* Fallback to XDG_RUNTIME_DIR if set */
    if (written < 0) {
        const char *xdg = getenv("XDG_RUNTIME_DIR");
        if (xdg && xdg[0] != '\0') {
            written = snprintf(buf, len, "%s/initd", xdg);
        }
    }

    /* No suitable runtime directory found */
    if (written < 0) {
        errno = ENOENT;
        return -1;
    }

    if ((size_t)written >= len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static int build_socket_path(char *buffer, size_t buflen, const char *filename) {
    if (!buffer || buflen == 0 || !filename) {
        errno = EINVAL;
        return -1;
    }

    const char *dir = initd_runtime_dir();
    if (!dir) {
        return -1;
    }

    int written = snprintf(buffer, buflen, "%s/%s", dir, filename);
    if (written < 0 || (size_t)written >= buflen) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

const char *control_socket_path(bool status) {
    char *buf = status ? control_status_path_buf : control_path_buf;
    size_t len = status ? sizeof(control_status_path_buf) : sizeof(control_path_buf);
    bool *initialized = status ? &control_status_path_initialized : &control_path_initialized;

    if (!*initialized) {
        if (build_socket_path(buf, len,
                              status ? CONTROL_STATUS_SOCKET_NAME : CONTROL_SOCKET_NAME) < 0) {
            return NULL;
        }
        *initialized = true;
    }

    return buf;
}

const char *timer_socket_path(bool status) {
    char *buf = status ? timer_status_path_buf : timer_path_buf;
    size_t len = status ? sizeof(timer_status_path_buf) : sizeof(timer_path_buf);
    bool *initialized = status ? &timer_status_path_initialized : &timer_path_initialized;

    if (!*initialized) {
        if (build_socket_path(buf, len,
                              status ? TIMER_STATUS_SOCKET_NAME : TIMER_SOCKET_NAME) < 0) {
            return NULL;
        }
        *initialized = true;
    }

    return buf;
}

const char *socket_activator_socket_path(bool status) {
    char *buf = status ? socket_status_path_buf : socket_path_buf;
    size_t len = status ? sizeof(socket_status_path_buf) : sizeof(socket_path_buf);
    bool *initialized = status ? &socket_status_path_initialized : &socket_path_initialized;

    if (!*initialized) {
        if (build_socket_path(buf, len,
                              status ? SOCKET_ACTIVATOR_STATUS_SOCKET_NAME : SOCKET_ACTIVATOR_SOCKET_NAME) < 0) {
            return NULL;
        }
        *initialized = true;
    }

    return buf;
}

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
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = control_socket_path(false);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
        close(fd);
        return -1;
    }

    return fd;
}

int connect_to_supervisor_status(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = control_socket_path(true);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
        close(fd);
        return -1;
    }

    return fd;
}

/* Connect to timer daemon control socket */
int connect_to_timer_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = timer_socket_path(false);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
        close(fd);
        return -1;
    }

    return fd;
}

int connect_to_timer_status(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = timer_socket_path(true);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
        close(fd);
        return -1;
    }

    return fd;
}

/* Connect to socket activator control socket */
int connect_to_socket_activator(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = socket_activator_socket_path(false);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
        close(fd);
        return -1;
    }

    return fd;
}

int connect_to_socket_status(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *path = socket_activator_socket_path(true);
    if (!path) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != ENOENT && errno != ECONNREFUSED) {
            perror("connect");
        }
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
    case CMD_NOTIFY_INACTIVE:return "notify-inactive";
    case CMD_SOCKET_ADOPT:  return "socket-adopt";
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

/* Detect if we're running as part of the initd init system vs standalone */
bool initd_is_running_as_init(void) {
    const char *mode = getenv("INITD_MODE");
    return (mode && strcmp(mode, "init") == 0);
}
