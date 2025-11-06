/* control.c - Control protocol implementation
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
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
#include <fcntl.h>
#include <stdbool.h>
#include "control.h"
#include "log.h"

/* SECURITY: Upper bound for IPC list counts to prevent multi-gigabyte allocations */
#define MAX_IPC_LIST_COUNT 10000

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

    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        return -1;
    }

    struct stat st;
    if (lstat(dir, &st) < 0) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    uid_t owner = st.st_uid;
    uid_t expected = geteuid();
    /* Allow root-owned directory or directory owned by the current user */
    if (owner != 0 && owner != expected) {
        errno = EPERM;
        return -1;
    }

    /* Normalise permissions */
    if ((st.st_mode & 0777) != 0755) {
        if (chmod(dir, 0755) < 0) {
            return -1;
        }
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
    if (stat(run_user_dir, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == uid && (st.st_mode & S_IWOTH) == 0) {
        written = snprintf(buf, len, "%s/initd", run_user_dir);
    }
#endif

    /* Fallback to XDG_RUNTIME_DIR if set */
    if (written < 0) {
        const char *xdg = getenv("XDG_RUNTIME_DIR");
        if (xdg && xdg[0] != '\0') {
            struct stat xdg_st;
            if (stat(xdg, &xdg_st) == 0 && S_ISDIR(xdg_st.st_mode) &&
                xdg_st.st_uid == getuid() && (xdg_st.st_mode & S_IWOTH) == 0) {
                written = snprintf(buf, len, "%s/initd", xdg);
            }
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

int ensure_component_runtime_dir(const char *component_name,
                                 uid_t target_uid,
                                 gid_t target_gid,
                                 bool user_mode) {
    if (!component_name || component_name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    const char *runtime_dir = initd_runtime_dir();
    if (!runtime_dir) {
        return -1;
    }

    size_t runtime_len = strnlen(runtime_dir, PATH_MAX);
    size_t component_len = strnlen(component_name, PATH_MAX);
    if (runtime_len == PATH_MAX || component_len == PATH_MAX ||
        runtime_len + 1 + component_len + 1 > PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int parent_fd = open(runtime_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) {
        log_msg(LOG_ERR, "runtime",
                "open runtime dir %s failed: %s",
                runtime_dir, strerror(errno));
        return -1;
    }

    struct stat st;
    if (mkdirat(parent_fd, component_name, 0755) < 0 && errno != EEXIST) {
        int saved = errno;
        close(parent_fd);
        log_msg(LOG_ERR, "runtime",
                "mkdir %s/%s failed: %s",
                runtime_dir, component_name, strerror(saved));
        errno = saved;
        return -1;
    }

    if (fstatat(parent_fd, component_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        int saved = errno;
        close(parent_fd);
        log_msg(LOG_ERR, "runtime",
                "stat %s/%s failed: %s",
                runtime_dir, component_name, strerror(saved));
        errno = saved;
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        close(parent_fd);
        log_msg(LOG_ERR, "runtime",
                "path %s/%s is not a directory",
                runtime_dir, component_name);
        errno = ENOTDIR;
        return -1;
    }

    uid_t desired_uid = user_mode ? getuid() : target_uid;
    gid_t desired_gid = user_mode ? getgid() : target_gid;

    if (st.st_uid != desired_uid || st.st_gid != desired_gid) {
        if (fchownat(parent_fd, component_name, desired_uid, desired_gid,
                     AT_SYMLINK_NOFOLLOW) < 0) {
            int saved = errno;
            close(parent_fd);
            log_msg(LOG_ERR, "runtime",
                    "chown %s/%s to %u:%u failed: %s",
                    runtime_dir, component_name,
                    (unsigned)desired_uid, (unsigned)desired_gid,
                    strerror(saved));
            errno = saved;
            return -1;
        }
    }

    if ((st.st_mode & 0777) != 0755) {
        if (fchmodat(parent_fd, component_name, 0755, 0) < 0) {
            int saved = errno;
            close(parent_fd);
            log_msg(LOG_ERR, "runtime",
                    "chmod %s/%s failed: %s",
                    runtime_dir, component_name, strerror(saved));
            errno = saved;
            return -1;
        }
    }

    close(parent_fd);
    return 0;
}

static int check_directory_safety(const char *path, uid_t expected_owner, bool allow_sticky_world_write) {
    struct stat st;
    if (lstat(path, &st) < 0) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    if (st.st_uid != expected_owner) {
        /* Allow root-owned parents for user mode to accommodate /run/user/$UID */
        if (!(expected_owner == getuid() && st.st_uid == 0)) {
            errno = EPERM;
            return -1;
        }
    }

    if ((st.st_mode & S_IWOTH) && (!allow_sticky_world_write || !(st.st_mode & S_ISVTX))) {
        errno = EPERM;
        return -1;
    }

    return 0;
}

int initd_validate_runtime_dir(const char *path, bool user_mode) {
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (path[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    size_t len = strnlen(path, PATH_MAX);
    if (len == PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (strcmp(path, "/") == 0) {
        errno = EINVAL;
        return -1;
    }

    char target_path[PATH_MAX];
    memcpy(target_path, path, len + 1);

    /* Remove trailing slashes from target path (except root) */
    size_t clean_len = len;
    while (clean_len > 1 && target_path[clean_len - 1] == '/') {
        target_path[--clean_len] = '\0';
    }

    char parent_buf[PATH_MAX];
    memcpy(parent_buf, target_path, clean_len + 1);
    const char *parent_path = "/";
    if (clean_len > 1) {
        char *last_slash = strrchr(parent_buf, '/');
        if (last_slash) {
            if (last_slash == parent_buf) {
                parent_path = "/";
            } else {
                *last_slash = '\0';
                parent_path = parent_buf;
            }
        }
    }

    char resolved_parent[PATH_MAX];
    if (!realpath(parent_path, resolved_parent)) {
        log_msg(LOG_ERR, "runtime", "realpath(%s) failed: %s",
                parent_path, strerror(errno));
        return -1;
    }

    uid_t expected_parent_owner = user_mode ? getuid() : 0;
    bool allow_sticky = true;
    if (check_directory_safety(resolved_parent, expected_parent_owner, allow_sticky) < 0) {
        log_msg(LOG_ERR, "runtime", "invalid parent directory %s", resolved_parent);
        return -1;
    }

    struct stat st;
    if (lstat(target_path, &st) == 0) {
        uid_t expected_owner = user_mode ? getuid() : 0;
        if (check_directory_safety(target_path, expected_owner, false) < 0) {
            log_msg(LOG_ERR, "runtime", "invalid runtime directory %s", target_path);
            return -1;
        }
    } else if (errno != ENOENT) {
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

/* Receive a control request
 * SECURITY: Ensures all string fields are NUL-terminated to prevent
 * buffer overruns when passed to strcmp/strlen/printf */
int recv_control_request(int fd, struct control_request *req) {
    ssize_t n = read(fd, req, sizeof(*req));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*req)) {
        return -1;
    }

    /* SECURITY: Force NUL termination of unit_name to prevent overrun.
     * Without this, an attacker can send 256 non-zero bytes causing strcmp(),
     * strlen(), and printf() to read past the buffer into stack memory,
     * leading to crash or information disclosure. */
    req->unit_name[sizeof(req->unit_name) - 1] = '\0';

    /* Reject if unit_name contains no NUL byte (completely filled) */
    if (memchr(req->unit_name, '\0', sizeof(req->unit_name) - 1) == NULL) {
        errno = EINVAL;
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

/* Receive a control response
 * SECURITY: Ensures all string fields are NUL-terminated */
int recv_control_response(int fd, struct control_response *resp) {
    ssize_t n = read(fd, resp, sizeof(*resp));
    if (n == 0) {
        return -1; /* EOF */
    }
    if (n != sizeof(*resp)) {
        return -1;
    }

    /* SECURITY: Force NUL termination of message field */
    resp->message[sizeof(resp->message) - 1] = '\0';

    /* Reject if message contains no NUL byte (completely filled) */
    if (memchr(resp->message, '\0', sizeof(resp->message) - 1) == NULL) {
        errno = EINVAL;
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
    case CMD_POWEROFF:      return "poweroff";
    case CMD_REBOOT:        return "reboot";
    case CMD_HALT:          return "halt";
    case CMD_DUMP_LOGS:     return "dump-logs";
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

/* Receive unit list
 * SECURITY: Ensures all string fields in all entries are NUL-terminated */
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

    /* SECURITY: Enforce sanity limit to prevent multi-gigabyte allocations */
    if (*count > MAX_IPC_LIST_COUNT) {
        errno = ENOMEM;
        return -1;
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

    /* SECURITY: Force NUL termination of all string fields */
    for (size_t i = 0; i < *count; i++) {
        (*entries)[i].name[sizeof((*entries)[i].name) - 1] = '\0';
        (*entries)[i].description[sizeof((*entries)[i].description) - 1] = '\0';
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

/* Receive timer list
 * SECURITY: Ensures all string fields in all entries are NUL-terminated */
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

    /* SECURITY: Enforce sanity limit to prevent multi-gigabyte allocations */
    if (*count > MAX_IPC_LIST_COUNT) {
        errno = ENOMEM;
        return -1;
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

    /* SECURITY: Force NUL termination of all string fields */
    for (size_t i = 0; i < *count; i++) {
        (*entries)[i].name[sizeof((*entries)[i].name) - 1] = '\0';
        (*entries)[i].unit[sizeof((*entries)[i].unit) - 1] = '\0';
        (*entries)[i].description[sizeof((*entries)[i].description) - 1] = '\0';
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

/* Receive socket list
 * SECURITY: Ensures all string fields in all entries are NUL-terminated */
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

    /* SECURITY: Enforce sanity limit to prevent multi-gigabyte allocations */
    if (*count > MAX_IPC_LIST_COUNT) {
        errno = ENOMEM;
        return -1;
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

    /* SECURITY: Force NUL termination of all string fields */
    for (size_t i = 0; i < *count; i++) {
        (*entries)[i].name[sizeof((*entries)[i].name) - 1] = '\0';
        (*entries)[i].listen[sizeof((*entries)[i].listen) - 1] = '\0';
        (*entries)[i].unit[sizeof((*entries)[i].unit) - 1] = '\0';
        (*entries)[i].description[sizeof((*entries)[i].description) - 1] = '\0';
    }

    return 0;
}

/* Detect if we're running as part of the initd init system vs standalone */
bool initd_is_running_as_init(void) {
    const char *mode = getenv("INITD_MODE");
    return (mode && strcmp(mode, "init") == 0);
}
