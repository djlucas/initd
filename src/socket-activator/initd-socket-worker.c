/* initd-socket-worker.c - Unprivileged socket activation worker
 *
 * Responsibilities:
 * - Parse .socket unit files
 * - Create and listen on sockets (TCP/UDP/Unix)
 * - Activate services on connection
 * - Pass file descriptors to services
 * - Implement idle timeout (kill service when idle)
 * - Accept control commands via Unix socket
 * - Send privileged requests to daemon via IPC
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdbool.h>
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/scanner.h"
#include "../common/parser.h"
#include "../common/socket-ipc.h"

#define MAX_SOCKETS 64

static int daemon_socket = -1;

/* Socket instance - runtime state for a loaded socket unit */
struct socket_instance {
    struct unit_file *unit;
    int listen_fd;              /* Listening socket */
    bool is_stream;             /* TCP/Unix stream vs UDP/Unix dgram */
    pid_t service_pid;          /* Active service PID (0 if none) */
    char service_name[MAX_UNIT_NAME];
    time_t service_start;       /* Time when current service started */
    time_t last_activity;       /* Last connection/activity time */
    int runtime_max_sec;        /* Max runtime for activated service */
    bool enabled;
    struct socket_instance *next;
};

static volatile sig_atomic_t shutdown_requested = 0;
static int control_socket = -1;
static int status_socket = -1;
static struct socket_instance *sockets = NULL;

#ifdef UNIT_TEST
static int test_idle_kill_count = 0;
static int test_runtime_kill_count = 0;
#endif

static void derive_service_name(struct socket_instance *sock) {
    const char *unit_name = sock->unit->name;
    const char *dot = strrchr(unit_name, '.');
    size_t base_len = dot && strcmp(dot, ".socket") == 0 ?
        (size_t)(dot - unit_name) : strlen(unit_name);
    if (base_len >= sizeof(sock->service_name)) {
        base_len = sizeof(sock->service_name) - 1;
    }
    memcpy(sock->service_name, unit_name, base_len);
    sock->service_name[base_len] = '\0';
    strncat(sock->service_name, ".service",
            sizeof(sock->service_name) - strlen(sock->service_name) - 1);
}

/* Notify supervisor about socket-managed service state */
static void notify_supervisor_socket_state(const struct socket_instance *sock, pid_t pid) {
    if (!sock || sock->service_name[0] == '\0') {
        return;
    }

    int fd = connect_to_supervisor();
    if (fd < 0) {
        fprintf(stderr, "socket-activator: failed to notify supervisor for %s\n",
                sock->service_name);
        return;
    }

    struct control_request req = {0};
    struct control_response resp = {0};

    req.header.length = sizeof(req);
    req.header.command = CMD_SOCKET_ADOPT;
    strncpy(req.unit_name, sock->service_name, sizeof(req.unit_name) - 1);
    req.aux_pid = (uint32_t)(pid > 0 ? pid : 0);

    if (send_control_request(fd, &req) < 0) {
        close(fd);
        return;
    }

    if (recv_control_response(fd, &resp) < 0) {
        close(fd);
        return;
    }

    close(fd);

    if (resp.code != RESP_SUCCESS) {
        fprintf(stderr, "socket-activator: supervisor refused adopt for %s: %s\n",
                sock->service_name, resp.message);
    }
}

static void mark_service_exit(pid_t pid) {
    for (struct socket_instance *s = sockets; s; s = s->next) {
        if (s->service_pid == pid) {
            fprintf(stderr, "socket-activator: service for %s exited (pid %d)\n",
                    s->unit->name, pid);
            s->service_pid = 0;
            s->service_start = 0;
            s->last_activity = 0;
            s->runtime_max_sec = 0;
            notify_supervisor_socket_state(s, 0);
            break;
        }
    }
}

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Reap zombie processes */
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        mark_service_exit(pid);
    }
}

/* Setup signal handlers */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("socket-activator: sigaction SIGTERM");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("socket-activator: sigaction SIGINT");
        return -1;
    }

    /* Handle SIGCHLD to reap zombies */
    sa.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("socket-activator: sigaction SIGCHLD");
        return -1;
    }

    return 0;
}

/* Create control socket */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_control_socket(void) {
    const char *path = socket_activator_socket_path(false);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        perror("socket-activator: mkdir runtime dir");
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket-activator: socket");
        return -1;
    }

    /* Remove old socket if exists */
    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("socket-activator: bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("socket-activator: listen");
        close(fd);
        return -1;
    }

    /* Set permissions - use fchmod to avoid race condition */
    fchmod(fd, 0666);

    fprintf(stderr, "socket-activator: control socket created at %s\n",
            path);
    return fd;
}

#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int create_status_socket(void) {
    const char *path = socket_activator_socket_path(true);
    if (!path) {
        return -1;
    }

    if (initd_ensure_runtime_dir() < 0 && errno != EEXIST) {
        perror("socket-activator: mkdir runtime dir");
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket-activator: status socket");
        return -1;
    }

    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path,
            sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("socket-activator: bind status");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("socket-activator: listen status");
        close(fd);
        return -1;
    }

    if (fchmod(fd, 0666) < 0) {
        perror("socket-activator: fchmod status");
        close(fd);
        return -1;
    }

    fprintf(stderr, "socket-activator: status socket created at %s\n",
            path);
    return fd;
}

/* Create listening socket from socket unit */
static int create_listen_socket(struct socket_instance *sock) {
    struct socket_section *s = &sock->unit->config.socket;
    int fd = -1;

    /* Unix stream socket */
    if (s->listen_stream && s->listen_stream[0] == '/') {
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket-activator: socket");
            return -1;
        }

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, s->listen_stream, sizeof(addr.sun_path) - 1);

        /* Remove old socket */
        unlink(s->listen_stream);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("socket-activator: bind");
            close(fd);
            return -1;
        }

        if (listen(fd, 128) < 0) {
            perror("socket-activator: listen");
            close(fd);
            return -1;
        }

        sock->is_stream = true;
        fprintf(stderr, "socket-activator: listening on Unix stream %s\n",
                s->listen_stream);
        return fd;
    }

    /* TCP stream socket */
    if (s->listen_stream) {
        char *colon = strchr(s->listen_stream, ':');
        if (!colon) {
            fprintf(stderr, "socket-activator: invalid ListenStream format: %s\n",
                    s->listen_stream);
            return -1;
        }

        int port = atoi(colon + 1);
        char host[256];
        size_t host_len = colon - s->listen_stream;
        strncpy(host, s->listen_stream, host_len);
        host[host_len] = '\0';

        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket-activator: socket");
            return -1;
        }

        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, host, &addr.sin_addr);
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("socket-activator: bind");
            close(fd);
            return -1;
        }

        if (listen(fd, 128) < 0) {
            perror("socket-activator: listen");
            close(fd);
            return -1;
        }

        sock->is_stream = true;
        fprintf(stderr, "socket-activator: listening on TCP %s:%d\n", host, port);
        return fd;
    }

    /* Unix datagram socket */
    if (s->listen_datagram && s->listen_datagram[0] == '/') {
        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket-activator: socket");
            return -1;
        }

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, s->listen_datagram, sizeof(addr.sun_path) - 1);

        unlink(s->listen_datagram);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("socket-activator: bind");
            close(fd);
            return -1;
        }

        sock->is_stream = false;
        fprintf(stderr, "socket-activator: listening on Unix dgram %s\n",
                s->listen_datagram);
        return fd;
    }

    /* UDP socket */
    if (s->listen_datagram) {
        char *colon = strchr(s->listen_datagram, ':');
        if (!colon) {
            fprintf(stderr, "socket-activator: invalid ListenDatagram format: %s\n",
                    s->listen_datagram);
            return -1;
        }

        int port = atoi(colon + 1);
        char host[256];
        size_t host_len = colon - s->listen_datagram;
        strncpy(host, s->listen_datagram, host_len);
        host[host_len] = '\0';

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket-activator: socket");
            return -1;
        }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, host, &addr.sin_addr);
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("socket-activator: bind");
            close(fd);
            return -1;
        }

        sock->is_stream = false;
        fprintf(stderr, "socket-activator: listening on UDP %s:%d\n", host, port);
        return fd;
    }

    return -1;
}

/* Try to activate service via supervisor */
/* Activate service directly and pass socket */
static int activate_direct(struct socket_instance *sock) {
    /* Load service unit */
    char unit_path[1024];
    struct unit_file unit;
    const char *dirs[] = {
        "/etc/initd/system",
        "/lib/initd/system",
        "/etc/systemd/system",
        "/lib/systemd/system",
        NULL
    };

    bool found = false;
    for (int i = 0; dirs[i]; i++) {
        snprintf(unit_path, sizeof(unit_path), "%s/%s", dirs[i], sock->service_name);
        if (parse_unit_file(unit_path, &unit) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "socket-activator: service %s not found\n", sock->service_name);
        return -1;
    }

    if (unit.type != UNIT_SERVICE) {
        free_unit_file(&unit);
        return -1;
    }

    if (!unit.config.service.exec_start) {
        free_unit_file(&unit);
        return -1;
    }

    int runtime_limit = unit.config.service.runtime_max_sec;

    /* Fork and exec service */
    pid_t pid = fork();
    if (pid < 0) {
        free_unit_file(&unit);
        return -1;
    }

    if (pid == 0) {
        /* Child process */

        /* Set up socket activation environment */
        char listen_fds[32];
        snprintf(listen_fds, sizeof(listen_fds), "%d", 1);
        setenv("LISTEN_FDS", listen_fds, 1);
        char listen_pid[32];
        snprintf(listen_pid, sizeof(listen_pid), "%d", (int)getpid());
        setenv("LISTEN_PID", listen_pid, 1);

        /* Duplicate listening socket to fd 3 (systemd convention) */
        if (dup2(sock->listen_fd, 3) < 0) {
            perror("socket-activator: dup2");
            exit(1);
        }

        /* Close the original listening fd in the child (fd 3 remains) */
        close(sock->listen_fd);

        /* Close other fds */
        for (int i = 4; i < 1024; i++) {
            close(i);
        }

        /* Parse and exec */
        char *argv[64];
        int argc = 0;
        char *cmd = strdup(unit.config.service.exec_start);
        char *token = strtok(cmd, " ");

        while (token && argc < 63) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        argv[argc] = NULL;

        execvp(argv[0], argv);
        perror("socket-activator: exec");
        exit(1);
    }

    /* Parent */
    free_unit_file(&unit);
    fprintf(stderr, "socket-activator: activated %s (pid %d)\n", sock->service_name, pid);

    sock->service_pid = pid;
    sock->runtime_max_sec = runtime_limit;
    sock->service_start = time(NULL);
    sock->last_activity = sock->service_start;

    notify_supervisor_socket_state(sock, pid);

    return 0;
}

/* Ensure the socket's service is active */
static void handle_socket_ready(struct socket_instance *sock) {
    time_t now = time(NULL);
    sock->last_activity = now;

    if (sock->listen_fd < 0) {
        return;
    }

    if (!sock->enabled) {
        return;
    }

    fprintf(stderr, "socket-activator: activity detected on %s\n", sock->unit->name);

    if (sock->service_pid > 0) {
        if (kill(sock->service_pid, 0) == 0) {
            /* Service is already running and will handle the connection */
            return;
        }
        /* Stale PID */
        mark_service_exit(sock->service_pid);
    }

    if (activate_direct(sock) < 0) {
        fprintf(stderr, "socket-activator: failed to activate %s\n", sock->service_name);
    }
}

/* Check for idle services to kill */
static void check_idle_timeouts(void) {
    time_t now = time(NULL);

    for (struct socket_instance *s = sockets; s; s = s->next) {
        if (s->service_pid == 0) continue;

        int idle_timeout = s->unit->config.socket.idle_timeout;
        if (idle_timeout <= 0) continue;

        time_t idle_time = now - s->last_activity;
        if (idle_time >= idle_timeout) {
            fprintf(stderr, "socket-activator: killing idle service %s (pid %d) after %ld seconds\n",
                    s->unit->name, s->service_pid, idle_time);
            kill(s->service_pid, SIGTERM);
#ifdef UNIT_TEST
            test_idle_kill_count++;
#endif
            s->service_pid = 0;
            s->service_start = 0;
            s->runtime_max_sec = 0;
            /* Avoid spamming signals; treat kill attempt as activity */
            s->last_activity = now;
        }
    }
}

/* Enforce RuntimeMaxSec for activated services */
static void check_runtime_limits(void) {
    time_t now = time(NULL);

    for (struct socket_instance *s = sockets; s; s = s->next) {
        if (s->service_pid == 0) {
            continue;
        }
        if (s->runtime_max_sec <= 0 || s->service_start == 0) {
            continue;
        }

        time_t runtime = now - s->service_start;
        if (runtime >= s->runtime_max_sec) {
            fprintf(stderr, "socket-activator: killing %s (pid %d) after RuntimeMaxSec=%d\n",
                    s->service_name, s->service_pid, s->runtime_max_sec);
            kill(s->service_pid, SIGTERM);
#ifdef UNIT_TEST
            test_runtime_kill_count++;
#endif
            s->service_pid = 0;
            s->service_start = 0;
            s->runtime_max_sec = 0;
            s->last_activity = now;
        }
    }
}

/* Load all socket units */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int load_sockets(void) {
    struct unit_file **units = NULL;
    int count = 0;

    if (scan_unit_directories(&units, &count) < 0) {
        return -1;
    }

    /* Filter for socket units */
    for (int i = 0; i < count; i++) {
        if (units[i]->type != UNIT_SOCKET) {
            continue;
        }

        struct socket_instance *instance = calloc(1, sizeof(struct socket_instance));
        if (!instance) {
            continue;
        }

        instance->unit = units[i];
        instance->enabled = units[i]->enabled;
        instance->service_pid = 0;
        instance->service_start = 0;
        instance->last_activity = 0;
        instance->runtime_max_sec = 0;

        /* Derive service name (foo.socket -> foo.service) */
        derive_service_name(instance);

        /* Create listening socket */
        instance->listen_fd = -1;
        instance->listen_fd = create_listen_socket(instance);
        if (instance->listen_fd < 0) {
            fprintf(stderr, "socket-activator: failed to create socket for %s\n",
                    units[i]->name);
            free(instance);
            continue;
        }

        /* Add to list */
        instance->next = sockets;
        sockets = instance;

        fprintf(stderr, "socket-activator: loaded %s (fd %d)\n",
                units[i]->name, instance->listen_fd);
    }

    return 0;
}

/* Handle control command */
/* Find socket by unit name */
static struct socket_instance *find_socket(const char *unit_name) {
    for (struct socket_instance *s = sockets; s; s = s->next) {
        if (strcmp(s->unit->name, unit_name) == 0) {
            return s;
        }
    }
    return NULL;
}

static bool socket_command_is_read_only(enum control_command cmd) {
    switch (cmd) {
    case CMD_STATUS:
    case CMD_IS_ACTIVE:
    case CMD_IS_ENABLED:
    case CMD_LIST_SOCKETS:
        return true;
    default:
        return false;
    }
}

static void handle_control_command(int client_fd, bool read_only) {
    struct control_request req = {0};
    struct control_response resp = {0};

    if (recv_control_request(client_fd, &req) < 0) {
        close(client_fd);
        return;
    }

    if (read_only && !socket_command_is_read_only(req.header.command)) {
        resp.header.length = sizeof(resp);
        resp.header.command = req.header.command;
        resp.code = RESP_PERMISSION_DENIED;
        snprintf(resp.message, sizeof(resp.message),
                 "Command %s requires privileged socket",
                 command_to_string(req.header.command));
        send_control_response(client_fd, &resp);
        close(client_fd);
        return;
    }

    fprintf(stderr, "socket-activator: received command %s for unit %s\n",
            command_to_string(req.header.command), req.unit_name);

    /* Set default response */
    resp.header.length = sizeof(resp);
    resp.header.command = req.header.command;
    resp.code = RESP_SUCCESS;
    snprintf(resp.message, sizeof(resp.message), "OK");

    /* Handle list-sockets command */
    if (req.header.command == CMD_LIST_SOCKETS) {
        /* Count sockets */
        size_t count = 0;
        for (struct socket_instance *s = sockets; s; s = s->next) {
            count++;
        }

        /* Build socket list */
        struct socket_list_entry *entries = NULL;
        if (count > 0) {
            entries = calloc(count, sizeof(struct socket_list_entry));
            if (!entries) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "Out of memory");
                send_control_response(client_fd, &resp);
                close(client_fd);
                return;
            }

            size_t i = 0;
            for (struct socket_instance *s = sockets; s; s = s->next) {
                strncpy(entries[i].name, s->unit->name, sizeof(entries[i].name) - 1);

                /* Determine listen address */
                struct socket_section *sock_config = &s->unit->config.socket;
                if (sock_config->listen_stream) {
                    strncpy(entries[i].listen, sock_config->listen_stream,
                           sizeof(entries[i].listen) - 1);
                } else if (sock_config->listen_datagram) {
                    strncpy(entries[i].listen, sock_config->listen_datagram,
                           sizeof(entries[i].listen) - 1);
                } else {
                    strcpy(entries[i].listen, "-");
                }

                /* Determine activated service name */
                /* Default: replace .socket with .service */
                strncpy(entries[i].unit, s->unit->name, sizeof(entries[i].unit) - 1);
                char *ext = strrchr(entries[i].unit, '.');
                if (ext) {
                    strcpy(ext, ".service");
                }

                /* State: listening if we have valid fd */
                entries[i].state = (s->listen_fd >= 0) ? UNIT_STATE_ACTIVE : UNIT_STATE_FAILED;
                entries[i].service_pid = s->service_pid;

                /* Description from unit file */
                if (s->unit->unit.description[0]) {
                    strncpy(entries[i].description, s->unit->unit.description,
                           sizeof(entries[i].description) - 1);
                } else {
                    entries[i].description[0] = '\0';
                }

                i++;
            }
        }

        /* Send response + list */
        send_control_response(client_fd, &resp);
        send_socket_list(client_fd, entries, count);
        free(entries);
        close(client_fd);
        return;
    }

    /* Handle status command */
    if (req.header.command == CMD_STATUS || req.header.command == CMD_IS_ACTIVE) {
        /* Find socket by name */
        struct socket_instance *sock = NULL;
        for (struct socket_instance *s = sockets; s; s = s->next) {
            if (strcmp(s->unit->name, req.unit_name) == 0) {
                sock = s;
                break;
            }
        }

        if (!sock) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message),
                    "Socket unit not found");
            send_control_response(client_fd, &resp);
            close(client_fd);
            return;
        }

        /* Build response */
        resp.state = (sock->listen_fd >= 0) ? UNIT_STATE_ACTIVE : UNIT_STATE_FAILED;
        resp.pid = sock->service_pid;

        if (sock->unit->unit.description[0]) {
            snprintf(resp.message, sizeof(resp.message), "%s", sock->unit->unit.description);
        } else {
            /* Derive service name from socket name */
            char service_name[MAX_UNIT_NAME];
            strncpy(service_name, sock->unit->name, sizeof(service_name) - 1);
            char *ext_pos = strrchr(service_name, '.');
            if (ext_pos) strcpy(ext_pos, ".service");
            snprintf(resp.message, sizeof(resp.message), "Socket for %s", service_name);
        }

        send_control_response(client_fd, &resp);
        close(client_fd);
        return;
    }

    /* Handle enable/disable commands */
    struct socket_instance *sock = find_socket(req.unit_name);

    switch (req.header.command) {
    case CMD_ENABLE:
        if (!sock) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Socket %s not found", req.unit_name);
        } else {
            /* Send enable request to daemon */
            struct socket_request daemon_req = {0};
            struct socket_response daemon_resp = {0};

            daemon_req.type = SOCKET_REQ_ENABLE_UNIT;
            strncpy(daemon_req.unit_name, sock->unit->name, sizeof(daemon_req.unit_name) - 1);
            strncpy(daemon_req.unit_path, sock->unit->path, sizeof(daemon_req.unit_path) - 1);

            if (send_socket_request(daemon_socket, &daemon_req) < 0 ||
                recv_socket_response(daemon_socket, &daemon_resp) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "IPC error");
            } else if (daemon_resp.type == SOCKET_RESP_ERROR) {
                resp.code = RESP_FAILURE;
                /* Truncate to fit in message buffer */
                char short_name[64];
                char short_msg[200];
                strncpy(short_name, req.unit_name, sizeof(short_name) - 1);
                short_name[sizeof(short_name) - 1] = '\0';
                strncpy(short_msg, daemon_resp.error_msg, sizeof(short_msg) - 1);
                short_msg[sizeof(short_msg) - 1] = '\0';
                snprintf(resp.message, sizeof(resp.message), "Failed to enable %s: %s",
                        short_name, short_msg);
            } else {
                if (sock->listen_fd < 0) {
                    int fd = create_listen_socket(sock);
                    if (fd < 0) {
                        resp.code = RESP_FAILURE;
                        snprintf(resp.message, sizeof(resp.message), "Failed to bind %s", req.unit_name);
                        break;
                    }
                    sock->listen_fd = fd;
                }
                sock->enabled = true;
                sock->unit->enabled = true;
                snprintf(resp.message, sizeof(resp.message), "Enabled %s", req.unit_name);
            }
        }
        break;

    case CMD_DISABLE:
        if (!sock) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Socket %s not found", req.unit_name);
        } else {
            /* Send disable request to daemon */
            struct socket_request daemon_req = {0};
            struct socket_response daemon_resp = {0};

            daemon_req.type = SOCKET_REQ_DISABLE_UNIT;
            strncpy(daemon_req.unit_name, sock->unit->name, sizeof(daemon_req.unit_name) - 1);
            strncpy(daemon_req.unit_path, sock->unit->path, sizeof(daemon_req.unit_path) - 1);

            if (send_socket_request(daemon_socket, &daemon_req) < 0 ||
                recv_socket_response(daemon_socket, &daemon_resp) < 0) {
                resp.code = RESP_FAILURE;
                snprintf(resp.message, sizeof(resp.message), "IPC error");
            } else if (daemon_resp.type == SOCKET_RESP_ERROR) {
                resp.code = RESP_FAILURE;
                /* Truncate to fit in message buffer */
                char short_name[64];
                char short_msg[200];
                strncpy(short_name, req.unit_name, sizeof(short_name) - 1);
                short_name[sizeof(short_name) - 1] = '\0';
                strncpy(short_msg, daemon_resp.error_msg, sizeof(short_msg) - 1);
                short_msg[sizeof(short_msg) - 1] = '\0';
                snprintf(resp.message, sizeof(resp.message), "Failed to disable %s: %s",
                        short_name, short_msg);
            } else {
                sock->enabled = false;
                sock->unit->enabled = false;
                if (sock->service_pid > 0) {
                    kill(sock->service_pid, SIGTERM);
                    sock->service_pid = 0;
                    sock->service_start = 0;
                    sock->runtime_max_sec = 0;
                }
                if (sock->listen_fd >= 0) {
                    close(sock->listen_fd);
                    sock->listen_fd = -1;
                    struct socket_section *sec = &sock->unit->config.socket;
                    if (sec->listen_stream && sec->listen_stream[0] == '/') {
                        unlink(sec->listen_stream);
                    }
                    if (sec->listen_datagram && sec->listen_datagram[0] == '/') {
                        unlink(sec->listen_datagram);
                    }
                }
                snprintf(resp.message, sizeof(resp.message), "Disabled %s", req.unit_name);
            }
        }
        break;

    case CMD_IS_ENABLED:
        if (!sock) {
            resp.code = RESP_UNIT_NOT_FOUND;
            snprintf(resp.message, sizeof(resp.message), "Socket %s not found", req.unit_name);
        } else {
            /* Check enabled status locally - no priv operation needed */
            sock->enabled = sock->unit->enabled;
            resp.code = sock->enabled ? RESP_SUCCESS : RESP_UNIT_INACTIVE;
            snprintf(resp.message, sizeof(resp.message), "%s", sock->enabled ? "enabled" : "disabled");
        }
        break;

    case CMD_START:
    case CMD_STOP:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message),
                "Socket units are automatically started/stopped by the activator");
        break;

    default:
        resp.code = RESP_INVALID_COMMAND;
        snprintf(resp.message, sizeof(resp.message),
                 "Socket activator: command not supported");
        break;
    }

    send_control_response(client_fd, &resp);
    close(client_fd);
}

/* Main event loop */
#ifdef UNIT_TEST
__attribute__((unused))
#endif
static int event_loop(void) {
    struct pollfd pfds[MAX_SOCKETS + 2];
    int nfds;
    int status_idx;

    while (!shutdown_requested) {
        nfds = 0;
        status_idx = -1;

        /* Add control socket */
        pfds[nfds].fd = control_socket;
        pfds[nfds].events = POLLIN;
        nfds++;

        if (status_socket >= 0) {
            status_idx = nfds;
            pfds[nfds].fd = status_socket;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        /* Add all listening sockets */
        struct socket_instance *s = sockets;
        while (s && nfds < MAX_SOCKETS) {
            if (s->listen_fd >= 0) {
                pfds[nfds].fd = s->listen_fd;
                pfds[nfds].events = POLLIN;
                nfds++;
            }
            s = s->next;
        }

        /* Poll with 1 second timeout for idle checks */
        int ret = poll(pfds, nfds, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("socket-activator: poll");
            return -1;
        }

        /* Check idle and runtime timeouts */
        check_idle_timeouts();
        check_runtime_limits();

        if (ret == 0) continue;  /* Timeout */

        /* Handle control socket */
        if (pfds[0].revents & POLLIN) {
            int client_fd = accept(control_socket, NULL, NULL);
            if (client_fd >= 0) {
                handle_control_command(client_fd, false);
            }
        }

        if (status_idx >= 0 && (pfds[status_idx].revents & POLLIN)) {
            int client_fd = accept(status_socket, NULL, NULL);
            if (client_fd >= 0) {
                handle_control_command(client_fd, true);
            }
        }

        /* Handle listening sockets */
        int idx = (status_idx >= 0) ? status_idx + 1 : 1;
        for (s = sockets; s && idx < nfds; s = s->next) {
            if (s->listen_fd < 0) {
                continue;
            }
            if (pfds[idx].revents & POLLIN) {
                handle_socket_ready(s);
            }
            idx++;
        }
    }

    return 0;
}

#ifdef UNIT_TEST
struct socket_instance *socket_worker_test_create(struct unit_file *unit) {
    struct socket_instance *inst = calloc(1, sizeof(struct socket_instance));
    if (!inst) return NULL;
    inst->unit = unit;
    inst->listen_fd = -1;
    inst->enabled = true;
    derive_service_name(inst);
    return inst;
}

int socket_worker_test_bind(struct socket_instance *inst) {
    if (!inst) return -1;
    int fd = create_listen_socket(inst);
    inst->listen_fd = fd;
    return fd;
}

void socket_worker_test_register(struct socket_instance *inst) {
    if (!inst) return;
    inst->next = sockets;
    sockets = inst;
}

void socket_worker_test_unregister_all(void) {
    struct socket_instance *cur = sockets;
    while (cur) {
        struct socket_instance *next = cur->next;
        if (cur->listen_fd >= 0) {
            close(cur->listen_fd);
        }
        cur->listen_fd = -1;
        cur->service_pid = 0;
        cur->service_start = 0;
        cur->last_activity = 0;
        cur->runtime_max_sec = 0;
        cur->next = NULL;
        cur = next;
    }
    sockets = NULL;
    test_idle_kill_count = 0;
    test_runtime_kill_count = 0;
}

void socket_worker_test_set_service(struct socket_instance *inst, pid_t pid,
                                    time_t start, time_t last, int runtime_max_sec) {
    if (!inst) return;
    inst->service_pid = pid;
    inst->service_start = start;
    inst->last_activity = last;
    inst->runtime_max_sec = runtime_max_sec;
}

pid_t socket_worker_test_get_service_pid(const struct socket_instance *inst) {
    return inst ? inst->service_pid : 0;
}

time_t socket_worker_test_get_last_activity(const struct socket_instance *inst) {
    return inst ? inst->last_activity : 0;
}

void socket_worker_test_check_idle(void) {
    check_idle_timeouts();
}

void socket_worker_test_check_runtime(void) {
    check_runtime_limits();
}

int socket_worker_test_idle_kills(void) {
    return test_idle_kill_count;
}

int socket_worker_test_runtime_kills(void) {
    return test_runtime_kill_count;
}

void socket_worker_test_reset_counters(void) {
    test_idle_kill_count = 0;
    test_runtime_kill_count = 0;
}

void socket_worker_test_destroy(struct socket_instance *inst) {
    if (!inst) return;
    if (inst->listen_fd >= 0) {
        close(inst->listen_fd);
        inst->listen_fd = -1;
    }
    free(inst);
}

void socket_worker_test_handle_control_fd(int fd) {
    handle_control_command(fd, false);
}

void socket_worker_test_handle_status_fd(int fd) {
    handle_control_command(fd, true);
}
#endif

#ifndef UNIT_TEST
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "initd-socket-worker: usage: %s <ipc_fd>\n", argv[0]);
        return 1;
    }

    /* Get IPC socket FD from command line */
    daemon_socket = atoi(argv[1]);

    fprintf(stderr, "initd-socket-worker: starting (ipc_fd=%d)\n", daemon_socket);

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    control_socket = create_control_socket();
    if (control_socket < 0) {
        return 1;
    }

    status_socket = create_status_socket();
    if (status_socket < 0) {
        close(control_socket);
        const char *ctrl_path = socket_activator_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        return 1;
    }

    /* Load socket units */
    if (load_sockets() < 0) {
        fprintf(stderr, "socket-activator: failed to load sockets\n");
        close(control_socket);
        close(status_socket);
        const char *ctrl_path = socket_activator_socket_path(false);
        if (ctrl_path) {
            unlink(ctrl_path);
        }
        const char *status_path = socket_activator_socket_path(true);
        if (status_path) {
            unlink(status_path);
        }
        return 1;
    }

    /* Run event loop */
    fprintf(stderr, "socket-activator: entering event loop\n");
    event_loop();

    /* Cleanup */
    fprintf(stderr, "socket-activator: shutting down\n");
    close(control_socket);
    const char *ctrl_path = socket_activator_socket_path(false);
    if (ctrl_path) {
        unlink(ctrl_path);
    }
    if (status_socket >= 0) {
        close(status_socket);
        const char *status_path = socket_activator_socket_path(true);
        if (status_path) {
            unlink(status_path);
        }
    }

    return 0;
}
#endif
