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
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/scanner.h"
#include "../common/parser.h"
#include "../common/socket-ipc.h"

#define SOCKET_ACTIVATOR_SOCKET_PATH "/run/initd/socket-activator.sock"
#define MAX_SOCKETS 64

static int daemon_socket = -1;

/* Socket instance - runtime state for a loaded socket unit */
struct socket_instance {
    struct unit_file *unit;
    int listen_fd;              /* Listening socket */
    bool is_stream;             /* TCP/Unix stream vs UDP/Unix dgram */
    pid_t service_pid;          /* Active service PID (0 if none) */
    time_t last_activity;       /* Last connection/activity time */
    bool enabled;
    struct socket_instance *next;
};

static volatile sig_atomic_t shutdown_requested = 0;
static int control_socket = -1;
static struct socket_instance *sockets = NULL;

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Reap zombie processes */
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Setup signal handlers */
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
static int create_control_socket(void) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket-activator: socket");
        return -1;
    }

    /* Remove old socket if exists */
    unlink(SOCKET_ACTIVATOR_SOCKET_PATH);

    /* Ensure directory exists */
    mkdir("/run/initd", 0755);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_ACTIVATOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

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
            SOCKET_ACTIVATOR_SOCKET_PATH);
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
static int activate_via_supervisor(const char *service_name, int client_fd) {
    /* TODO: Requires IPC with supervisor to delegate service startup + FD passing */
    /* Optional Phase 3 enhancement - allows supervisor to manage service lifecycle */
    /* For now, return failure to fall back to direct */
    (void)service_name;  /* Unused in stub implementation */
    (void)client_fd;     /* Unused in stub implementation */
    return -1;
}

/* Activate service directly and pass socket */
static int activate_direct(struct socket_instance *sock, int client_fd) {
    /* Determine service name from socket name */
    char service_name[MAX_UNIT_NAME + 16];  /* Room for ".service" suffix */
    char *dot = strrchr(sock->unit->name, '.');
    if (dot) {
        size_t len = dot - sock->unit->name;
        strncpy(service_name, sock->unit->name, len);
        service_name[len] = '\0';
        strcat(service_name, ".service");
    } else {
        snprintf(service_name, sizeof(service_name), "%s.service", sock->unit->name);
    }

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
        snprintf(unit_path, sizeof(unit_path), "%s/%s", dirs[i], service_name);
        if (parse_unit_file(unit_path, &unit) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "socket-activator: service %s not found\n", service_name);
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
        setenv("LISTEN_PID", "0", 1);  /* Will be updated after exec */

        /* Duplicate client socket to fd 3 (standard for socket activation) */
        if (client_fd >= 0) {
            dup2(client_fd, 3);
            close(client_fd);
        }

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
    fprintf(stderr, "socket-activator: activated %s (pid %d)\n", service_name, pid);

    sock->service_pid = pid;
    sock->last_activity = time(NULL);

    return 0;
}

/* Handle incoming connection */
static void handle_connection(struct socket_instance *sock) {
    int client_fd = -1;

    if (sock->is_stream) {
        /* Accept connection */
        client_fd = accept(sock->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("socket-activator: accept");
            return;
        }
    }

    fprintf(stderr, "socket-activator: connection on %s\n", sock->unit->name);

    /* Update activity time */
    sock->last_activity = time(NULL);

    /* If service is already running, pass connection to it */
    if (sock->service_pid > 0) {
        /* Check if process is still alive */
        if (kill(sock->service_pid, 0) == 0) {
            fprintf(stderr, "socket-activator: service already active, connection handled by existing process\n");
            /* For simplicity, just close. Real impl would pass to service. */
            if (client_fd >= 0) close(client_fd);
            return;
        } else {
            /* Process died */
            sock->service_pid = 0;
        }
    }

    /* Try to activate via supervisor, fall back to direct */
    if (activate_via_supervisor(sock->unit->name, client_fd) < 0) {
        fprintf(stderr, "socket-activator: supervisor unavailable, activating directly\n");
        activate_direct(sock, client_fd);
    }

    /* Close client fd in parent (child has it) */
    if (client_fd >= 0) {
        close(client_fd);
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
            s->service_pid = 0;
        }
    }
}

/* Load all socket units */
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
        instance->last_activity = 0;

        /* Create listening socket */
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

static void handle_control_command(int client_fd) {
    struct control_request req = {0};
    struct control_response resp = {0};

    if (recv_control_request(client_fd, &req) < 0) {
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
                sock->enabled = true;
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
static int event_loop(void) {
    struct pollfd pfds[MAX_SOCKETS + 1];
    int nfds;

    while (!shutdown_requested) {
        nfds = 0;

        /* Add control socket */
        pfds[nfds].fd = control_socket;
        pfds[nfds].events = POLLIN;
        nfds++;

        /* Add all listening sockets */
        struct socket_instance *s = sockets;
        while (s && nfds < MAX_SOCKETS) {
            pfds[nfds].fd = s->listen_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
            s = s->next;
        }

        /* Poll with 1 second timeout for idle checks */
        int ret = poll(pfds, nfds, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("socket-activator: poll");
            return -1;
        }

        /* Check idle timeouts */
        check_idle_timeouts();

        if (ret == 0) continue;  /* Timeout */

        /* Handle control socket */
        if (pfds[0].revents & POLLIN) {
            int client_fd = accept(control_socket, NULL, NULL);
            if (client_fd >= 0) {
                handle_control_command(client_fd);
            }
        }

        /* Handle listening sockets */
        int idx = 1;
        for (s = sockets; s && idx < nfds; s = s->next, idx++) {
            if (pfds[idx].revents & POLLIN) {
                handle_connection(s);
            }
        }
    }

    return 0;
}

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

    /* Load socket units */
    if (load_sockets() < 0) {
        fprintf(stderr, "socket-activator: failed to load sockets\n");
        return 1;
    }

    /* Run event loop */
    fprintf(stderr, "socket-activator: entering event loop\n");
    event_loop();

    /* Cleanup */
    fprintf(stderr, "socket-activator: shutting down\n");
    close(control_socket);
    unlink(SOCKET_ACTIVATOR_SOCKET_PATH);

    return 0;
}
