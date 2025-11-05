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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#ifdef __linux__
#include <sys/xattr.h>  /* For SMACK labels via fsetxattr */
#include <linux/netlink.h>  /* For AF_NETLINK sockets */
#endif
#ifdef __has_include
#  if __has_include(<mqueue.h>)
#    include <mqueue.h>
#    define HAVE_MQUEUE 1
#  endif
#else
#  ifndef __APPLE__
#    include <mqueue.h>
#    define HAVE_MQUEUE 1
#  endif
#endif
#include "../common/control.h"
#include "../common/unit.h"
#include "../common/scanner.h"
#include "../common/parser.h"
#include "../common/socket-ipc.h"
#include "../common/log-enhanced.h"

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

    /* Trigger rate limiting */
    time_t trigger_times[128];  /* Circular buffer of trigger timestamps */
    int trigger_count;          /* Number of triggers tracked */
    int trigger_index;          /* Next index to write in circular buffer */
    bool trigger_limit_hit;     /* Rate limit exceeded, refusing connections */

    /* MaxConnections= tracking for Accept=yes mode */
    int active_connections;     /* Current number of active per-connection instances */

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

/* Forward declaration */
static int run_socket_exec_command(const char *command, const char *unit_name, const char *stage);

/* Check if socket activation is within trigger rate limit
 * Returns: true if activation allowed, false if rate limit exceeded */
static bool check_trigger_limit(struct socket_instance *sock) {
    time_t now = time(NULL);
    const struct socket_section *cfg = &sock->unit->config.socket;

    /* Get configured limits (with defaults) */
    int interval = cfg->trigger_limit_interval_sec;
    int burst = cfg->trigger_limit_burst;

    /* Validate limits */
    if (interval <= 0) interval = 2;       /* Default: 2 seconds */
    if (burst <= 0) burst = 2500;          /* Default: 2500 */
    if (burst > 128) burst = 128;          /* Cap at buffer size */

    /* Count triggers within the interval window */
    int triggers_in_window = 0;
    for (int i = 0; i < sock->trigger_count && i < 128; i++) {
        if ((now - sock->trigger_times[i]) <= interval) {
            triggers_in_window++;
        }
    }

    /* Check if we've exceeded the burst limit */
    if (triggers_in_window >= burst) {
        if (!sock->trigger_limit_hit) {
            log_warn("socket-worker", "%s: Trigger rate limit exceeded (%d activations in %ds), refusing connections",
                     sock->unit->name, triggers_in_window, interval);
            sock->trigger_limit_hit = true;
        }
        return false;
    }

    /* Reset limit-hit flag if we're back under the limit */
    if (sock->trigger_limit_hit && triggers_in_window < (burst / 2)) {
        log_info("socket-worker", "%s: Trigger rate limit recovered, accepting connections",
                 sock->unit->name);
        sock->trigger_limit_hit = false;
    }

    /* Record this trigger in circular buffer */
    sock->trigger_times[sock->trigger_index] = now;
    sock->trigger_index = (sock->trigger_index + 1) % 128;
    if (sock->trigger_count < 128) {
        sock->trigger_count++;
    }

    return true;
}

static void derive_service_name(struct socket_instance *sock) {
    /* Use Service= if specified */
    if (sock->unit->config.socket.service) {
        strncpy(sock->service_name, sock->unit->config.socket.service,
                sizeof(sock->service_name) - 1);
        sock->service_name[sizeof(sock->service_name) - 1] = '\0';
        return;
    }

    /* Otherwise derive from socket name (foo.socket -> foo.service) */
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
        log_warn("socket-worker", "failed to notify supervisor for %s",
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
        log_warn("socket-worker", "supervisor refused adopt for %s: %s",
                 sock->service_name, resp.message);
    }
}

static void mark_service_exit(pid_t pid) {
    bool found = false;

    /* First check Accept=no mode (single service instance) */
    for (struct socket_instance *s = sockets; s; s = s->next) {
        if (s->service_pid == pid) {
            log_info("socket-worker", "service for %s exited (pid %d)",
                     s->unit->name, pid);
            s->service_pid = 0;
            s->service_start = 0;
            s->last_activity = 0;
            s->runtime_max_sec = 0;
            notify_supervisor_socket_state(s, 0);

            /* Run ExecStopPost if configured */
            const struct socket_section *socket_cfg = &s->unit->config.socket;
            if (socket_cfg->exec_stop_post) {
                if (run_socket_exec_command(socket_cfg->exec_stop_post, s->unit->name, "ExecStopPost") < 0) {
                    log_warn("socket-worker", "ExecStopPost failed for %s", s->unit->name);
                    /* Continue despite failure */
                }
            }

            found = true;
            break;
        }
    }

    /* If not found, it's likely an Accept=yes per-connection instance.
     * Decrement active_connections for any socket that has them. */
    if (!found) {
        for (struct socket_instance *s = sockets; s; s = s->next) {
            if (s->active_connections > 0) {
                s->active_connections--;
                log_info("socket-worker", "per-connection instance for %s exited (pid %d), "
                         "%d connections remaining",
                         s->unit->name, pid, s->active_connections);
                /* Note: We can't definitively know which socket this child belonged to
                 * without tracking PIDs, so we just decrement the first socket with
                 * active connections. This works correctly if only one socket uses
                 * Accept=yes mode. */
                break;
            }
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
        log_error("socket-worker", "sigaction SIGTERM: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_error("socket-worker", "sigaction SIGINT: %s", strerror(errno));
        return -1;
    }

    /* Handle SIGCHLD to reap zombies */
    sa.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        log_error("socket-worker", "sigaction SIGCHLD: %s", strerror(errno));
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
        log_error("socket-worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("socket-worker", "socket: %s", strerror(errno));
        return -1;
    }

    /* Remove old socket if exists */
    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("socket-worker", "bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("socket-worker", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set permissions - use fchmod to avoid race condition */
    fchmod(fd, 0666);

    log_debug("socket-worker", "Control socket created at %s", path);
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
        log_error("socket-worker", "mkdir runtime dir: %s", strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("socket-worker", "status socket: %s", strerror(errno));
        return -1;
    }

    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path,
            sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("socket-worker", "bind status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        log_error("socket-worker", "listen status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (fchmod(fd, 0666) < 0) {
        log_error("socket-worker", "fchmod status: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_debug("socket-worker", "Status socket created at %s", path);
    return fd;
}

/* Apply socket options via setsockopt */
static int apply_socket_options(int fd, const struct socket_section *s, int family) {
    int ret;

    /* KeepAlive= - SO_KEEPALIVE */
    if (s->keep_alive) {
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_KEEPALIVE: %s", strerror(errno));
            /* Non-fatal */
        }
    }

    /* SendBuffer= - SO_SNDBUF */
    if (s->send_buffer > 0) {
        ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer, sizeof(s->send_buffer));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_SNDBUF to %d: %s",
                     s->send_buffer, strerror(errno));
            /* Non-fatal */
        }
    }

    /* ReceiveBuffer= - SO_RCVBUF */
    if (s->receive_buffer > 0) {
        ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &s->receive_buffer, sizeof(s->receive_buffer));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_RCVBUF to %d: %s",
                     s->receive_buffer, strerror(errno));
            /* Non-fatal */
        }
    }

    /* Broadcast= - SO_BROADCAST */
    if (s->broadcast) {
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_BROADCAST: %s", strerror(errno));
            /* Non-fatal */
        }
    }

    /* IPTOS= - IP_TOS (IPv4 only) */
    if (s->ip_tos >= 0 && family == AF_INET) {
        ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &s->ip_tos, sizeof(s->ip_tos));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IP_TOS to %d: %s",
                     s->ip_tos, strerror(errno));
            /* Non-fatal */
        }
    }

    /* IPTTL= - IP_TTL (IPv4 only) */
    if (s->ip_ttl >= 0 && family == AF_INET) {
        ret = setsockopt(fd, IPPROTO_IP, IP_TTL, &s->ip_ttl, sizeof(s->ip_ttl));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IP_TTL to %d: %s",
                     s->ip_ttl, strerror(errno));
            /* Non-fatal */
        }
    }

    /* ReusePort= - SO_REUSEPORT (portable, but different semantics) */
    if (s->reuse_port) {
#ifdef SO_REUSEPORT
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_REUSEPORT: %s", strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_REUSEPORT not supported on this platform");
#endif
    }

    /* KeepAliveTimeSec= - TCP keepalive idle time (TCP only) */
    if (s->keep_alive_time > 0 && family == AF_INET) {
#if defined(__APPLE__)
        /* macOS uses TCP_KEEPALIVE instead of TCP_KEEPIDLE */
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &s->keep_alive_time, sizeof(s->keep_alive_time));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_KEEPALIVE to %d: %s",
                     s->keep_alive_time, strerror(errno));
        }
#elif defined(TCP_KEEPIDLE) && !defined(__OpenBSD__)
        /* Linux, FreeBSD, NetBSD */
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &s->keep_alive_time, sizeof(s->keep_alive_time));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_KEEPIDLE to %d: %s",
                     s->keep_alive_time, strerror(errno));
        }
#else
        /* OpenBSD - per-socket keepalive time not supported (sysctl only) */
        log_warn("socket-worker", "TCP keepalive time configuration not supported on this platform");
#endif
    }

    /* KeepAliveIntervalSec= - TCP keepalive interval (TCP only) */
    if (s->keep_alive_interval > 0 && family == AF_INET) {
#if defined(TCP_KEEPINTVL) && !defined(__OpenBSD__)
        /* Linux, FreeBSD, NetBSD, macOS */
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &s->keep_alive_interval, sizeof(s->keep_alive_interval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_KEEPINTVL to %d: %s",
                     s->keep_alive_interval, strerror(errno));
        }
#else
        /* OpenBSD - per-socket keepalive interval not supported */
        log_warn("socket-worker", "TCP keepalive interval configuration not supported on this platform");
#endif
    }

    /* KeepAliveProbes= - TCP keepalive probe count (TCP only) */
    if (s->keep_alive_count > 0 && family == AF_INET) {
#if defined(TCP_KEEPCNT) && !defined(__OpenBSD__)
        /* Linux, FreeBSD, NetBSD, macOS */
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &s->keep_alive_count, sizeof(s->keep_alive_count));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_KEEPCNT to %d: %s",
                     s->keep_alive_count, strerror(errno));
        }
#else
        /* OpenBSD - per-socket keepalive count not supported */
        log_warn("socket-worker", "TCP keepalive probe count configuration not supported on this platform");
#endif
    }

    /* FreeBind= - bind to non-local addresses (platform-specific) */
    if (s->free_bind && family == AF_INET) {
#if defined(__linux__)
        /* Linux: IP_FREEBIND */
        int optval = 1;
        ret = setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IP_FREEBIND: %s", strerror(errno));
        }
#elif defined(__OpenBSD__)
        /* OpenBSD: SO_BINDANY (note SOL_SOCKET level, not IPPROTO_IP) */
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_BINDANY, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_BINDANY: %s", strerror(errno));
        }
#elif defined(__FreeBSD__) || defined(__NetBSD__)
        /* FreeBSD/NetBSD: IP_BINDANY */
        int optval = 1;
        ret = setsockopt(fd, IPPROTO_IP, IP_BINDANY, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IP_BINDANY: %s", strerror(errno));
        }
#else
        /* macOS and others - not supported */
        log_warn("socket-worker", "FreeBind not supported on this platform");
#endif
    }

    /* Transparent= - IP_TRANSPARENT (Linux-only) */
    if (s->transparent && family == AF_INET) {
#if defined(__linux__) && defined(IP_TRANSPARENT)
        int optval = 1;
        ret = setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IP_TRANSPARENT: %s", strerror(errno));
        }
#else
        log_warn("socket-worker", "IP_TRANSPARENT not supported (Linux-only feature)");
#endif
    }

    /* TCPCongestion= - TCP congestion control algorithm */
    if (s->tcp_congestion && family == AF_INET) {
#if (defined(__linux__) || defined(__FreeBSD__)) && defined(TCP_CONGESTION)
        /* Linux and FreeBSD support TCP_CONGESTION */
        ret = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, s->tcp_congestion, strlen(s->tcp_congestion));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_CONGESTION to %s: %s",
                     s->tcp_congestion, strerror(errno));
        }
#else
        /* OpenBSD, NetBSD, macOS have limited/no support */
        log_warn("socket-worker", "TCP_CONGESTION not supported on this platform");
#endif
    }

    /* Mark= - SO_MARK firewall packet marking (Linux-only) */
    if (s->mark >= 0) {
#if defined(__linux__) && defined(SO_MARK)
        ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &s->mark, sizeof(s->mark));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_MARK to %d: %s",
                     s->mark, strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_MARK not supported (Linux-only feature)");
#endif
    }

    /* PassCredentials= - SO_PASSCRED for AF_UNIX (Linux-only) */
    if (s->pass_credentials && family == AF_UNIX) {
#if defined(__linux__) && defined(SO_PASSCRED)
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_PASSCRED: %s", strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_PASSCRED not supported (Linux-only feature)");
#endif
    }

    /* PassSecurity= - SO_PASSSEC for AF_UNIX (Linux-only) */
    if (s->pass_security && family == AF_UNIX) {
#if defined(__linux__) && defined(SO_PASSSEC)
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_PASSSEC, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_PASSSEC: %s", strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_PASSSEC not supported (Linux-only feature)");
#endif
    }

    /* BindIPv6Only= - IPV6_V6ONLY (portable) */
    if (s->bind_ipv6_only && family == AF_INET6) {
        int v6only;
        if (strcmp(s->bind_ipv6_only, "ipv6-only") == 0) {
            v6only = 1;
        } else if (strcmp(s->bind_ipv6_only, "both") == 0) {
            v6only = 0;
        } else {
            /* "default" - don't set, use system default */
            goto skip_ipv6_only;
        }
        ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set IPV6_V6ONLY to %d: %s",
                     v6only, strerror(errno));
        }
    skip_ipv6_only:;
    }

    /* NoDelay= - TCP_NODELAY (portable, TCP only) */
    if (s->no_delay && family == AF_INET) {
        int optval = 1;
        ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_NODELAY: %s", strerror(errno));
        }
    }

    /* DeferAcceptSec= - TCP_DEFER_ACCEPT (Linux-only, TCP only) */
    if (s->defer_accept_sec > 0 && family == AF_INET) {
#if defined(__linux__) && defined(TCP_DEFER_ACCEPT)
        ret = setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &s->defer_accept_sec,
                         sizeof(s->defer_accept_sec));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set TCP_DEFER_ACCEPT to %d: %s",
                     s->defer_accept_sec, strerror(errno));
        }
#else
        log_warn("socket-worker", "TCP_DEFER_ACCEPT not supported (Linux-only feature)");
#endif
    }

    /* Priority= - SO_PRIORITY (Linux-only) */
    if (s->priority >= 0) {
#if defined(__linux__) && defined(SO_PRIORITY)
        ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &s->priority, sizeof(s->priority));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_PRIORITY to %d: %s",
                     s->priority, strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_PRIORITY not supported (Linux-only feature)");
#endif
    }

    /* SMACK security labels (Linux-only) */
#ifdef __linux__
    /* SmackLabel= - SMACK label for the socket itself */
    if (s->smack_label) {
        ret = fsetxattr(fd, "security.SMACK64", s->smack_label,
                        strlen(s->smack_label), 0);
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SMACK64 label '%s': %s",
                     s->smack_label, strerror(errno));
        }
    }

    /* SmackLabelIPIn= - SMACK label for incoming packets */
    if (s->smack_label_ip_in) {
        ret = fsetxattr(fd, "security.SMACK64IPIN", s->smack_label_ip_in,
                        strlen(s->smack_label_ip_in), 0);
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SMACK64IPIN label '%s': %s",
                     s->smack_label_ip_in, strerror(errno));
        }
    }

    /* SmackLabelIPOut= - SMACK label for outgoing packets */
    if (s->smack_label_ip_out) {
        ret = fsetxattr(fd, "security.SMACK64IPOUT", s->smack_label_ip_out,
                        strlen(s->smack_label_ip_out), 0);
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SMACK64IPOUT label '%s': %s",
                     s->smack_label_ip_out, strerror(errno));
        }
    }

    /* SELinuxContextFromNet= - SO_PASSSEC for SELinux context from peer */
    if (s->selinux_context_from_net) {
#if defined(__linux__) && defined(SO_PASSSEC)
        int optval = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_PASSSEC, &optval, sizeof(optval));
        if (ret < 0) {
            log_warn("socket-worker", "Failed to set SO_PASSSEC: %s", strerror(errno));
        }
#else
        log_warn("socket-worker", "SO_PASSSEC not supported (Linux-only feature)");
#endif
    }
#endif

    return 0;
}

/* Apply SocketUser= and SocketGroup= ownership to Unix socket
 * Uses IPC to request privileged daemon to perform chown operation */
static int apply_socket_ownership(const char *socket_path, const struct socket_section *s) {
    /* Skip if neither SocketUser= nor SocketGroup= is set */
    if (s->socket_user[0] == '\0' && s->socket_group[0] == '\0') {
        return 0;
    }

    /* Build IPC request for privileged daemon */
    struct socket_request req = {0};
    struct socket_response resp = {0};

    req.type = SOCKET_REQ_CHOWN;
    strncpy(req.socket_path, socket_path, sizeof(req.socket_path) - 1);
    strncpy(req.owner, s->socket_user, sizeof(req.owner) - 1);
    strncpy(req.group, s->socket_group, sizeof(req.group) - 1);

    /* Send request to privileged daemon */
    if (send_socket_request(daemon_socket, &req) < 0) {
        log_warn("socket-worker", "Failed to send chown request for %s", socket_path);
        return -1;
    }

    /* Wait for response */
    if (recv_socket_response(daemon_socket, &resp) < 0) {
        log_warn("socket-worker", "Failed to receive chown response for %s", socket_path);
        return -1;
    }

    if (resp.type != SOCKET_RESP_OK) {
        log_warn("socket-worker", "Chown failed for %s: %s",
                 socket_path, resp.error_msg);
        return -1;
    }

    return 0;
}

/* Create listening socket from socket unit */
static int create_listen_socket(struct socket_instance *sock) {
    const struct socket_section *s = &sock->unit->config.socket;
    int fd;

    /* Unix stream socket */
    if (s->listen_stream && s->listen_stream[0] == '/') {
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            log_error("socket-worker", "socket: %s", strerror(errno));
            return -1;
        }

        /* Apply socket options */
        apply_socket_options(fd, s, AF_UNIX);

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, s->listen_stream, sizeof(addr.sun_path) - 1);

        /* Remove old socket */
        unlink(s->listen_stream);

        /* Create parent directory if needed with DirectoryMode= */
        const char *last_slash = strrchr(s->listen_stream, '/');
        if (last_slash && last_slash != s->listen_stream) {
            char dir_path[MAX_PATH];
            size_t dir_len = last_slash - s->listen_stream;
            if (dir_len < sizeof(dir_path)) {
                memcpy(dir_path, s->listen_stream, dir_len);
                dir_path[dir_len] = '\0';

                struct stat st;
                if (stat(dir_path, &st) < 0 && errno == ENOENT) {
                    if (mkdir(dir_path, s->directory_mode) < 0 && errno != EEXIST) {
                        log_warn("socket-worker", "mkdir %s: %s", dir_path, strerror(errno));
                    }
                }
            }
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Use configured backlog */
        if (listen(fd, s->backlog) < 0) {
            log_error("socket-worker", "listen: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Set socket file permissions with SocketMode= */
        if (fchmod(fd, s->socket_mode) < 0) {
            log_warn("socket-worker", "fchmod %04o: %s", s->socket_mode, strerror(errno));
        }

        /* Apply SocketUser=/SocketGroup= ownership */
        apply_socket_ownership(s->listen_stream, s);

        /* Symlinks= - create symlinks to the socket */
        for (int i = 0; i < s->symlinks_count; i++) {
            if (s->symlinks[i]) {
                unlink(s->symlinks[i]);  /* Remove old symlink if exists */
                if (symlink(s->listen_stream, s->symlinks[i]) < 0) {
                    log_warn("socket-worker", "symlink %s -> %s: %s",
                             s->symlinks[i], s->listen_stream, strerror(errno));
                }
            }
        }

        sock->is_stream = true;
        log_info("socket-worker", "Listening on Unix stream %s", s->listen_stream);
        return fd;
    }

    /* Unix sequential packet socket */
    if (s->listen_sequential_packet) {
        fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            log_error("socket-worker", "socket: %s", strerror(errno));
            return -1;
        }

        /* Apply socket options */
        apply_socket_options(fd, s, AF_UNIX);

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, s->listen_sequential_packet, sizeof(addr.sun_path) - 1);

        /* Remove old socket */
        unlink(s->listen_sequential_packet);

        /* Create parent directory if needed with DirectoryMode= */
        const char *last_slash = strrchr(s->listen_sequential_packet, '/');
        if (last_slash && last_slash != s->listen_sequential_packet) {
            char dir_path[MAX_PATH];
            size_t dir_len = last_slash - s->listen_sequential_packet;
            if (dir_len < sizeof(dir_path)) {
                memcpy(dir_path, s->listen_sequential_packet, dir_len);
                dir_path[dir_len] = '\0';

                struct stat st;
                if (stat(dir_path, &st) < 0 && errno == ENOENT) {
                    if (mkdir(dir_path, s->directory_mode) < 0 && errno != EEXIST) {
                        log_warn("socket-worker", "mkdir %s: %s", dir_path, strerror(errno));
                    }
                }
            }
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Use configured backlog (SEQPACKET is connection-oriented) */
        if (listen(fd, s->backlog) < 0) {
            log_error("socket-worker", "listen: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Set socket file permissions with SocketMode= */
        if (fchmod(fd, s->socket_mode) < 0) {
            log_warn("socket-worker", "fchmod %04o: %s", s->socket_mode, strerror(errno));
        }

        /* Apply SocketUser=/SocketGroup= ownership */
        apply_socket_ownership(s->listen_sequential_packet, s);

        /* Symlinks= - create symlinks to the socket */
        for (int i = 0; i < s->symlinks_count; i++) {
            if (s->symlinks[i]) {
                unlink(s->symlinks[i]);  /* Remove old symlink if exists */
                if (symlink(s->listen_sequential_packet, s->symlinks[i]) < 0) {
                    log_warn("socket-worker", "symlink %s -> %s: %s",
                             s->symlinks[i], s->listen_sequential_packet, strerror(errno));
                }
            }
        }

        sock->is_stream = true;  /* Connection-oriented like stream */
        log_info("socket-worker", "Listening on Unix seqpacket %s", s->listen_sequential_packet);
        return fd;
    }

    /* TCP stream socket */
    if (s->listen_stream) {
        const char *colon = strchr(s->listen_stream, ':');
        if (!colon) {
            log_error("socket-worker", "invalid ListenStream format: %s",
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
            log_error("socket-worker", "socket: %s", strerror(errno));
            return -1;
        }

        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        /* Apply socket options */
        apply_socket_options(fd, s, AF_INET);

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, host, &addr.sin_addr);
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Use configured backlog */
        if (listen(fd, s->backlog) < 0) {
            log_error("socket-worker", "listen: %s", strerror(errno));
            close(fd);
            return -1;
        }

        sock->is_stream = true;
        log_info("socket-worker", "Listening on TCP %s:%d", host, port);
        return fd;
    }

    /* Unix datagram socket */
    if (s->listen_datagram && s->listen_datagram[0] == '/') {
        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            log_error("socket-worker", "socket: %s", strerror(errno));
            return -1;
        }

        /* Apply socket options */
        apply_socket_options(fd, s, AF_UNIX);

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, s->listen_datagram, sizeof(addr.sun_path) - 1);

        unlink(s->listen_datagram);

        /* Create parent directory if needed with DirectoryMode= */
        const char *last_slash = strrchr(s->listen_datagram, '/');
        if (last_slash && last_slash != s->listen_datagram) {
            char dir_path[MAX_PATH];
            size_t dir_len = last_slash - s->listen_datagram;
            if (dir_len < sizeof(dir_path)) {
                memcpy(dir_path, s->listen_datagram, dir_len);
                dir_path[dir_len] = '\0';

                struct stat st;
                if (stat(dir_path, &st) < 0 && errno == ENOENT) {
                    if (mkdir(dir_path, s->directory_mode) < 0 && errno != EEXIST) {
                        log_warn("socket-worker", "mkdir %s: %s", dir_path, strerror(errno));
                    }
                }
            }
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* Set socket file permissions with SocketMode= */
        if (fchmod(fd, s->socket_mode) < 0) {
            log_warn("socket-worker", "fchmod %04o: %s", s->socket_mode, strerror(errno));
        }

        /* Apply SocketUser=/SocketGroup= ownership */
        apply_socket_ownership(s->listen_datagram, s);

        /* Symlinks= - create symlinks to the socket */
        for (int i = 0; i < s->symlinks_count; i++) {
            if (s->symlinks[i]) {
                unlink(s->symlinks[i]);  /* Remove old symlink if exists */
                if (symlink(s->listen_datagram, s->symlinks[i]) < 0) {
                    log_warn("socket-worker", "symlink %s -> %s: %s",
                             s->symlinks[i], s->listen_datagram, strerror(errno));
                }
            }
        }

        sock->is_stream = false;
        log_info("socket-worker", "Listening on Unix dgram %s", s->listen_datagram);
        return fd;
    }

    /* UDP socket */
    if (s->listen_datagram) {
        const char *colon = strchr(s->listen_datagram, ':');
        if (!colon) {
            log_error("socket-worker", "invalid ListenDatagram format: %s",
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
            log_error("socket-worker", "socket: %s", strerror(errno));
            return -1;
        }

        /* Apply socket options */
        apply_socket_options(fd, s, AF_INET);

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, host, &addr.sin_addr);
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        sock->is_stream = false;
        log_info("socket-worker", "Listening on UDP %s:%d", host, port);
        return fd;
    }

    /* FIFO (named pipe) */
    if (s->listen_fifo) {
        /* Validate absolute path */
        if (s->listen_fifo[0] != '/') {
            log_error("socket-worker", "ListenFIFO must be absolute path: %s", s->listen_fifo);
            return -1;
        }

        /* Remove old FIFO if exists */
        unlink(s->listen_fifo);

        /* Create parent directory if needed with DirectoryMode= */
        const char *last_slash = strrchr(s->listen_fifo, '/');
        if (last_slash && last_slash != s->listen_fifo) {
            char dir_path[MAX_PATH];
            size_t dir_len = last_slash - s->listen_fifo;
            if (dir_len < sizeof(dir_path)) {
                memcpy(dir_path, s->listen_fifo, dir_len);
                dir_path[dir_len] = '\0';

                struct stat st;
                if (stat(dir_path, &st) < 0 && errno == ENOENT) {
                    if (mkdir(dir_path, s->directory_mode) < 0 && errno != EEXIST) {
                        log_warn("socket-worker", "mkdir %s: %s", dir_path, strerror(errno));
                    }
                }
            }
        }

        /* Create FIFO with SocketMode= */
        if (mkfifo(s->listen_fifo, s->socket_mode) < 0) {
            log_error("socket-worker", "mkfifo %s: %s", s->listen_fifo, strerror(errno));
            return -1;
        }

        /* Apply SocketUser=/SocketGroup= ownership */
        apply_socket_ownership(s->listen_fifo, s);

        /* Open FIFO for reading (non-blocking to avoid hanging) */
        fd = open(s->listen_fifo, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            log_error("socket-worker", "open %s: %s", s->listen_fifo, strerror(errno));
            unlink(s->listen_fifo);
            return -1;
        }

        /* Apply PipeSize= if configured */
        if (s->pipe_size > 0) {
#ifdef F_SETPIPE_SZ
            if (fcntl(fd, F_SETPIPE_SZ, s->pipe_size) < 0) {
                log_warn("socket-worker", "fcntl F_SETPIPE_SZ %d: %s",
                         s->pipe_size, strerror(errno));
            }
#else
            log_warn("socket-worker", "PipeSize= not supported on this platform");
#endif
        }

        sock->is_stream = false;  /* FIFO behaves like datagram */
        log_info("socket-worker", "Listening on FIFO %s", s->listen_fifo);
        return fd;
    }

    /* POSIX message queue */
    if (s->listen_message_queue) {
#ifdef HAVE_MQUEUE
        /* Validate message queue name (must start with /) */
        if (s->listen_message_queue[0] != '/') {
            log_error("socket-worker", "ListenMessageQueue must start with /: %s",
                      s->listen_message_queue);
            return -1;
        }

        /* Remove old queue if exists */
        mq_unlink(s->listen_message_queue);

        /* Set message queue attributes if configured */
        struct mq_attr attr = {0};
        struct mq_attr *attr_ptr = NULL;

        if (s->message_queue_max_messages > 0 && s->message_queue_message_size > 0) {
            attr.mq_maxmsg = s->message_queue_max_messages;
            attr.mq_msgsize = s->message_queue_message_size;
            attr_ptr = &attr;
        } else if (s->message_queue_max_messages > 0 || s->message_queue_message_size > 0) {
            log_warn("socket-worker", "MessageQueueMaxMessages and MessageQueueMessageSize "
                     "must both be set or neither - ignoring");
        }

        /* Open message queue (O_RDONLY for activation) */
        mqd_t mqd = mq_open(s->listen_message_queue,
                            O_RDONLY | O_CREAT | O_NONBLOCK | O_CLOEXEC,
                            s->socket_mode, attr_ptr);
        if (mqd == (mqd_t)-1) {
            log_error("socket-worker", "mq_open %s: %s",
                      s->listen_message_queue, strerror(errno));
            return -1;
        }

        /* Message queue descriptors are file descriptors on Linux */
        fd = (int)mqd;

        sock->is_stream = false;  /* Message queue behaves like datagram */
        log_info("socket-worker", "Listening on message queue %s", s->listen_message_queue);
        return fd;
#else
        log_error("socket-worker", "ListenMessageQueue not supported on this platform");
        return -1;
#endif
    }

    /* Special file (character devices, /proc, /sys) */
    if (s->listen_special) {
        /* Validate absolute path */
        if (s->listen_special[0] != '/') {
            log_error("socket-worker", "ListenSpecial must be absolute path: %s", s->listen_special);
            return -1;
        }

        /* Determine open mode based on Writable= */
        int flags = s->writable ? O_RDWR : O_RDONLY;
        flags |= O_NONBLOCK | O_CLOEXEC;

        /* Open the special file */
        fd = open(s->listen_special, flags);
        if (fd < 0) {
            log_error("socket-worker", "open %s: %s", s->listen_special, strerror(errno));
            return -1;
        }

        sock->is_stream = false;  /* Special files behave like datagram */
        log_info("socket-worker", "Listening on special file %s (%s)",
                 s->listen_special, s->writable ? "read-write" : "read-only");
        return fd;
    }

    /* Netlink socket (Linux-only) */
    if (s->listen_netlink) {
#ifdef __linux__
        /* Parse netlink family and optional multicast group
         * Format: "kobject-uevent" or "kobject-uevent 1" */
        char family_str[64];
        int multicast_group = 0;

        sscanf(s->listen_netlink, "%63s %d", family_str, &multicast_group);

        /* Map family name to protocol number */
        int netlink_family = -1;
        if (strcmp(family_str, "kobject-uevent") == 0) {
            netlink_family = NETLINK_KOBJECT_UEVENT;
        } else if (strcmp(family_str, "route") == 0) {
            netlink_family = NETLINK_ROUTE;
        } else if (strcmp(family_str, "audit") == 0) {
            netlink_family = 16;  /* NETLINK_AUDIT */
        } else {
            log_error("socket-worker", "Unknown netlink family: %s", family_str);
            return -1;
        }

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, netlink_family);
        if (fd < 0) {
            log_error("socket-worker", "netlink socket: %s", strerror(errno));
            return -1;
        }

        /* Apply socket options */
        apply_socket_options(fd, s, AF_NETLINK);

        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = 0;  /* Kernel will assign PID */
        addr.nl_groups = multicast_group;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("socket-worker", "netlink bind: %s", strerror(errno));
            close(fd);
            return -1;
        }

        sock->is_stream = false;
        log_info("socket-worker", "Listening on netlink %s (group %d)",
                 family_str, multicast_group);
        return fd;
#else
        log_error("socket-worker", "ListenNetlink not supported (Linux-only feature)");
        return -1;
#endif
    }

    /* USB FunctionFS (Linux-only) */
    if (s->listen_usb_function) {
#ifdef __linux__
        /* Validate absolute path */
        if (s->listen_usb_function[0] != '/') {
            log_error("socket-worker", "ListenUSBFunction must be absolute path: %s",
                     s->listen_usb_function);
            return -1;
        }

        /* Open the ep0 endpoint (control endpoint) */
        char ep0_path[PATH_MAX];
        snprintf(ep0_path, sizeof(ep0_path), "%s/ep0", s->listen_usb_function);

        fd = open(ep0_path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            log_error("socket-worker", "Failed to open USB FunctionFS ep0 %s: %s",
                     ep0_path, strerror(errno));
            return -1;
        }

        /* Note: The service using this socket should write USB descriptors
         * and strings to this fd to activate the USB function */

        sock->is_stream = false;  /* FunctionFS endpoints behave like character devices */
        log_info("socket-worker", "Listening on USB FunctionFS %s", s->listen_usb_function);
        return fd;
#else
        log_error("socket-worker", "ListenUSBFunction not supported (Linux-only feature)");
        return -1;
#endif
    }

    return -1;
}

/* Build argv array from command string (simplified from supervisor) */
static int build_exec_argv(const char *command, char ***argv_out) {
    if (!command || command[0] == '\0' || !argv_out) {
        errno = EINVAL;
        return -1;
    }

    char *copy = strdup(command);
    if (!copy) {
        return -1;
    }

    size_t capacity = 8;
    size_t argc = 0;
    char **argv = calloc(capacity, sizeof(char *));
    if (!argv) {
        free(copy);
        return -1;
    }

    char *saveptr = NULL;
    const char *token = strtok_r(copy, " \t", &saveptr);
    while (token) {
        if (argc + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char **tmp = realloc(argv, new_capacity * sizeof(char *));
            if (!tmp) {
                goto error;
            }
            argv = tmp;
            capacity = new_capacity;
        }

        argv[argc] = strdup(token);
        if (!argv[argc]) {
            goto error;
        }
        argc++;

        token = strtok_r(NULL, " \t", &saveptr);
    }

    free(copy);

    if (argc == 0) {
        free(argv);
        errno = EINVAL;
        return -1;
    }

    argv[argc] = NULL;
    *argv_out = argv;
    return 0;

error:
    for (size_t i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    free(copy);
    return -1;
}

/* Free argv array */
static void free_exec_argv(char **argv) {
    if (!argv) {
        return;
    }
    for (size_t i = 0; argv[i] != NULL; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* Run exec command for socket lifecycle (simplified, no privilege dropping)
 * Socket worker is already unprivileged, so commands run as worker user */
static int run_socket_exec_command(const char *command, const char *unit_name, const char *stage) {
    if (!command || command[0] == '\0') {
        return 0;
    }

    char **argv = NULL;
    if (build_exec_argv(command, &argv) < 0) {
        log_error("socket-worker", "%s for %s failed to parse command", stage, unit_name);
        return -1;
    }

    const char *exec_path = argv[0];
    if (!exec_path || exec_path[0] != '/') {
        log_error("socket-worker", "%s for %s must use absolute path", stage, unit_name);
        free_exec_argv(argv);
        errno = EINVAL;
        return -1;
    }

    if (strstr(exec_path, "..") != NULL) {
        log_error("socket-worker", "%s for %s path contains '..'", stage, unit_name);
        free_exec_argv(argv);
        errno = EINVAL;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        log_error("socket-worker", "fork %s: %s", stage, strerror(saved_errno));
        free_exec_argv(argv);
        errno = saved_errno;
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        if (setsid() < 0) {
            log_error("socket-worker", "setsid (%s): %s", stage, strerror(errno));
        }

        /* Close daemon socket and other fds */
        if (daemon_socket >= 0) {
            close(daemon_socket);
        }
        if (control_socket >= 0) {
            close(control_socket);
        }
        if (status_socket >= 0) {
            close(status_socket);
        }

        /* Close listening sockets */
        for (struct socket_instance *s = sockets; s; s = s->next) {
            if (s->listen_fd >= 0) {
                close(s->listen_fd);
            }
        }

        execv(exec_path, argv);
        log_error("socket-worker", "execv %s: %s", stage, strerror(errno));
        _exit(1);
    }

    /* Parent */
    free_exec_argv(argv);

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        int saved_errno = errno;
        log_error("socket-worker", "waitpid %s: %s", stage, strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("socket-worker", "%s for %s failed (status=%d)",
                  stage, unit_name, WEXITSTATUS(status));
        errno = ECHILD;
        return -1;
    }

    return 0;
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
        log_error("socket-worker", "service %s not found", sock->service_name);
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

    /* Run ExecStartPre if configured */
    const struct socket_section *socket_cfg = &sock->unit->config.socket;
    if (socket_cfg->exec_start_pre) {
        if (run_socket_exec_command(socket_cfg->exec_start_pre, sock->unit->name, "ExecStartPre") < 0) {
            log_warn("socket-worker", "ExecStartPre failed for %s, continuing", sock->unit->name);
            /* Continue despite failure - systemd behavior */
        }
    }

    /* Fork and exec service */
    pid_t pid = fork();
    if (pid < 0) {
        free_unit_file(&unit);
        return -1;
    }

    if (pid == 0) {

        /* Child process */
        if (daemon_socket >= 0) {
            close(daemon_socket);
        }

        /* Set up socket activation environment */
        char listen_fds[32];
        snprintf(listen_fds, sizeof(listen_fds), "%d", 1);
        setenv("LISTEN_FDS", listen_fds, 1);
        char listen_pid[32];
        snprintf(listen_pid, sizeof(listen_pid), "%d", (int)getpid());
        setenv("LISTEN_PID", listen_pid, 1);

        /* Set LISTEN_FDNAMES if FileDescriptorName= is configured */
        const char *fd_name = sock->unit->config.socket.file_descriptor_name;
        if (fd_name) {
            setenv("LISTEN_FDNAMES", fd_name, 1);
        } else {
            /* Default: unit name (including .socket suffix) */
            setenv("LISTEN_FDNAMES", sock->unit->name, 1);
        }

        /* Duplicate listening socket to fd 3 (systemd convention) */
        if (dup2(sock->listen_fd, 3) < 0) {
            log_error("socket-worker", "dup2: %s", strerror(errno));
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
        log_error("socket-worker", "exec: %s", strerror(errno));
        exit(1);
    }

    /* Parent */
    free_unit_file(&unit);
    log_info("socket-worker", "Activated %s (pid %d)", sock->service_name, pid);

    sock->service_pid = pid;
    sock->runtime_max_sec = runtime_limit;
    sock->service_start = time(NULL);
    sock->last_activity = sock->service_start;

    notify_supervisor_socket_state(sock, pid);

    /* Run ExecStartPost if configured */
    if (socket_cfg->exec_start_post) {
        if (run_socket_exec_command(socket_cfg->exec_start_post, sock->unit->name, "ExecStartPost") < 0) {
            log_warn("socket-worker", "ExecStartPost failed for %s", sock->unit->name);
            /* Continue despite failure */
        }
    }

    return 0;
}

/* Activate service for per-connection mode (Accept=true, inetd-style) */
static int activate_per_connection(struct socket_instance *sock) {
    const struct socket_section *socket_cfg = &sock->unit->config.socket;

    /* Check MaxConnections= limit */
    if (socket_cfg->max_connections > 0 &&
        sock->active_connections >= socket_cfg->max_connections) {
        log_warn("socket-worker", "MaxConnections=%d reached for %s, refusing connection",
                 socket_cfg->max_connections, sock->unit->name);

        /* Still need to accept and close to avoid connection queue buildup */
        int conn_fd = accept(sock->listen_fd, NULL, NULL);
        if (conn_fd >= 0) {
            close(conn_fd);
        }
        return -1;
    }

    /* Accept the connection */
    int conn_fd = accept(sock->listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        log_error("socket-worker", "accept: %s", strerror(errno));
        return -1;
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
        snprintf(unit_path, sizeof(unit_path), "%s/%s", dirs[i], sock->service_name);
        if (parse_unit_file(unit_path, &unit) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        log_error("socket-worker", "service %s not found", sock->service_name);
        close(conn_fd);
        return -1;
    }

    if (unit.type != UNIT_SERVICE) {
        free_unit_file(&unit);
        close(conn_fd);
        return -1;
    }

    if (!unit.config.service.exec_start) {
        free_unit_file(&unit);
        close(conn_fd);
        return -1;
    }

    /* Run ExecStartPre if configured */
    if (socket_cfg->exec_start_pre) {
        if (run_socket_exec_command(socket_cfg->exec_start_pre, sock->unit->name, "ExecStartPre") < 0) {
            log_warn("socket-worker", "ExecStartPre failed for %s, continuing", sock->unit->name);
        }
    }

    /* Fork and exec service for this connection */
    pid_t pid = fork();
    if (pid < 0) {
        free_unit_file(&unit);
        close(conn_fd);
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        if (daemon_socket >= 0) {
            close(daemon_socket);
        }

        /* Set up socket activation environment */
        char listen_fds[32];
        snprintf(listen_fds, sizeof(listen_fds), "%d", 1);
        setenv("LISTEN_FDS", listen_fds, 1);
        char listen_pid[32];
        snprintf(listen_pid, sizeof(listen_pid), "%d", (int)getpid());
        setenv("LISTEN_PID", listen_pid, 1);

        /* Set LISTEN_FDNAMES for Accept=yes mode */
        const char *fd_name = sock->unit->config.socket.file_descriptor_name;
        if (fd_name) {
            setenv("LISTEN_FDNAMES", fd_name, 1);
        } else {
            /* Default: "connection" for Accept=yes */
            setenv("LISTEN_FDNAMES", "connection", 1);
        }

        /* Duplicate connection fd to fd 3 (systemd convention) */
        if (dup2(conn_fd, 3) < 0) {
            log_error("socket-worker", "dup2: %s", strerror(errno));
            exit(1);
        }

        /* Close the original connection fd (fd 3 remains) */
        close(conn_fd);

        /* Close listening socket in child */
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
        log_error("socket-worker", "exec: %s", strerror(errno));
        exit(1);
    }

    /* Parent */
    free_unit_file(&unit);
    close(conn_fd);  /* Parent closes connection fd */

    /* Increment active connection count for MaxConnections= tracking */
    sock->active_connections++;

    log_info("socket-worker", "Spawned per-connection instance of %s (pid %d)",
             sock->service_name, pid);

    /* Run ExecStartPost if configured */
    if (socket_cfg->exec_start_post) {
        if (run_socket_exec_command(socket_cfg->exec_start_post, sock->unit->name, "ExecStartPost") < 0) {
            log_warn("socket-worker", "ExecStartPost failed for %s", sock->unit->name);
        }
    }

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

    log_debug("socket-worker", "Activity detected on %s", sock->unit->name);

    /* Check trigger rate limit */
    if (!check_trigger_limit(sock)) {
        /* Rate limit exceeded, refuse connection */
        log_debug("socket-worker", "Refusing connection for %s (rate limited)", sock->unit->name);
        return;
    }

    /* Check if this is Accept=true (per-connection) mode */
    if (sock->unit->config.socket.accept) {
        /* inetd-style: spawn new service for each connection */
        if (activate_per_connection(sock) < 0) {
            log_error("socket-worker", "failed to activate per-connection service for %s",
                      sock->service_name);
        }
        return;
    }

    /* Accept=false (default): single service instance handles all connections */
    if (sock->service_pid > 0) {
        if (kill(sock->service_pid, 0) == 0) {
            /* Service is already running and will handle the connection */
            return;
        }
        /* Stale PID */
        mark_service_exit(sock->service_pid);
    }

    if (activate_direct(sock) < 0) {
        log_error("socket-worker", "failed to activate %s", sock->service_name);
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
            log_info("socket-worker", "Killing idle service %s (pid %d) after %ld seconds",
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
            log_info("socket-worker", "Killing %s (pid %d) after RuntimeMaxSec=%d",
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
            log_warn("socket-worker", "failed to create socket for %s",
                     units[i]->name);
            free(instance);
            continue;
        }

        /* Add to list */
        instance->next = sockets;
        sockets = instance;

        log_debug("socket-worker", "Loaded %s (fd %d)",
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

    log_debug("socket-worker", "Received command %s for unit %s",
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
                    /* RemoveOnStop= - remove socket files when stopped */
                    if (sec->remove_on_stop) {
                        if (sec->listen_stream && sec->listen_stream[0] == '/') {
                            unlink(sec->listen_stream);
                        }
                        if (sec->listen_datagram && sec->listen_datagram[0] == '/') {
                            unlink(sec->listen_datagram);
                        }
                        /* Remove symlinks too if they exist */
                        for (int i = 0; i < sec->symlinks_count; i++) {
                            if (sec->symlinks[i]) {
                                unlink(sec->symlinks[i]);
                            }
                        }
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

    while (!shutdown_requested) {
        int nfds = 0;
        int status_idx = -1;

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
            log_error("socket-worker", "poll: %s", strerror(errno));
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
    /* Initialize enhanced logging */
    log_enhanced_init("socket-worker", NULL);

    const char *debug_env = getenv("INITD_DEBUG_SOCKET");
    bool debug_mode = (debug_env && strcmp(debug_env, "0") != 0);
    if (debug_mode) {
        log_set_console_level(LOGLEVEL_DEBUG);
        log_set_file_level(LOGLEVEL_DEBUG);
        log_info("socket-worker", "Debug mode enabled (INITD_DEBUG_SOCKET)");
    } else {
        log_set_console_level(LOGLEVEL_INFO);
        log_set_file_level(LOGLEVEL_INFO);
    }

    if (argc < 2) {
        log_error("socket-worker", "usage: %s <ipc_fd>", argv[0]);
        return 1;
    }

    /* Get IPC socket FD from command line */
    errno = 0;
    char *endptr = NULL;
    long parsed_fd = strtol(argv[1], &endptr, 10);
    if (errno != 0 || endptr == argv[1] || *endptr != '\0' ||
        parsed_fd < 0 || parsed_fd > INT_MAX) {
        log_error("socket-worker", "invalid IPC fd argument '%s'", argv[1]);
        return 1;
    }

    daemon_socket = (int)parsed_fd;

    int fd_flags = fcntl(daemon_socket, F_GETFD);
    if (fd_flags < 0 || fcntl(daemon_socket, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        log_error("socket-worker", "failed to reapply FD_CLOEXEC to IPC fd: %s", strerror(errno));
        return 1;
    }

    log_info("socket-worker", "Starting (ipc_fd=%d)", daemon_socket);

    /* Setup signals */
    log_debug("socket-worker", "Setting up signal handlers");
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create control socket */
    log_debug("socket-worker", "Creating control socket");
    control_socket = create_control_socket();
    if (control_socket < 0) {
        return 1;
    }

    log_debug("socket-worker", "Creating status socket");
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
    log_debug("socket-worker", "Loading socket units");
    if (load_sockets() < 0) {
        log_error("socket-worker", "failed to load sockets");
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
    log_debug("socket-worker", "Entering event loop");
    event_loop();

    /* Cleanup */
    log_info("socket-worker", "Shutting down");
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

    log_enhanced_close();
    return 0;
}
#endif
