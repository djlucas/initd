/* supervisor-master.c - Privileged supervisor process
 *
 * Responsibilities:
 * - Fork supervisor-slave and drop privileges
 * - Handle privileged requests from slave (fork/exec services)
 * - Set up cgroups (Linux only)
 * - Set up namespaces
 * - Drop privileges before exec
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include "../common/ipc.h"

#ifndef SLAVE_PATH
#define SLAVE_PATH "/usr/libexec/initd/supervisor-slave"
#endif

#ifndef SUPERVISOR_USER
#define SUPERVISOR_USER "initd-supervisor"
#endif

static volatile sig_atomic_t shutdown_requested = 0;
static pid_t slave_pid = 0;
static int ipc_socket = -1;

/* Signal handlers */
static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Reaping handled in main loop */
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("supervisor-master: sigaction SIGTERM");
        return -1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("supervisor-master: sigaction SIGCHLD");
        return -1;
    }

    return 0;
}

/* Create IPC socketpair for master/slave communication */
static int create_ipc_socket(int *master_fd, int *slave_fd) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("supervisor-master: socketpair");
        return -1;
    }

    *master_fd = sv[0];
    *slave_fd = sv[1];
    return 0;
}

/* Lookup unprivileged user for slave */
static int lookup_supervisor_user(uid_t *uid, gid_t *gid) {
    struct passwd *pw = getpwnam(SUPERVISOR_USER);
    if (!pw) {
        fprintf(stderr, "supervisor-master: user '%s' not found\n", SUPERVISOR_USER);
        fprintf(stderr, "supervisor-master: falling back to 'nobody'\n");

        /* Fallback to nobody */
        pw = getpwnam("nobody");
        if (!pw) {
            fprintf(stderr, "supervisor-master: user 'nobody' not found either\n");
            return -1;
        }
    }

    *uid = pw->pw_uid;
    *gid = pw->pw_gid;

    fprintf(stderr, "supervisor-master: slave will run as %s (uid=%d, gid=%d)\n",
            pw->pw_name, *uid, *gid);
    return 0;
}

/* Fork and exec slave process */
static pid_t start_slave(int slave_fd) {
    uid_t slave_uid;
    gid_t slave_gid;

    /* Lookup unprivileged user */
    if (lookup_supervisor_user(&slave_uid, &slave_gid) < 0) {
        fprintf(stderr, "supervisor-master: cannot find unprivileged user for slave\n");
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("supervisor-master: fork slave");
        return -1;
    }

    if (pid == 0) {
        /* Child: will become slave */
        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", slave_fd);

        /* Drop privileges before exec */
        if (slave_gid != 0) {
            /* Set supplementary groups */
            if (setgroups(1, &slave_gid) < 0) {
                perror("supervisor-master: setgroups");
                _exit(1);
            }

            /* Set GID */
            if (setgid(slave_gid) < 0) {
                perror("supervisor-master: setgid");
                _exit(1);
            }
        }

        if (slave_uid != 0) {
            /* Set UID (must be last) */
            if (setuid(slave_uid) < 0) {
                perror("supervisor-master: setuid");
                _exit(1);
            }
        }

        /* Verify we dropped privileges */
        if (getuid() == 0 || geteuid() == 0) {
            fprintf(stderr, "supervisor-master: failed to drop privileges!\n");
            _exit(1);
        }

        fprintf(stderr, "supervisor-slave: running as uid=%d, gid=%d\n", getuid(), getgid());

        execl(SLAVE_PATH, "supervisor-slave", fd_str, NULL);
        perror("supervisor-master: exec slave");
        _exit(1);
    }

    /* Parent */
    close(slave_fd); /* Master doesn't need slave's end */
    fprintf(stderr, "supervisor-master: started slave (pid %d)\n", pid);
    return pid;
}

/* Start a service process with privilege dropping */
static pid_t start_service_process(struct priv_request *req) {
    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child: will become service */

        /* Drop privileges if User/Group specified */
        if (req->run_gid != 0) {
            if (setgid(req->run_gid) < 0) {
                perror("supervisor-master: setgid");
                _exit(1);
            }
        }

        if (req->run_uid != 0) {
            if (setuid(req->run_uid) < 0) {
                perror("supervisor-master: setuid");
                _exit(1);
            }
        }

        /* TODO: Set up cgroups (Linux only) */
        /* TODO: Set up namespaces if configured */

        /* Exec service */
        execl("/bin/sh", "sh", "-c", req->exec_path, NULL);
        perror("supervisor-master: exec service");
        _exit(1);
    }

    /* Parent */
    return pid;
}

/* Handle privileged request from slave */
static int handle_request(struct priv_request *req, struct priv_response *resp) {
    memset(resp, 0, sizeof(*resp));

    switch (req->type) {
    case REQ_START_SERVICE:
        fprintf(stderr, "supervisor-master: start service request: %s\n", req->unit_name);

        pid_t pid = start_service_process(req);
        if (pid < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to fork service");
        } else {
            resp->type = RESP_SERVICE_STARTED;
            resp->service_pid = pid;
            fprintf(stderr, "supervisor-master: started %s (pid %d)\n", req->unit_name, pid);
        }
        break;

    case REQ_STOP_SERVICE:
        fprintf(stderr, "supervisor-master: stop service request: pid %d\n", req->service_pid);
        if (kill(req->service_pid, SIGTERM) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to kill service");
        } else {
            resp->type = RESP_SERVICE_STOPPED;
        }
        break;

    case REQ_SHUTDOWN_COMPLETE:
        fprintf(stderr, "supervisor-master: slave shutdown complete\n");
        resp->type = RESP_OK;
        shutdown_requested = 1;
        break;

    default:
        resp->type = RESP_ERROR;
        resp->error_code = EINVAL;
        snprintf(resp->error_msg, sizeof(resp->error_msg), "Unknown request type");
        break;
    }

    return 0;
}

/* Reap zombie processes and notify slave */
static void reap_zombies(void) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == slave_pid) {
            fprintf(stderr, "supervisor-master: slave exited (status %d)\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            slave_pid = 0;
        } else {
            /* Service process exited - notify slave */
            int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            fprintf(stderr, "supervisor-master: service pid %d exited (status %d)\n",
                    pid, exit_status);

            /* Send notification to slave */
            struct priv_response notif = {0};
            notif.type = RESP_SERVICE_EXITED;
            notif.service_pid = pid;
            notif.exit_status = exit_status;

            if (send_response(ipc_socket, &notif) < 0) {
                fprintf(stderr, "supervisor-master: failed to notify slave of service exit\n");
            }
        }
    }
}

/* Main loop: handle IPC from slave */
static int main_loop(void) {
    fd_set readfds;
    struct timeval tv;
    struct priv_request req;
    struct priv_response resp;

    while (!shutdown_requested && slave_pid > 0) {
        /* Set up select */
        FD_ZERO(&readfds);
        FD_SET(ipc_socket, &readfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(ipc_socket + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("supervisor-master: select");
            break;
        }

        /* Handle IPC request from slave */
        if (ret > 0 && FD_ISSET(ipc_socket, &readfds)) {
            if (recv_request(ipc_socket, &req) < 0) {
                fprintf(stderr, "supervisor-master: IPC read failed\n");
                break;
            }

            /* Handle the request */
            handle_request(&req, &resp);

            /* Send response */
            if (send_response(ipc_socket, &resp) < 0) {
                fprintf(stderr, "supervisor-master: IPC write failed\n");
                break;
            }
        }

        /* Reap zombies */
        reap_zombies();
    }

    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    fprintf(stderr, "supervisor-master: starting\n");

    /* Setup signals */
    if (setup_signals() < 0) {
        return 1;
    }

    /* Create IPC socket */
    int master_fd, slave_fd;
    if (create_ipc_socket(&master_fd, &slave_fd) < 0) {
        return 1;
    }
    ipc_socket = master_fd;

    /* Fork and exec slave */
    slave_pid = start_slave(slave_fd);
    if (slave_pid < 0) {
        return 1;
    }

    /* Main loop */
    main_loop();

    /* Cleanup */
    if (slave_pid > 0) {
        kill(slave_pid, SIGTERM);
        waitpid(slave_pid, NULL, 0);
    }

    fprintf(stderr, "supervisor-master: exiting\n");
    return 0;
}
