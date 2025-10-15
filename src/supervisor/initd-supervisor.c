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
#include "../common/privileged-ops.h"
#include "../common/parser.h"
#include "service-registry.h"

#ifndef WORKER_PATH
#define WORKER_PATH "/usr/libexecdir/initd/initd-supervisor-worker"
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

        execl(WORKER_PATH, "initd-supervisor-worker", fd_str, NULL);
        perror("supervisor-master: exec slave");
        _exit(1);
    }

    /* Parent */
    close(slave_fd); /* Master doesn't need slave's end */
    fprintf(stderr, "supervisor-master: started slave (pid %d)\n", pid);
    return pid;
}

/* Start a service process with privilege dropping */
static pid_t start_service_process(struct priv_request *req, uid_t validated_uid, gid_t validated_gid) {
    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child: will become service */

        /* Create new process group so we can kill all children with killpg() */
        if (setsid() < 0) {
            perror("supervisor-master: setsid");
            /* Non-fatal, continue anyway */
        }

        /* Setup service environment (PrivateTmp, LimitNOFILE) BEFORE dropping privileges */
        struct service_section svc_config = {
            .private_tmp = req->private_tmp,
            .limit_nofile = req->limit_nofile,
            .kill_mode = req->kill_mode
        };

        if (setup_service_environment(&svc_config) < 0) {
            fprintf(stderr, "supervisor-master: failed to setup service environment\n");
            _exit(1);
        }

        /* Validate exec_path is absolute (prevent relative path attacks) */
        if (req->exec_path[0] != '/') {
            fprintf(stderr, "supervisor-master: exec_path must be absolute: %s\n", req->exec_path);
            _exit(1);
        }

        /* Check for directory traversal attempts */
        if (strstr(req->exec_path, "..") != NULL) {
            fprintf(stderr, "supervisor-master: exec_path contains '..': %s\n", req->exec_path);
            _exit(1);
        }

        /* Drop privileges using VALIDATED UID/GID from master's unit file parsing */
        if (validated_gid != 0) {
            /* Clear supplementary groups first */
            if (setgroups(1, &validated_gid) < 0) {
                perror("supervisor-master: setgroups");
                _exit(1);
            }

            if (setgid(validated_gid) < 0) {
                perror("supervisor-master: setgid");
                _exit(1);
            }
        }

        if (validated_uid != 0) {
            if (setuid(validated_uid) < 0) {
                perror("supervisor-master: setuid");
                _exit(1);
            }
        }

        /* Verify we cannot regain privileges */
        if (validated_uid != 0) {
            if (setuid(0) == 0 || seteuid(0) == 0) {
                fprintf(stderr, "supervisor-master: SECURITY: can still become root after dropping privileges!\n");
                _exit(1);
            }
        }

        /* Exec service using argv (NO SHELL - prevents injection) */
        if (req->exec_args != NULL && req->exec_args[0] != NULL) {
            execv(req->exec_path, req->exec_args);
        } else {
            /* Fallback: no args provided, exec with single arg */
            char *argv[] = {req->exec_path, NULL};
            execv(req->exec_path, argv);
        }

        perror("supervisor-master: execv");
        _exit(1);
    }

    /* Parent */
    return pid;
}

/* Handle privileged request from slave */
static int handle_request(struct priv_request *req, struct priv_response *resp) {
    memset(resp, 0, sizeof(*resp));

    switch (req->type) {
    case REQ_START_SERVICE: {
        fprintf(stderr, "supervisor-master: start service request: %s\n", req->unit_name);

        /* SECURITY: Master must parse unit file to get authoritative User/Group values.
         * Never trust worker-supplied run_uid/run_gid as compromised worker could
         * request uid=0 to escalate privileges. */
        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
            break;
        }

        /* Extract and validate User/Group from parsed unit file */
        uid_t validated_uid = 0;  /* Default: root */
        gid_t validated_gid = 0;

        if (unit.config.service.user[0] != '\0') {
            struct passwd *pw = getpwnam(unit.config.service.user);
            if (!pw) {
                fprintf(stderr, "supervisor-master: user '%s' not found\n", unit.config.service.user);
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "User '%s' not found", unit.config.service.user);
                free_unit_file(&unit);
                break;
            }
            validated_uid = pw->pw_uid;
            fprintf(stderr, "supervisor-master: service will run as user %s (uid=%d)\n",
                    unit.config.service.user, validated_uid);
        }

        if (unit.config.service.group[0] != '\0') {
            struct group *gr = getgrnam(unit.config.service.group);
            if (!gr) {
                fprintf(stderr, "supervisor-master: group '%s' not found\n", unit.config.service.group);
                resp->type = RESP_ERROR;
                resp->error_code = EINVAL;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "Group '%s' not found", unit.config.service.group);
                free_unit_file(&unit);
                break;
            }
            validated_gid = gr->gr_gid;
            fprintf(stderr, "supervisor-master: service will run as group %s (gid=%d)\n",
                    unit.config.service.group, validated_gid);
        } else if (validated_uid != 0) {
            /* If User specified but Group not specified, use user's primary group */
            struct passwd *pw = getpwuid(validated_uid);
            if (pw) {
                validated_gid = pw->pw_gid;
            }
        }

        /* Start service with validated credentials */
        int kill_mode = unit.config.service.kill_mode;
        pid_t pid = start_service_process(req, validated_uid, validated_gid);
        free_unit_file(&unit);

        if (pid < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to fork service");
        } else {
            /* Register service in the registry to prevent arbitrary kill() attacks */
            if (register_service(pid, req->unit_name, kill_mode) < 0) {
                /* Registry full - kill the service we just started */
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
                resp->type = RESP_ERROR;
                resp->error_code = ENOMEM;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "Service registry full");
            } else {
                resp->type = RESP_SERVICE_STARTED;
                resp->service_pid = pid;
                fprintf(stderr, "supervisor-master: started %s (pid %d)\n", req->unit_name, pid);
            }
        }
        break;
    }

    case REQ_STOP_SERVICE: {
        fprintf(stderr, "supervisor-master: stop service request: pid %d\n", req->service_pid);

        /* SECURITY: Validate that this PID belongs to a managed service.
         * Prevents compromised worker from killing arbitrary processes. */
        struct service_record *svc = lookup_service(req->service_pid);
        if (!svc) {
            fprintf(stderr, "supervisor-master: SECURITY: attempt to stop unmanaged PID %d\n",
                    req->service_pid);
            resp->type = RESP_ERROR;
            resp->error_code = ESRCH;
            snprintf(resp->error_msg, sizeof(resp->error_msg),
                     "PID %d is not a managed service", req->service_pid);
            break;
        }

        fprintf(stderr, "supervisor-master: stopping service %s (pid=%d, kill_mode=%d)\n",
                svc->unit_name, svc->pid, svc->kill_mode);

        /* Use VALIDATED kill_mode from registry (from unit file), not from worker request */
        switch (svc->kill_mode) {
        case KILL_NONE:
            /* Don't kill anything */
            fprintf(stderr, "supervisor-master: KillMode=none, not sending signal\n");
            resp->type = RESP_SERVICE_STOPPED;
            break;

        case KILL_PROCESS:
            /* Kill only the main process (default) */
            if (kill(svc->pid, SIGTERM) < 0) {
                resp->type = RESP_ERROR;
                resp->error_code = errno;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to kill service");
            } else {
                resp->type = RESP_SERVICE_STOPPED;
            }
            break;

        case KILL_CONTROL_GROUP:
            /* Kill entire process group using VALIDATED pgid from registry */
            if (killpg(svc->pgid, SIGTERM) < 0) {
                /* If killpg fails (not a process group leader), fallback to kill */
                if (kill(svc->pid, SIGTERM) < 0) {
                    resp->type = RESP_ERROR;
                    resp->error_code = errno;
                    snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to kill service group");
                } else {
                    resp->type = RESP_SERVICE_STOPPED;
                }
            } else {
                resp->type = RESP_SERVICE_STOPPED;
            }
            break;

        case KILL_MIXED:
            /* SIGTERM to main process, SIGKILL to rest of group */
            kill(svc->pid, SIGTERM);
            /* Sleep briefly to let main process exit gracefully */
            usleep(100000); /* 100ms */
            /* Kill remaining processes in group */
            killpg(svc->pgid, SIGKILL);
            resp->type = RESP_SERVICE_STOPPED;
            break;

        default:
            /* Fallback to process mode */
            if (kill(svc->pid, SIGTERM) < 0) {
                resp->type = RESP_ERROR;
                resp->error_code = errno;
                snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to kill service");
            } else {
                resp->type = RESP_SERVICE_STOPPED;
            }
            break;
        }
        break;
    }

    case REQ_ENABLE_UNIT: {
        fprintf(stderr, "supervisor-master: enable unit request: %s\n", req->unit_path);
        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (enable_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to enable unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_ENABLED;
            free_unit_file(&unit);
            fprintf(stderr, "supervisor-master: enabled unit %s\n", req->unit_path);
        }
        break;
    }

    case REQ_DISABLE_UNIT: {
        fprintf(stderr, "supervisor-master: disable unit request: %s\n", req->unit_path);
        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (disable_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to disable unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_DISABLED;
            free_unit_file(&unit);
            fprintf(stderr, "supervisor-master: disabled unit %s\n", req->unit_path);
        }
        break;
    }

    case REQ_CONVERT_UNIT: {
        fprintf(stderr, "supervisor-master: convert unit request: %s\n", req->unit_path);
        struct unit_file unit = {0};

        if (parse_unit_file(req->unit_path, &unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to parse unit file");
        } else if (convert_systemd_unit(&unit) < 0) {
            resp->type = RESP_ERROR;
            resp->error_code = errno;
            snprintf(resp->error_msg, sizeof(resp->error_msg), "Failed to convert unit");
            free_unit_file(&unit);
        } else {
            resp->type = RESP_UNIT_CONVERTED;
            strncpy(resp->converted_path, unit.path, sizeof(resp->converted_path) - 1);
            free_unit_file(&unit);
            fprintf(stderr, "supervisor-master: converted unit to %s\n", resp->converted_path);
        }
        break;
    }

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
            /* Service process exited - unregister and notify slave */
            int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            fprintf(stderr, "supervisor-master: service pid %d exited (status %d)\n",
                    pid, exit_status);

            /* Remove from service registry */
            unregister_service(pid);

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
                free_request(&req);
                break;
            }

            /* Free dynamically allocated request fields */
            free_request(&req);
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

    /* Initialize service registry */
    service_registry_init();

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
