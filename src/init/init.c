/* init.c - PID 1 init process for initd
 *
 * Minimal init system responsibilities:
 * - Reap zombie processes
 * - Start and monitor supervisor-master
 * - Handle shutdown signals
 * - Coordinate system shutdown
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
#include <sys/types.h>
#include <sys/reboot.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#ifndef SUPERVISOR_PATH
#define SUPERVISOR_PATH "/usr/libexec/initd/supervisor-master"
#endif

#define DEFAULT_TIMEOUT 30
#define MAX_PATH 256

/* Global state */
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t shutdown_type = 0; /* 0=poweroff, 1=reboot, 2=halt */
static pid_t supervisor_pid = 0;
static char supervisor_path[MAX_PATH] = SUPERVISOR_PATH;
static int supervisor_timeout = DEFAULT_TIMEOUT;

/* Signal handlers */
static void sigchld_handler(int sig) {
    (void)sig;
    /* Just set a flag, reaping happens in main loop */
}

static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 0; /* poweroff */
}

static void sigint_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 1; /* reboot */
}

static void sigusr1_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 2; /* halt */
}

/* Parse command line arguments */
static void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        char *eq = strchr(arg, '=');

        if (!eq) {
            continue; /* Skip malformed args */
        }

        *eq = '\0'; /* Split into key and value */
        char *key = arg;
        char *value = eq + 1;

        if (strcmp(key, "supervisor") == 0) {
            strncpy(supervisor_path, value, MAX_PATH - 1);
            supervisor_path[MAX_PATH - 1] = '\0';
        } else if (strcmp(key, "timeout") == 0) {
            supervisor_timeout = atoi(value);
            if (supervisor_timeout <= 0) {
                supervisor_timeout = DEFAULT_TIMEOUT;
            }
        }

        *eq = '='; /* Restore for safety */
    }
}

/* Start supervisor-master */
static pid_t start_supervisor(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("init: fork failed");
        return -1;
    }

    if (pid == 0) {
        /* Child: exec supervisor */
        execl(supervisor_path, "supervisor-master", NULL);
        /* If exec fails */
        perror("init: exec supervisor failed");
        _exit(1);
    }

    /* Parent */
    fprintf(stderr, "init: started supervisor-master (pid %d)\n", pid);
    return pid;
}

/* Reap zombie processes */
static void reap_zombies(void) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == supervisor_pid) {
            fprintf(stderr, "init: supervisor-master exited (status %d)\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            supervisor_pid = 0;

            /* If shutdown not requested, restart supervisor */
            if (!shutdown_requested) {
                fprintf(stderr, "init: restarting supervisor-master\n");
                supervisor_pid = start_supervisor();
            }
        }
    }
}

/* Kill all remaining processes (safety net for orphaned services)
 *
 * SECURITY: This function handles the case where supervisor-master is SIGKILL'd
 * during shutdown, potentially leaving orphaned service processes running.
 *
 * Current approach (Phase 2 - portable):
 * 1. Reap reparented children (services that became our children)
 * 2. Send SIGTERM to all processes (kill(-1, SIGTERM))
 * 3. Wait 2 seconds for graceful exit
 * 4. Send SIGKILL to survivors (kill(-1, SIGKILL))
 * 5. Reap all killed processes
 *
 * This works on all Unix-like systems but is somewhat crude.
 *
 * Future enhancement (Phase 4 - Linux-specific):
 * - Put each service in its own cgroup at fork time
 * - On shutdown, destroy cgroups (kills all processes in them)
 * - Prevents orphaning even if supervisor dies unexpectedly
 * - More precise than kill(-1) which affects all processes
 * - See: cgroup v2 with cgroup.kill interface
 *
 * Note: Services already use process groups (setsid), but we can't track
 * their PGIDs after supervisor-master dies. Cgroups solve this via filesystem
 * persistence of the cgroup hierarchy.
 */
static void kill_remaining_processes(void) {
    pid_t pid;
    int status;
    int killed = 0;

    fprintf(stderr, "init: cleaning up any orphaned processes\n");

    /* First pass: reap any children that got reparented to us */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        fprintf(stderr, "init: reaped orphaned process %d\n", pid);
        killed++;
    }

    /* Second pass: send SIGTERM to all processes except ourselves
     * Note: kill(-1, sig) sends signal to all processes we can signal */
    fprintf(stderr, "init: sending SIGTERM to all remaining processes\n");
    kill(-1, SIGTERM);

    /* Give processes time to exit gracefully */
    sleep(2);

    /* Third pass: reap any that exited */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        fprintf(stderr, "init: reaped process %d after SIGTERM\n", pid);
        killed++;
    }

    /* Final pass: SIGKILL anything still alive */
    fprintf(stderr, "init: sending SIGKILL to all remaining processes\n");
    kill(-1, SIGKILL);

    /* Reap the killed processes */
    sleep(1);
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        fprintf(stderr, "init: reaped process %d after SIGKILL\n", pid);
        killed++;
    }

    if (killed > 0) {
        fprintf(stderr, "init: cleaned up %d orphaned processes\n", killed);
    }
}

/* Perform system shutdown */
static void do_shutdown(void) {
    fprintf(stderr, "INIT: shutdown requested (type %d)\n", shutdown_type);

    /* RACE PREVENTION: Block SIGCHLD during critical section to prevent
     * concurrent reap_zombies() from modifying supervisor_pid while we're
     * trying to kill/wait for it. Without this, supervisor could die between
     * our check and kill(), or be restarted with a new PID, causing us to
     * signal the wrong process. */
    sigset_t oldmask, blockmask;
    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

    /* Critical section: supervisor_pid operations are now atomic */
    pid_t supervisor_to_shutdown = supervisor_pid;

    if (supervisor_to_shutdown > 0) {
        fprintf(stderr, "INIT: signaling supervisor to shutdown (pid %d)\n", supervisor_to_shutdown);
        kill(supervisor_to_shutdown, SIGTERM);

        /* Wait for supervisor to exit (with timeout) */
        int timeout = supervisor_timeout;
        while (timeout > 0) {
            sleep(1);

            /* Manually reap with signals still blocked */
            int status;
            pid_t pid = waitpid(supervisor_to_shutdown, &status, WNOHANG);
            if (pid == supervisor_to_shutdown) {
                fprintf(stderr, "INIT: supervisor-master exited gracefully (status %d)\n",
                        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
                supervisor_pid = 0;
                break;
            } else if (pid < 0 && errno == ECHILD) {
                /* Supervisor already reaped */
                supervisor_pid = 0;
                break;
            }

            timeout--;
        }

        /* Force kill if still running after timeout */
        if (timeout == 0 && kill(supervisor_to_shutdown, 0) == 0) {
            fprintf(stderr, "INIT: supervisor timeout, sending SIGKILL\n");
            kill(supervisor_to_shutdown, SIGKILL);
            waitpid(supervisor_to_shutdown, NULL, 0);
            supervisor_pid = 0;

            /* SAFETY: If we had to SIGKILL the supervisor, it may have left
             * orphaned service processes. Clean them up before shutdown. */
            kill_remaining_processes();
        }
    }

    /* Restore signal mask - critical section complete */
    sigprocmask(SIG_SETMASK, &oldmask, NULL);

    /* Final sync */
    sync();
    sync();

    /* Perform shutdown action */
    fprintf(stderr, "INIT: performing final shutdown\n");

    switch (shutdown_type) {
    case 0: /* poweroff */
        reboot(RB_POWER_OFF);
        break;
    case 1: /* reboot */
        reboot(RB_AUTOBOOT);
        break;
    case 2: /* halt */
        reboot(RB_HALT_SYSTEM);
        break;
    }

    /* Should not reach here */
    fprintf(stderr, "INIT: initd shutdown failed: %s\n", strerror(errno));
    while (1) pause();
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;

    /* SIGCHLD - reap zombies */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("init: sigaction SIGCHLD");
        return -1;
    }

    /* SIGTERM - poweroff */
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("init: sigaction SIGTERM");
        return -1;
    }

    /* SIGINT - reboot (Ctrl+Alt+Del) */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("init: sigaction SIGINT");
        return -1;
    }

    /* SIGUSR1 - halt */
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("init: sigaction SIGUSR1");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    /* Verify we are PID 1 */
    if (getpid() != 1) {
        fprintf(stderr, "init: must be run as PID 1\n");
        return 1;
    }

    fprintf(stderr, "INIT: initd version %s booting\n", INITD_VERSION);

    /* Parse command line arguments */
    parse_args(argc, argv);

    /* Setup signal handlers */
    if (setup_signals() < 0) {
        fprintf(stderr, "init: failed to setup signal handlers\n");
        return 1;
    }

    /* Start supervisor */
    supervisor_pid = start_supervisor();
    if (supervisor_pid < 0) {
        fprintf(stderr, "init: failed to start supervisor\n");
        return 1;
    }

    /* Main loop */
    fprintf(stderr, "init: entering main loop\n");

    while (1) {
        /* Check for shutdown */
        if (shutdown_requested) {
            do_shutdown();
            /* does not return */
        }

        /* Reap any zombies */
        reap_zombies();

        /* Sleep briefly to avoid busy loop */
        sleep(1);
    }

    /* Never reached */
    return 0;
}
