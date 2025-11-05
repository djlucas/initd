/* init.c - PID 1 init process for initd
 *
 * Minimal init system responsibilities:
 * - Reap zombie processes
 * - Start and monitor initd-supervisor
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
#include "../common/log-enhanced.h"

#ifndef SUPERVISOR_PATH
#define SUPERVISOR_PATH "/usr/sbin/initd-supervisor"
#endif

#define DEFAULT_TIMEOUT 30
#define MAX_PATH 256

/* Global state */
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t shutdown_type = 0; /* 0=poweroff, 1=reboot, 2=halt */
static volatile sig_atomic_t shutdown_from_signal = 0;
static pid_t supervisor_pid = 0;
static char supervisor_path[MAX_PATH] = SUPERVISOR_PATH;
static int supervisor_timeout = DEFAULT_TIMEOUT;
static int supervisor_restart_count = 0;
static char target_name[MAX_PATH] = "";  /* Target to boot (e.g., "rescue.target") */

/* Signal handlers */
static void sigchld_handler(int sig) {
    (void)sig;
    /* Just set a flag, reaping happens in main loop */
}

static void sigterm_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 0; /* poweroff */
    shutdown_from_signal = 1;
}

static void sigint_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 1; /* reboot */
    shutdown_from_signal = 1;
}

static void sigusr1_handler(int sig) {
    (void)sig;
    shutdown_requested = 1;
    shutdown_type = 2; /* halt */
    shutdown_from_signal = 1;
}

/* Parse command line arguments */
static void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        char *eq = strchr(arg, '=');

        if (eq) {
            /* key=value format */
            *eq = '\0'; /* Split into key and value */
            const char *key = arg;
            const char *value = eq + 1;

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
        } else {
            /* Simple argument - check for target names or runlevels */
            if (strcmp(arg, "rescue") == 0 || strcmp(arg, "single") == 0 || strcmp(arg, "1") == 0 || strcmp(arg, "s") == 0 || strcmp(arg, "S") == 0) {
                strncpy(target_name, "rescue.target", MAX_PATH - 1);
            } else if (strcmp(arg, "emergency") == 0) {
                strncpy(target_name, "emergency.target", MAX_PATH - 1);
            } else if (strcmp(arg, "multi-user") == 0 || strcmp(arg, "3") == 0) {
                strncpy(target_name, "multi-user.target", MAX_PATH - 1);
            } else if (strcmp(arg, "graphical") == 0 || strcmp(arg, "5") == 0) {
                strncpy(target_name, "graphical.target", MAX_PATH - 1);
            }
            /* Ignore other simple arguments */
        }
    }
}

/* Start initd-supervisor */
static pid_t start_supervisor(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("init: fork failed");
        return -1;
    }

    if (pid == 0) {
        /* Child: Set environment to indicate we're running as init */
        setenv("INITD_MODE", "init", 1);

        /* Set target if specified */
        if (target_name[0] != '\0') {
            setenv("INITD_TARGET", target_name, 1);
        }

        /* Extract basename for argv[0] so ps shows correct process name */
        char *name = strrchr(supervisor_path, '/');
        name = name ? name + 1 : supervisor_path;

        /* exec supervisor */
        execl(supervisor_path, name, NULL);
        /* If exec fails */
        perror("init: exec supervisor failed");
        _exit(1);
    }

    /* Parent */
    log_info("init", "Started %s", supervisor_path);
    log_debug("init", "supervisor pid: %d", pid);
    return pid;
}

/* Reap zombie processes */
static void reap_zombies(void) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == supervisor_pid) {
            log_warn("init", "initd-supervisor exited (status %d)",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            supervisor_pid = 0;

            /* If shutdown not requested, restart supervisor */
            if (!shutdown_requested) {
                supervisor_restart_count++;
                if (supervisor_restart_count > 10) {
                    log_error("init", "Supervisor crashed more than 10 times; dropping to rescue shell");
                    execl("/bin/bash", "bash", "-l", NULL);
                    _exit(1);
                }
                log_info("init", "Restarting initd-supervisor (attempt %d)",
                         supervisor_restart_count);
                supervisor_pid = start_supervisor();
            }
        }
    }
}

/* Kill all remaining processes (safety net for orphaned services)
 *
 * SECURITY: This function handles the case where initd-supervisor is SIGKILL'd
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
 * their PGIDs after initd-supervisor dies. Cgroups solve this via filesystem
 * persistence of the cgroup hierarchy.
 */
static void kill_remaining_processes(void) {
    pid_t pid;
    int status;
    int killed = 0;

    log_warn("init", "Cleaning up orphaned processes");

    /* First pass: reap any children that got reparented to us */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        log_debug("init", "reaped orphaned process %d", pid);
        killed++;
    }

    /* Second pass: send SIGTERM to all processes except ourselves
     * Note: kill(-1, sig) sends signal to all processes we can signal */
    log_debug("init", "sending SIGTERM to all remaining processes");
    kill(-1, SIGTERM);

    /* Give processes time to exit gracefully */
    sleep(2);

    /* Third pass: reap any that exited */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        log_debug("init", "reaped process %d after SIGTERM", pid);
        killed++;
    }

    /* Final pass: SIGKILL anything still alive */
    log_debug("init", "sending SIGKILL to all remaining processes");
    kill(-1, SIGKILL);

    /* Reap the killed processes */
    sleep(1);
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        log_debug("init", "reaped process %d after SIGKILL", pid);
        killed++;
    }

    if (killed > 0) {
        log_info("init", "Cleaned up %d orphaned processes", killed);
    }
}

/* Run shutdown helper script (/sbin/poweroff, /sbin/reboot, /sbin/halt)
 * Returns 0 on success, -1 on failure */
static int run_shutdown_helper(int type) {
    static const char *helpers[] = {
        "/sbin/poweroff",
        "/sbin/reboot",
        "/sbin/halt"
    };

    if (type < 0 || type > 2) {
        return -1;
    }

    const char *path = helpers[type];
    if (access(path, X_OK) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_error("init", "failed to fork shutdown helper: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: exec the shutdown helper */
        execl(path, path, NULL);
        _exit(127);
    }

    /* Parent: wait for helper to complete */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_error("init", "failed to wait for shutdown helper: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    log_warn("init", "shutdown helper exited with status %d", WEXITSTATUS(status));
    return -1;
}

/* Perform system shutdown */
static void do_shutdown(void) {
    const char *shutdown_names[] = {"poweroff", "reboot", "halt"};
    log_info("init", "Shutdown requested: %s", shutdown_names[shutdown_type]);

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
        log_debug("init", "signaling supervisor to shutdown (pid %d)", supervisor_to_shutdown);
        kill(supervisor_to_shutdown, SIGTERM);

        /* Wait for supervisor to exit (with timeout) */
        int timeout = supervisor_timeout;
        while (timeout > 0) {
            sleep(1);

            /* Manually reap with signals still blocked */
            int status;
            pid_t pid = waitpid(supervisor_to_shutdown, &status, WNOHANG);
            if (pid == supervisor_to_shutdown) {
                log_debug("init", "initd-supervisor exited gracefully (status %d)",
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
            log_warn("init", "Supervisor timeout, sending SIGKILL");
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
    log_info("init", "Performing final shutdown");

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
    log_error("init", "Shutdown failed: %s", strerror(errno));
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

    /* Initialize logging (console only for init) */
    log_enhanced_init("init", NULL);
    log_set_console_level(LOGLEVEL_INFO);

    fprintf(stderr, "INIT: initd version %s booting\n", INITD_VERSION);

    /* Parse command line arguments */
    parse_args(argc, argv);

    /* Setup signal handlers */
    if (setup_signals() < 0) {
        log_error("init", "failed to setup signal handlers");
        return 1;
    }

    /* Start supervisor */
    supervisor_pid = start_supervisor();
    if (supervisor_pid < 0) {
        log_error("init", "failed to start supervisor");
        return 1;
    }

    /* Main loop */
    log_debug("init", "entering main loop");

    while (1) {
        /* Check for shutdown */
        if (shutdown_requested) {
            /* If shutdown was triggered by a signal, try to run the helper script first */
            if (shutdown_from_signal) {
                shutdown_from_signal = 0;
                if (run_shutdown_helper(shutdown_type) == 0) {
                    /* Helper handled shutdown successfully, clear the request */
                    shutdown_requested = 0;
                    continue;
                }
                log_warn("init", "shutdown helper failed; falling back to builtin shutdown");
            }
            /* Either no helper available, or helper failed - use builtin shutdown */
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
