/* initctl.c - Control interface for initd (systemctl compatible)
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "../common/control.h"

/* Print usage */
static void format_time_iso(time_t ts, char *buf, size_t len) {
    if (ts <= 0) {
        snprintf(buf, len, "n/a");
        return;
    }

    struct tm tm_buf;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
    if (localtime_r(&ts, &tm_buf) == NULL) {
        snprintf(buf, len, "n/a");
        return;
    }
#else
    struct tm *tmp = localtime(&ts);
    if (!tmp) {
        snprintf(buf, len, "n/a");
        return;
    }
    tm_buf = *tmp;
#endif

    if (strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        snprintf(buf, len, "n/a");
    }
}

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [COMMAND] [UNIT]\n\n", progname);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  start UNIT          Start a service\n");
    fprintf(stderr, "  stop UNIT           Stop a service\n");
    fprintf(stderr, "  restart UNIT        Restart a service\n");
    fprintf(stderr, "  status UNIT         Show unit status\n");
    fprintf(stderr, "  is-active UNIT      Check if unit is active\n");
    fprintf(stderr, "  is-enabled UNIT     Check if unit is enabled\n");
    fprintf(stderr, "  enable UNIT         Enable unit\n");
    fprintf(stderr, "  disable UNIT        Disable unit\n");
    fprintf(stderr, "  list-units [--all]  List all units\n");
    fprintf(stderr, "  list-timers         List all timers\n");
    fprintf(stderr, "  list-sockets        List all sockets\n");
    fprintf(stderr, "  daemon-reload       Reload unit files\n");
}

/* Parse command string to enum */
static int parse_command(const char *cmd_str, enum control_command *cmd) {
    if (strcmp(cmd_str, "start") == 0) {
        *cmd = CMD_START;
    } else if (strcmp(cmd_str, "stop") == 0) {
        *cmd = CMD_STOP;
    } else if (strcmp(cmd_str, "restart") == 0) {
        *cmd = CMD_RESTART;
    } else if (strcmp(cmd_str, "reload") == 0) {
        *cmd = CMD_RELOAD;
    } else if (strcmp(cmd_str, "status") == 0) {
        *cmd = CMD_STATUS;
    } else if (strcmp(cmd_str, "is-active") == 0) {
        *cmd = CMD_IS_ACTIVE;
    } else if (strcmp(cmd_str, "is-enabled") == 0) {
        *cmd = CMD_IS_ENABLED;
    } else if (strcmp(cmd_str, "enable") == 0) {
        *cmd = CMD_ENABLE;
    } else if (strcmp(cmd_str, "disable") == 0) {
        *cmd = CMD_DISABLE;
    } else if (strcmp(cmd_str, "list-units") == 0) {
        *cmd = CMD_LIST_UNITS;
    } else if (strcmp(cmd_str, "list-timers") == 0) {
        *cmd = CMD_LIST_TIMERS;
    } else if (strcmp(cmd_str, "list-sockets") == 0) {
        *cmd = CMD_LIST_SOCKETS;
    } else if (strcmp(cmd_str, "daemon-reload") == 0) {
        *cmd = CMD_DAEMON_RELOAD;
    } else if (strcmp(cmd_str, "isolate") == 0) {
        *cmd = CMD_ISOLATE;
    } else {
        return -1;
    }
    return 0;
}

/* Normalize unit name - add .service extension if missing */
static void normalize_unit_name(char *dest, const char *src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';

    /* If no extension, add .service */
    if (!strchr(dest, '.')) {
        size_t len = strlen(dest);
        if (len + 8 < dest_size) { /* strlen(".service") = 8 */
            strcat(dest, ".service");
        }
    }
}

/* Print status in systemd-like format */
static void print_status(const struct control_response *resp, const char *unit_name) {
    /* Color codes */
    const char *color_reset = "\033[0m";
    const char *color_green = "\033[0;32m";
    const char *color_red = "\033[0;31m";

    /* Determine color based on state */
    const char *state_color = color_reset;
    if (resp->state == UNIT_STATE_ACTIVE) {
        state_color = color_green;
    } else if (resp->state == UNIT_STATE_FAILED) {
        state_color = color_red;
    }

    printf("%s●%s %s - %s\n",
           state_color, color_reset,
           unit_name,
           resp->message);

    printf("   Loaded: loaded\n");
    printf("   Active: %s%s%s",
           state_color,
           state_to_string(resp->state),
           color_reset);

    if (resp->pid > 0) {
        printf(" (pid %d)", resp->pid);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *progname = argv[0];

    /* Check if called as systemctl (symlink) */
    char *base = strrchr(progname, '/');
    if (base) {
        progname = base + 1;
    }

    if (argc < 2) {
        print_usage(progname);
        return 1;
    }

    const char *cmd_str = argv[1];
    enum control_command cmd;

    /* Parse command */
    if (parse_command(cmd_str, &cmd) < 0) {
        fprintf(stderr, "Error: Unknown command '%s'\n", cmd_str);
        print_usage(progname);
        return 1;
    }

    /* Handle list-units command */
    if (cmd == CMD_LIST_UNITS) {
        uint16_t flags = 0;

        /* Check for --all flag */
        if (argc >= 3 && strcmp(argv[2], "--all") == 0) {
            flags |= REQ_FLAG_ALL;
        }

        /* Connect to supervisor */
        int fd = connect_to_supervisor();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to supervisor\n");
            fprintf(stderr, "Is the init system running?\n");
            return 1;
        }

        /* Build and send request */
        struct control_request req = {0};
        req.header.length = sizeof(req);
        req.header.command = CMD_LIST_UNITS;
        req.header.flags = flags;

        if (send_control_request(fd, &req) < 0) {
            fprintf(stderr, "Error: Failed to send request\n");
            close(fd);
            return 1;
        }

        /* Receive response first */
        struct control_response resp = {0};
        if (recv_control_response(fd, &resp) < 0) {
            fprintf(stderr, "Error: Failed to receive response\n");
            close(fd);
            return 1;
        }

        if (resp.code != RESP_SUCCESS) {
            fprintf(stderr, "Error: %s\n", resp.message);
            close(fd);
            return 1;
        }

        /* Receive unit list */
        struct unit_list_entry *entries = NULL;
        size_t count = 0;
        if (recv_unit_list(fd, &entries, &count) < 0) {
            fprintf(stderr, "Error: Failed to receive unit list\n");
            close(fd);
            return 1;
        }

        close(fd);

        /* Optionally pull timer units */
        struct timer_list_entry *timer_entries = NULL;
        size_t timer_count = 0;
        int timer_fd = connect_to_timer_daemon();
        if (timer_fd >= 0) {
            struct control_request timer_req = {0};
            struct control_response timer_resp = {0};

            timer_req.header.length = sizeof(timer_req);
            timer_req.header.command = CMD_LIST_TIMERS;
            timer_req.header.flags = flags;

            if (send_control_request(timer_fd, &timer_req) == 0 &&
                recv_control_response(timer_fd, &timer_resp) == 0 &&
                timer_resp.code == RESP_SUCCESS &&
                recv_timer_list(timer_fd, &timer_entries, &timer_count) == 0) {
                /* success */
            } else {
                fprintf(stderr, "Warning: Timer daemon did not return timer list.\n");
                if (timer_entries) {
                    free(timer_entries);
                    timer_entries = NULL;
                    timer_count = 0;
                }
            }
            close(timer_fd);
        } else {
            fprintf(stderr, "Warning: Timer daemon unavailable; timer units will be omitted.\n");
        }

        size_t total = count + timer_count;
        if (timer_count > 0) {
            struct unit_list_entry *tmp = realloc(entries, total * sizeof(*entries));
            if (!tmp) {
                fprintf(stderr, "Error: Out of memory expanding unit list\n");
                free(entries);
                if (timer_entries) free(timer_entries);
                return 1;
            }
            entries = tmp;

            for (size_t i = 0; i < timer_count; i++) {
                struct unit_list_entry *slot = &entries[count + i];
                memset(slot, 0, sizeof(*slot));
                strncpy(slot->name, timer_entries[i].name, sizeof(slot->name) - 1);
                slot->state = timer_entries[i].state;
                slot->pid = (pid_t)-1; /* sentinel for timer */

                char next_buf[64];
                char last_buf[64];
                format_time_iso(timer_entries[i].next_run, next_buf, sizeof(next_buf));
                format_time_iso(timer_entries[i].last_run, last_buf, sizeof(last_buf));

                if (timer_entries[i].description[0] != '\0') {
                    snprintf(slot->description, sizeof(slot->description),
                             "%s (timer for %s; next %s; last %s)",
                             timer_entries[i].description,
                             timer_entries[i].unit,
                             next_buf,
                             last_buf);
                } else {
                    snprintf(slot->description, sizeof(slot->description),
                             "Timer for %s (next %s; last %s)",
                             timer_entries[i].unit,
                             next_buf,
                             last_buf);
                }
            }
        } else {
            total = count;
        }

        if (timer_entries) {
            free(timer_entries);
        }

        if (total == 0) {
            printf("No units found.\n");
            free(entries);
            return 0;
        }

        printf("%-40s %-12s %-8s %s\n", "UNIT", "LOAD", "ACTIVE", "SUB");
        for (size_t i = 0; i < total; i++) {
            const char *sub = "";
            if (entries[i].pid > 0) {
                sub = "running";
            } else if (entries[i].pid == (pid_t)-1) {
                sub = "timer";
            }

            printf("%-40s %-12s %-8s %-8s %s\n",
                   entries[i].name,
                   "loaded",
                   state_to_string(entries[i].state),
                   sub,
                   entries[i].description);
        }

        printf("\n%zu units listed.\n", total);

        free(entries);
        return 0;
    }

    /* Handle list-timers command */
    if (cmd == CMD_LIST_TIMERS) {
        /* Connect to timer daemon */
        int fd = connect_to_timer_daemon();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to timer daemon\n");
            fprintf(stderr, "Is the timer daemon running?\n");
            return 1;
        }

        /* Build and send request */
        struct control_request req = {0};
        req.header.length = sizeof(req);
        req.header.command = CMD_LIST_TIMERS;

        if (send_control_request(fd, &req) < 0) {
            fprintf(stderr, "Error: Failed to send request\n");
            close(fd);
            return 1;
        }

        /* Receive response */
        struct control_response resp = {0};
        if (recv_control_response(fd, &resp) < 0) {
            fprintf(stderr, "Error: Failed to receive response\n");
            close(fd);
            return 1;
        }

        if (resp.code != RESP_SUCCESS) {
            fprintf(stderr, "Error: %s\n", resp.message);
            close(fd);
            return 1;
        }

        /* Receive timer list */
        struct timer_list_entry *entries = NULL;
        size_t count = 0;
        if (recv_timer_list(fd, &entries, &count) < 0) {
            fprintf(stderr, "Error: Failed to receive timer list\n");
            close(fd);
            return 1;
        }

        close(fd);

        /* Display timer list */
        if (count == 0) {
            printf("No timers found.\n");
            return 0;
        }

        /* Print header */
        printf("%-30s %-30s %-20s %-20s\n",
               "TIMER", "ACTIVATES", "NEXT", "LAST");

        /* Print entries */
        for (size_t i = 0; i < count; i++) {
            char next_str[32] = "-";
            char last_str[32] = "-";

            /* Format next run time */
            if (entries[i].next_run > 0) {
                time_t now = time(NULL);
                time_t delta = entries[i].next_run - now;
                if (delta < 0) delta = 0;

                if (delta < 60) {
                    snprintf(next_str, sizeof(next_str), "%lds", delta);
                } else if (delta < 3600) {
                    snprintf(next_str, sizeof(next_str), "%ldm", delta / 60);
                } else if (delta < 86400) {
                    snprintf(next_str, sizeof(next_str), "%ldh", delta / 3600);
                } else {
                    snprintf(next_str, sizeof(next_str), "%ldd", delta / 86400);
                }
            }

            /* Format last run time */
            if (entries[i].last_run > 0) {
                time_t now = time(NULL);
                time_t delta = now - entries[i].last_run;

                if (delta < 60) {
                    snprintf(last_str, sizeof(last_str), "%lds ago", delta);
                } else if (delta < 3600) {
                    snprintf(last_str, sizeof(last_str), "%ldm ago", delta / 60);
                } else if (delta < 86400) {
                    snprintf(last_str, sizeof(last_str), "%ldh ago", delta / 3600);
                } else {
                    snprintf(last_str, sizeof(last_str), "%ldd ago", delta / 86400);
                }
            }

            printf("%-30s %-30s %-20s %-20s\n",
                   entries[i].name,
                   entries[i].unit,
                   next_str,
                   last_str);
        }

        printf("\n%zu timers listed.\n", count);

        free(entries);
        return 0;
    }

    /* Handle list-sockets command */
    if (cmd == CMD_LIST_SOCKETS) {
        /* Connect to socket activator */
        int fd = connect_to_socket_activator();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to socket activator\n");
            fprintf(stderr, "Is the socket activator running?\n");
            return 1;
        }

        /* Build and send request */
        struct control_request req = {0};
        req.header.length = sizeof(req);
        req.header.command = CMD_LIST_SOCKETS;

        if (send_control_request(fd, &req) < 0) {
            fprintf(stderr, "Error: Failed to send request\n");
            close(fd);
            return 1;
        }

        /* Receive response */
        struct control_response resp = {0};
        if (recv_control_response(fd, &resp) < 0) {
            fprintf(stderr, "Error: Failed to receive response\n");
            close(fd);
            return 1;
        }

        if (resp.code != RESP_SUCCESS) {
            fprintf(stderr, "Error: %s\n", resp.message);
            close(fd);
            return 1;
        }

        /* Receive socket list */
        struct socket_list_entry *entries = NULL;
        size_t count = 0;
        if (recv_socket_list(fd, &entries, &count) < 0) {
            fprintf(stderr, "Error: Failed to receive socket list\n");
            close(fd);
            return 1;
        }

        close(fd);

        /* Display list */
        if (count == 0) {
            printf("No sockets found.\n");
            return 0;
        }

        /* Print header */
        printf("%-30s %-30s %-30s %-10s\n",
               "SOCKET", "LISTEN", "UNIT", "ACTIVE");

        /* Print entries */
        for (size_t i = 0; i < count; i++) {
            printf("%-30s %-30s %-30s %-10s\n",
                   entries[i].name,
                   entries[i].listen,
                   entries[i].unit,
                   state_to_string(entries[i].state));
        }

        printf("\n%zu sockets listed.\n", count);

        free(entries);
        return 0;
    }

    /* Commands that don't require a unit name */
    if (cmd == CMD_DAEMON_RELOAD) {
        int failures = 0;

        /* Reload supervisor */
        int sup_fd = connect_to_supervisor();
        if (sup_fd >= 0) {
            struct control_request req = {0};
            struct control_response resp = {0};
            req.header.length = sizeof(req);
            req.header.command = CMD_DAEMON_RELOAD;
            if (send_control_request(sup_fd, &req) == 0 &&
                recv_control_response(sup_fd, &resp) == 0 &&
                resp.code == RESP_SUCCESS) {
                printf("Supervisor: %s\n", resp.message[0] ? resp.message : "reload complete");
            } else {
                fprintf(stderr, "Warning: supervisor daemon-reload failed.\n");
                failures++;
            }
            close(sup_fd);
        } else {
            fprintf(stderr, "Warning: supervisor unavailable; skipping reload.\n");
            failures++;
        }

        /* Reload timer daemon (best-effort) */
        int timer_fd = connect_to_timer_daemon();
        if (timer_fd >= 0) {
            struct control_request req = {0};
            struct control_response resp = {0};
            req.header.length = sizeof(req);
            req.header.command = CMD_DAEMON_RELOAD;
            if (send_control_request(timer_fd, &req) == 0 &&
                recv_control_response(timer_fd, &resp) == 0 &&
                resp.code == RESP_SUCCESS) {
                printf("Timer daemon: %s\n", resp.message[0] ? resp.message : "reload complete");
            } else {
                fprintf(stderr, "Warning: timer daemon reload failed.\n");
                failures++;
            }
            close(timer_fd);
        } else {
            fprintf(stderr, "Warning: timer daemon unavailable; skipping reload.\n");
        }

        if (failures == 0) {
            return 0;
        }
        return 1;
    }

    /* Commands that require a unit name */
    if (argc < 3) {
        fprintf(stderr, "Error: Missing unit name\n");
        print_usage(progname);
        return 1;
    }

    const char *unit_name_arg = argv[2];
    char unit_name[256];
    normalize_unit_name(unit_name, unit_name_arg, sizeof(unit_name));

    /* Determine which daemon to connect to based on unit type */
    int fd;
    const char *ext = strrchr(unit_name, '.');
    if (ext && strcmp(ext, ".timer") == 0) {
        /* Route timer units to timer daemon */
        fd = connect_to_timer_daemon();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to timer daemon\n");
            fprintf(stderr, "Is the timer daemon running?\n");
            return 1;
        }
    } else if (ext && strcmp(ext, ".socket") == 0) {
        /* Route socket units to socket activator */
        fd = connect_to_socket_activator();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to socket activator\n");
            fprintf(stderr, "Is the socket activator running?\n");
            return 1;
        }
    } else {
        /* Route service/target units to supervisor */
        fd = connect_to_supervisor();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to supervisor\n");
            fprintf(stderr, "Is the init system running?\n");
            return 1;
        }
    }

    /* Build and send request */
    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = cmd;
    strncpy(req.unit_name, unit_name, sizeof(req.unit_name) - 1);

    if (send_control_request(fd, &req) < 0) {
        fprintf(stderr, "Error: Failed to send request\n");
        close(fd);
        return 1;
    }

    /* Receive response */
    struct control_response resp = {0};
    if (recv_control_response(fd, &resp) < 0) {
        fprintf(stderr, "Error: Failed to receive response\n");
        close(fd);
        return 1;
    }

    close(fd);

    /* Process response based on command */
    int exit_code = 0;

    switch (cmd) {
    case CMD_START:
    case CMD_STOP:
        if (resp.code == RESP_SUCCESS) {
            /* Silent success, like systemd */
        } else {
            fprintf(stderr, "Failed: %s\n", resp.message);
            exit_code = 1;
        }
        break;

    case CMD_STATUS:
        if (resp.code == RESP_SUCCESS || resp.code == RESP_UNIT_INACTIVE) {
            print_status(&resp, unit_name);
            exit_code = (resp.state == UNIT_STATE_ACTIVE) ? 0 : 3;
        } else {
            fprintf(stderr, "Error: %s\n", resp.message);
            exit_code = 4;
        }
        break;

    case CMD_IS_ACTIVE:
        printf("%s\n", state_to_string(resp.state));
        exit_code = (resp.state == UNIT_STATE_ACTIVE) ? 0 : 1;
        break;

    case CMD_ENABLE:
    case CMD_DISABLE:
        if (resp.code == RESP_SUCCESS) {
            /* Silent success like systemd */
        } else {
            fprintf(stderr, "Failed: %s\n", resp.message);
            exit_code = 1;
        }
        break;

    case CMD_IS_ENABLED:
        printf("%s\n", resp.message);
        exit_code = (resp.code == RESP_SUCCESS) ? 0 : 1;
        break;

    default:
        if (resp.code == RESP_SUCCESS) {
            printf("%s\n", resp.message);
        } else {
            fprintf(stderr, "Error: %s\n", resp.message);
            exit_code = 1;
        }
        break;
    }

    return exit_code;
}
