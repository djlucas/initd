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
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>
#include "../common/control.h"
#include "../common/parser.h"
#include "../common/privileged-ops.h"
#include "../common/unit.h"

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
    fprintf(stderr, "  poweroff            Shut down and power off the system\n");
    fprintf(stderr, "  reboot              Shut down and reboot the system\n");
    fprintf(stderr, "  halt                Shut down and halt the system\n");
    fprintf(stderr, "  user enable USER [DAEMON...]\n");
    fprintf(stderr, "                     Enable per-user daemons (requires root)\n");
    fprintf(stderr, "  user disable USER [DAEMON...]\n");
    fprintf(stderr, "                     Disable per-user daemons (requires root)\n");
    fprintf(stderr, "  user status USER   Show per-user daemon settings\n");
}

enum runtime_scope {
    SCOPE_AUTO = 0,
    SCOPE_SYSTEM,
    SCOPE_USER
};

static int configure_runtime_dir(enum runtime_scope scope) {
    const char *target = INITD_RUNTIME_DEFAULT;
    char user_dir[PATH_MAX];

    if (scope != SCOPE_SYSTEM) {
        if (initd_default_user_runtime_dir(user_dir, sizeof(user_dir)) < 0) {
            if (scope == SCOPE_USER) {
                fprintf(stderr, "Error: unable to determine per-user runtime directory\n");
                return -1;
            }
        } else {
            struct stat st;
            if (scope == SCOPE_USER) {
                if (stat(user_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
                    fprintf(stderr,
                            "Error: per-user runtime directory %s not available.\n",
                            user_dir);
                    return -1;
                }
                target = user_dir;
            } else { /* AUTO */
                char socket_path[PATH_MAX];
                int written = snprintf(socket_path, sizeof(socket_path),
                                       "%s/%s", user_dir,
                                       CONTROL_STATUS_SOCKET_NAME);
                if (written >= 0 && (size_t)written < sizeof(socket_path)) {
                    struct stat st;
                    if (stat(socket_path, &st) == 0) {
                        target = user_dir;
                    }
                }
            }
        }
    }

    if (setenv(INITD_RUNTIME_DIR_ENV, target, 1) < 0) {
        perror("setenv");
        return -1;
    }

    if (initd_set_runtime_dir(target) < 0) {
        perror("initd_set_runtime_dir");
        return -1;
    }

    return 0;
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
    } else if (strcmp(cmd_str, "poweroff") == 0) {
        *cmd = CMD_POWEROFF;
    } else if (strcmp(cmd_str, "reboot") == 0) {
        *cmd = CMD_REBOOT;
    } else if (strcmp(cmd_str, "halt") == 0) {
        *cmd = CMD_HALT;
    } else {
        return -1;
    }
    return 0;
}

static bool command_is_read_only(enum control_command cmd) {
    switch (cmd) {
    case CMD_STATUS:
    case CMD_IS_ACTIVE:
    case CMD_IS_ENABLED:
    case CMD_LIST_UNITS:
    case CMD_LIST_TIMERS:
    case CMD_LIST_SOCKETS:
        return true;
    default:
        return false;
    }
}

struct user_daemon_config {
    bool supervisor;
    bool timer;
    bool socket_act;
};

#ifndef USER_MARKER_DIR
#define USER_MARKER_DIR "/etc/initd/users-enabled"
#endif
#define USER_CONFIG_FILENAME "user-daemons.conf"

static void daemon_config_init(struct user_daemon_config *cfg) {
    cfg->supervisor = false;
    cfg->timer = false;
    cfg->socket_act = false;
}

/* Copy at most dest_size-1 bytes, appending ellipsis if truncated. */
static void copy_truncated(char *dest, size_t dest_size, const char *src) {
    if (!dest || dest_size == 0) {
        return;
    }

    if (!src) {
        dest[0] = '\0';
        return;
    }

    size_t len = strnlen(src, dest_size - 1);
    memcpy(dest, src, len);
    dest[len] = '\0';

    if (src[len] != '\0' && dest_size > 4) {
        dest[dest_size - 1] = '\0';
        dest[dest_size - 2] = '.';
        dest[dest_size - 3] = '.';
        dest[dest_size - 4] = '.';
    }
}

static int ensure_directory_owned(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: %s exists and is not a directory\n", path);
            return -1;
        }
        return 0;
    }

    if (errno != ENOENT) {
        perror("stat");
        return -1;
    }

    if (mkdir(path, mode) < 0) {
        perror("mkdir");
        return -1;
    }

    /* Use fd-based operations to avoid TOCTOU race */
    int dir_fd = open(path, O_DIRECTORY | O_RDONLY);
    if (dir_fd < 0) {
        perror("open");
        rmdir(path);
        return -1;
    }

    if (fchown(dir_fd, uid, gid) < 0) {
        perror("fchown");
        close(dir_fd);
        rmdir(path);
        return -1;
    }

    if (fchmod(dir_fd, mode) < 0) {
        perror("fchmod");
        close(dir_fd);
        rmdir(path);
        return -1;
    }

    close(dir_fd);
    return 0;
}

static int ensure_root_marker_dir(void) {
    struct stat st;
    if (stat(USER_MARKER_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: %s exists and is not a directory\n", USER_MARKER_DIR);
            return -1;
        }
        return 0;
    }

    if (errno != ENOENT) {
        perror("stat");
        return -1;
    }

    if (mkdir(USER_MARKER_DIR, 0755) < 0) {
        perror("mkdir");
        return -1;
    }

    return 0;
}

static int validate_username(const char *user) {
    if (!user || user[0] == '\0') {
        return -1;
    }

    for (const char *p = user; *p; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-' || *p == '.')) {
            return -1;
        }
    }
    return 0;
}

static int load_daemon_config(const char *path,
                              struct user_daemon_config *cfg,
                              bool *exists) {
    daemon_config_init(cfg);
    *exists = false;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            return 0;
        }
        perror("fopen");
        return -1;
    }

    *exists = true;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\0' || *p == '\n') {
            continue;
        }

        char *equals = strchr(p, '=');
        if (!equals) {
            continue;
        }
        *equals = '\0';
        char *value = equals + 1;

        char *newline = strchr(value, '\n');
        if (newline) {
            *newline = '\0';
        }

        if (strcasecmp(value, "enabled") != 0 &&
            strcasecmp(value, "true") != 0 &&
            strcmp(value, "1") != 0) {
            continue;
        }

        if (strcasecmp(p, "supervisor") == 0) {
            cfg->supervisor = true;
        } else if (strcasecmp(p, "timer") == 0) {
            cfg->timer = true;
        } else if (strcasecmp(p, "socket") == 0 ||
                   strcasecmp(p, "socket-activator") == 0) {
            cfg->socket_act = true;
        }
    }

    fclose(f);
    return 0;
}

static int write_daemon_config(const char *dir,
                               const char *path,
                               const struct user_daemon_config *cfg,
                               uid_t uid,
                               gid_t gid) {
    char tmp_path[PATH_MAX];
    int written = snprintf(tmp_path, sizeof(tmp_path),
                           "%s/.user-daemons.conf.tmpXXXXXX", dir);
    if (written < 0 || (size_t)written >= sizeof(tmp_path)) {
        fprintf(stderr, "Error: temp path too long\n");
        return -1;
    }

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        perror("mkstemp");
        return -1;
    }

    FILE *out = fdopen(fd, "w");
    if (!out) {
        perror("fdopen");
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    fprintf(out, "# initd per-user daemon settings\n");
    fprintf(out, "supervisor=%s\n", cfg->supervisor ? "enabled" : "disabled");
    fprintf(out, "timer=%s\n", cfg->timer ? "enabled" : "disabled");
    fprintf(out, "socket=%s\n", cfg->socket_act ? "enabled" : "disabled");

    if (fflush(out) != 0) {
        perror("fflush");
        fclose(out);
        unlink(tmp_path);
        return -1;
    }

    if (fchmod(fd, 0640) < 0) {
        perror("fchmod");
        fclose(out);
        unlink(tmp_path);
        return -1;
    }

    if (fchown(fd, uid, gid) < 0) {
        perror("fchown");
        fclose(out);
        unlink(tmp_path);
        return -1;
    }

    if (fsync(fd) < 0) {
        perror("fsync");
        fclose(out);
        unlink(tmp_path);
        return -1;
    }

    if (fclose(out) != 0) {
        perror("fclose");
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) < 0) {
        perror("rename");
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

static int apply_daemon_token(const char *token,
                              bool enable,
                              struct user_daemon_config *cfg) {
    if (strcasecmp(token, "supervisor") == 0) {
        cfg->supervisor = enable;
    } else if (strcasecmp(token, "timer") == 0) {
        cfg->timer = enable;
    } else if (strcasecmp(token, "socket") == 0 ||
               strcasecmp(token, "socket-activator") == 0) {
        cfg->socket_act = enable;
    } else if (strcasecmp(token, "all") == 0) {
        cfg->supervisor = enable;
        cfg->timer = enable;
        cfg->socket_act = enable;
    } else {
        return -1;
    }
    return 0;
}

static int update_marker_file(const char *user, bool any_enabled) {
    char marker_path[PATH_MAX];
    int written = snprintf(marker_path, sizeof(marker_path),
                           USER_MARKER_DIR "/%s", user);
    if (written < 0 || (size_t)written >= sizeof(marker_path)) {
        fprintf(stderr, "Error: user name too long\n");
        return -1;
    }

    if (any_enabled) {
        int fd = open(marker_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) {
            perror("open");
            return -1;
        }
        if (close(fd) < 0) {
            perror("close");
            return -1;
        }
    } else {
        if (unlink(marker_path) < 0) {
            if (errno != ENOENT) {
                perror("unlink");
                return -1;
            }
        }
    }

    return 0;
}

static void print_daemon_status(const char *user,
                                const struct user_daemon_config *cfg,
                                bool marker_exists) {
    printf("User: %s\n", user);
    printf("  supervisor: %s\n", cfg->supervisor ? "enabled" : "disabled");
    printf("  timer: %s\n", cfg->timer ? "enabled" : "disabled");
    printf("  socket: %s\n", cfg->socket_act ? "enabled" : "disabled");
    printf("  reboot persistence marker: %s\n", marker_exists ? "present" : "absent");
}

static bool daemon_any_enabled(const struct user_daemon_config *cfg) {
    return cfg->supervisor || cfg->timer || cfg->socket_act;
}

static int handle_user_command(int argc, char *argv[], int index) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: user management commands require root privileges\n");
        return 1;
    }

    if (index + 1 >= argc) {
        fprintf(stderr, "Error: missing user subcommand\n");
        print_usage(argv[0]);
        return 1;
    }

    const char *subcmd = argv[index + 1];
    if (strcmp(subcmd, "enable") != 0 &&
        strcmp(subcmd, "disable") != 0 &&
        strcmp(subcmd, "status") != 0) {
        fprintf(stderr, "Error: unknown user subcommand '%s'\n", subcmd);
        print_usage(argv[0]);
        return 1;
    }

    if (index + 2 >= argc) {
        fprintf(stderr, "Error: missing user name\n");
        return 1;
    }

    const char *user = argv[index + 2];
    if (validate_username(user) < 0) {
        fprintf(stderr, "Error: invalid user name '%s'\n", user);
        return 1;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "Error: user '%s' not found\n", user);
        return 1;
    }

    if (ensure_root_marker_dir() < 0) {
        return 1;
    }

    if (strcmp(subcmd, "status") == 0) {
        char config_dir[PATH_MAX];
        char config_path[PATH_MAX];
        int written = snprintf(config_dir, sizeof(config_dir),
                               "%s/.config/initd", pw->pw_dir);
        if (written < 0 || (size_t)written >= sizeof(config_dir)) {
            fprintf(stderr, "Error: path too long\n");
            return 1;
        }
        written = snprintf(config_path, sizeof(config_path), "%s/%s",
                           config_dir, USER_CONFIG_FILENAME);
        if (written < 0 || (size_t)written >= sizeof(config_path)) {
            fprintf(stderr, "Error: path too long\n");
            return 1;
        }

        struct user_daemon_config cfg;
        bool exists;
        if (load_daemon_config(config_path, &cfg, &exists) < 0) {
            return 1;
        }

        char marker_path[PATH_MAX];
        snprintf(marker_path, sizeof(marker_path),
                 USER_MARKER_DIR "/%s", user);
        struct stat st;
        bool marker_exists = (stat(marker_path, &st) == 0);

        print_daemon_status(user, &cfg, marker_exists);
        return 0;
    }

    int daemon_argc = argc - (index + 3);
    char **daemon_argv = argv + index + 3;
    bool enable = (strcmp(subcmd, "enable") == 0);

    char config_dir[PATH_MAX];
    char config_path[PATH_MAX];
    int written = snprintf(config_dir, sizeof(config_dir),
                           "%s/.config/initd", pw->pw_dir);
    if (written < 0 || (size_t)written >= sizeof(config_dir)) {
        fprintf(stderr, "Error: path too long\n");
        return 1;
    }
    written = snprintf(config_path, sizeof(config_path),
                       "%s/%s", config_dir, USER_CONFIG_FILENAME);
    if (written < 0 || (size_t)written >= sizeof(config_path)) {
        fprintf(stderr, "Error: path too long\n");
        return 1;
    }

    char config_parent[PATH_MAX];
    written = snprintf(config_parent, sizeof(config_parent),
                       "%s/.config", pw->pw_dir);
    if (written < 0 || (size_t)written >= sizeof(config_parent)) {
        fprintf(stderr, "Error: path too long\n");
        return 1;
    }
    if (ensure_directory_owned(config_parent, 0750, pw->pw_uid, pw->pw_gid) < 0) {
        return 1;
    }
    if (ensure_directory_owned(config_dir, 0750, pw->pw_uid, pw->pw_gid) < 0) {
        return 1;
    }

    struct user_daemon_config cfg;
    bool config_exists;
    if (load_daemon_config(config_path, &cfg, &config_exists) < 0) {
        return 1;
    }

    if (daemon_argc == 0) {
        cfg.supervisor = enable;
        cfg.timer = enable;
        cfg.socket_act = enable;
    } else {
        for (int i = 0; i < daemon_argc; i++) {
            if (apply_daemon_token(daemon_argv[i], enable, &cfg) < 0) {
                fprintf(stderr, "Error: unknown daemon '%s'\n", daemon_argv[i]);
                return 1;
            }
        }
    }

    bool any_enabled = daemon_any_enabled(&cfg);

    if (write_daemon_config(config_dir, config_path, &cfg, pw->pw_uid, pw->pw_gid) < 0) {
        return 1;
    }

    if (update_marker_file(user, any_enabled) < 0) {
        return 1;
    }

    printf("Updated daemon settings for %s\n", user);
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

/* Offline enable/disable/is-enabled handler when daemon isn't available */
static int handle_offline_unit_operation(enum control_command cmd, const char *unit_name) {
    struct unit_file unit = {0};
    char unit_path[1024];

    /* Only enable/disable/is-enabled can work offline */
    if (cmd != CMD_ENABLE && cmd != CMD_DISABLE && cmd != CMD_IS_ENABLED) {
        return -1;
    }

    /* Search for unit file in standard directories */
    const char *search_dirs[] = {
        "/etc/initd/system",
        "/lib/initd/system",
        "/usr/lib/initd/system",
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        NULL
    };

    bool found = false;
    for (int i = 0; search_dirs[i]; i++) {
        snprintf(unit_path, sizeof(unit_path), "%s/%s", search_dirs[i], unit_name);
        if (parse_unit_file(unit_path, &unit) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Unit %s not found.\n", unit_name);
        return 1;
    }

    int result = 0;

    switch (cmd) {
    case CMD_ENABLE:
        /* Need root for enable */
        if (getuid() != 0) {
            fprintf(stderr, "Authentication required for enabling units (must be root)\n");
            free_unit_file(&unit);
            return 1;
        }

        if (enable_unit(&unit) < 0) {
            fprintf(stderr, "Failed to enable %s\n", unit_name);
            result = 1;
        }
        /* Silent success like systemd */
        break;

    case CMD_DISABLE:
        /* Need root for disable */
        if (getuid() != 0) {
            fprintf(stderr, "Authentication required for disabling units (must be root)\n");
            free_unit_file(&unit);
            return 1;
        }

        if (disable_unit(&unit) < 0) {
            fprintf(stderr, "Failed to disable %s\n", unit_name);
            result = 1;
        }
        /* Silent success like systemd */
        break;

    case CMD_IS_ENABLED:
        /* is-enabled doesn't need root */
        if (is_unit_enabled(&unit)) {
            printf("enabled\n");
            result = 0;
        } else {
            printf("disabled\n");
            result = 1;
        }
        break;

    default:
        result = -1;
        break;
    }

    free_unit_file(&unit);
    return result;
}

int main(int argc, char *argv[]) {
    const char *progname = argv[0];

    /* Check if called as systemctl (symlink) */
    char *base = strrchr(progname, '/');
    if (base) {
        progname = base + 1;
    }

    enum runtime_scope scope = SCOPE_AUTO;
    int cmd_index = 1;
    while (cmd_index < argc) {
        const char *arg = argv[cmd_index];
        if (strcmp(arg, "--user") == 0) {
            scope = SCOPE_USER;
            cmd_index++;
        } else if (strcmp(arg, "--system") == 0) {
            scope = SCOPE_SYSTEM;
            cmd_index++;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(progname);
            return 0;
        } else {
            break;
        }
    }

    if (cmd_index >= argc) {
        print_usage(progname);
        return 1;
    }

    if (strcmp(argv[cmd_index], "user") == 0) {
        return handle_user_command(argc, argv, cmd_index);
    }

    if (configure_runtime_dir(scope) < 0) {
        return 1;
    }

    const char *cmd_str = argv[cmd_index];
    enum control_command cmd;

    /* Parse command */
    if (parse_command(cmd_str, &cmd) < 0) {
        fprintf(stderr, "Error: Unknown command '%s'\n", cmd_str);
        print_usage(progname);
        return 1;
    }

    bool read_only_cmd = command_is_read_only(cmd);
    int cmd_argc = argc - cmd_index;
    int args_offset = cmd_index + 1;

    /* Handle list-units command */
    if (cmd == CMD_LIST_UNITS) {
        uint16_t flags = 0;

        /* Check for --all flag */
        if (cmd_argc >= 2 && strcmp(argv[args_offset], "--all") == 0) {
            flags |= REQ_FLAG_ALL;
        }

        /* Connect to supervisor (read-only socket) */
        int fd = connect_to_supervisor_status();
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
        int timer_fd = connect_to_timer_status();
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
        if (timer_count > 0 && timer_entries) {
            struct unit_list_entry *tmp = realloc(entries, total * sizeof(*entries));
            if (!tmp) {
                fprintf(stderr, "Error: Out of memory expanding unit list\n");
                free(entries);
                free(timer_entries);
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

                char desc_buf[96];
                char unit_buf[96];
                copy_truncated(desc_buf, sizeof(desc_buf), timer_entries[i].description);
                copy_truncated(unit_buf, sizeof(unit_buf), timer_entries[i].unit);

                int written;
                if (desc_buf[0] != '\0') {
                    written = snprintf(slot->description, sizeof(slot->description),
                                       "%s (timer for %s; next %s; last %s)",
                                       desc_buf,
                                       unit_buf,
                                       next_buf,
                                       last_buf);
                } else {
                    written = snprintf(slot->description, sizeof(slot->description),
                                       "Timer for %s (next %s; last %s)",
                                       unit_buf,
                                       next_buf,
                                       last_buf);
                }

                if (written < 0 || (size_t)written >= sizeof(slot->description)) {
                    slot->description[sizeof(slot->description) - 1] = '\0';
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
        /* Connect to timer daemon (read-only socket) */
        int fd = connect_to_timer_status();
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
        /* Connect to socket activator (read-only socket) */
        int fd = connect_to_socket_status();
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

    /* Handle shutdown commands (poweroff, reboot, halt) */
    if (cmd == CMD_POWEROFF || cmd == CMD_REBOOT || cmd == CMD_HALT) {
        int fd = connect_to_supervisor();
        if (fd < 0) {
            fprintf(stderr, "Error: Failed to connect to supervisor\n");
            fprintf(stderr, "Is the init system running?\n");
            return 1;
        }

        struct control_request req = {0};
        struct control_response resp = {0};
        req.header.length = sizeof(req);
        req.header.command = cmd;

        if (send_control_request(fd, &req) < 0) {
            fprintf(stderr, "Error: Failed to send shutdown request\n");
            close(fd);
            return 1;
        }

        if (recv_control_response(fd, &resp) < 0) {
            fprintf(stderr, "Error: Failed to receive response\n");
            close(fd);
            return 1;
        }

        close(fd);

        if (resp.code == RESP_SUCCESS) {
            printf("%s\n", resp.message[0] ? resp.message : "Shutdown initiated");
            return 0;
        } else {
            fprintf(stderr, "Error: %s\n", resp.message);
            return 1;
        }
    }

    /* Commands that require a unit name */
    if (cmd_argc < 2) {
        fprintf(stderr, "Error: Missing unit name\n");
        print_usage(progname);
        return 1;
    }

    const char *unit_name_arg = argv[args_offset];
    char unit_name[256];
    normalize_unit_name(unit_name, unit_name_arg, sizeof(unit_name));

    /* Determine which daemon to connect to based on unit type */
    int fd;
    const char *ext = strrchr(unit_name, '.');
    if (ext && strcmp(ext, ".timer") == 0) {
        /* Route timer units to timer daemon */
        fd = read_only_cmd ? connect_to_timer_status() : connect_to_timer_daemon();
        if (fd < 0) {
            /* Try offline mode for enable/disable/is-enabled */
            if (cmd == CMD_ENABLE || cmd == CMD_DISABLE || cmd == CMD_IS_ENABLED) {
                return handle_offline_unit_operation(cmd, unit_name);
            }
            fprintf(stderr, "Error: Failed to connect to timer daemon\n");
            fprintf(stderr, "Is the timer daemon running?\n");
            return 1;
        }
    } else if (ext && strcmp(ext, ".socket") == 0) {
        /* Route socket units to socket activator */
        fd = read_only_cmd ? connect_to_socket_status() : connect_to_socket_activator();
        if (fd < 0) {
            /* Try offline mode for enable/disable/is-enabled */
            if (cmd == CMD_ENABLE || cmd == CMD_DISABLE || cmd == CMD_IS_ENABLED) {
                return handle_offline_unit_operation(cmd, unit_name);
            }
            fprintf(stderr, "Error: Failed to connect to socket activator\n");
            fprintf(stderr, "Is the socket activator running?\n");
            return 1;
        }
    } else {
        /* Route service/target units to supervisor */
        fd = read_only_cmd ? connect_to_supervisor_status() : connect_to_supervisor();
        if (fd < 0) {
            /* Try offline mode for enable/disable/is-enabled */
            if (cmd == CMD_ENABLE || cmd == CMD_DISABLE || cmd == CMD_IS_ENABLED) {
                return handle_offline_unit_operation(cmd, unit_name);
            }
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
