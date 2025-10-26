/* control.h - Control protocol between initctl and supervisor-worker
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef CONTROL_H
#define CONTROL_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define INITD_RUNTIME_DIR_ENV "INITD_RUNTIME_DIR"
#ifndef INITD_RUNTIME_DEFAULT
#define INITD_RUNTIME_DEFAULT "/run/initd"
#endif

#define CONTROL_SOCKET_NAME "supervisor/supervisor.sock"
#define CONTROL_STATUS_SOCKET_NAME "supervisor/supervisor.status.sock"
#define TIMER_SOCKET_NAME "timer/timer.sock"
#define TIMER_STATUS_SOCKET_NAME "timer/timer.status.sock"
#define SOCKET_ACTIVATOR_SOCKET_NAME "socket/socket-activator.sock"
#define SOCKET_ACTIVATOR_STATUS_SOCKET_NAME "socket/socket-activator.status.sock"

/* Control socket default paths (system scope) */
#define CONTROL_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" CONTROL_SOCKET_NAME
#define CONTROL_STATUS_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" CONTROL_STATUS_SOCKET_NAME
#define TIMER_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" TIMER_SOCKET_NAME
#define TIMER_STATUS_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" TIMER_STATUS_SOCKET_NAME
#define SOCKET_ACTIVATOR_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" SOCKET_ACTIVATOR_SOCKET_NAME
#define SOCKET_ACTIVATOR_STATUS_SOCKET_PATH INITD_RUNTIME_DEFAULT "/" SOCKET_ACTIVATOR_STATUS_SOCKET_NAME

/* Command codes */
enum control_command {
    CMD_START = 1,
    CMD_STOP,
    CMD_RESTART,
    CMD_RELOAD,
    CMD_ENABLE,
    CMD_DISABLE,
    CMD_STATUS,
    CMD_IS_ACTIVE,
    CMD_IS_ENABLED,
    CMD_LIST_UNITS,
    CMD_LIST_TIMERS,
    CMD_LIST_SOCKETS,
    CMD_DAEMON_RELOAD,
    CMD_ISOLATE,
    CMD_NOTIFY_INACTIVE,
    CMD_SOCKET_ADOPT,
    CMD_POWEROFF,
    CMD_REBOOT,
    CMD_HALT,
    CMD_DUMP_LOGS
};

/* Response codes */
enum control_response_code {
    RESP_SUCCESS = 0,
    RESP_FAILURE = 1,
    RESP_UNIT_NOT_FOUND = 2,
    RESP_UNIT_ALREADY_ACTIVE = 3,
    RESP_UNIT_INACTIVE = 4,
    RESP_PERMISSION_DENIED = 5,
    RESP_INVALID_COMMAND = 6
};

/* Unit state for status responses */
enum unit_state_response {
    UNIT_STATE_INACTIVE = 0,
    UNIT_STATE_ACTIVATING,
    UNIT_STATE_ACTIVE,
    UNIT_STATE_DEACTIVATING,
    UNIT_STATE_FAILED,
    UNIT_STATE_UNKNOWN
};

/* Request flags */
#define REQ_FLAG_ALL       0x0001  /* Include systemd directories for list-units */
#define REQ_FLAG_INTERNAL  0x0002  /* Sent by timers/socket activator (not manual ctl) */

/* Message header */
struct msg_header {
    uint32_t length;    // Total message length (including header)
    uint16_t command;   // Command code
    uint16_t flags;     // Request flags
};

/* Request message (header + unit name) */
struct control_request {
    struct msg_header header;
    char unit_name[256];
    uint32_t aux_pid;      // Optional: external PID (socket activation)
    uint32_t aux_data;     // Reserved for future use
};

/* Response message (header + status info) */
struct control_response {
    struct msg_header header;
    uint32_t code;              // Response code
    uint32_t state;             // Unit state (for STATUS/IS_ACTIVE)
    pid_t pid;                  // Service PID (for STATUS)
    char message[512];          // Human-readable message
};

/* List entry for LIST_UNITS */
struct unit_list_entry {
    char name[256];
    uint32_t state;
    pid_t pid;
    char description[256];
};

/* Timer entry for LIST_TIMERS */
struct timer_list_entry {
    char name[256];
    char unit[280];             // Unit to activate (e.g., backup.service) - extra room for suffix
    time_t next_run;            // Next scheduled run time
    time_t last_run;            // Last run time (0 if never)
    uint32_t state;             // Timer state
    char description[256];
};

/* Socket entry for LIST_SOCKETS */
struct socket_list_entry {
    char name[256];             // Socket unit name (e.g., sshd.socket)
    char listen[256];           // Listen address (e.g., [::]:22, /run/foo.sock)
    char unit[256];             // Unit to activate (e.g., sshd.service)
    uint32_t state;             // Socket state (listening/failed)
    pid_t service_pid;          // Active service PID (0 if none)
    char description[256];
};

/* Control protocol functions */
int send_control_request(int fd, const struct control_request *req);
int recv_control_request(int fd, struct control_request *req);
int send_control_response(int fd, const struct control_response *resp);
int recv_control_response(int fd, struct control_response *resp);

/* Unit list functions */
int send_unit_list(int fd, const struct unit_list_entry *entries, size_t count);
int recv_unit_list(int fd, struct unit_list_entry **entries, size_t *count);

/* Timer list functions */
int send_timer_list(int fd, const struct timer_list_entry *entries, size_t count);
int recv_timer_list(int fd, struct timer_list_entry **entries, size_t *count);

/* Socket list functions */
int send_socket_list(int fd, const struct socket_list_entry *entries, size_t count);
int recv_socket_list(int fd, struct socket_list_entry **entries, size_t *count);

/* Helper functions */
int initd_set_runtime_dir(const char *path);
int initd_ensure_runtime_dir(void);
int initd_default_user_runtime_dir(char *buf, size_t len);
int initd_validate_runtime_dir(const char *path, bool user_mode);
int ensure_component_runtime_dir(const char *component_name, uid_t target_uid, gid_t target_gid, bool user_mode);
const char *control_socket_path(bool status);
const char *timer_socket_path(bool status);
const char *socket_activator_socket_path(bool status);

/* Runtime mode detection */
bool initd_is_running_as_init(void);

int connect_to_supervisor(void);
int connect_to_supervisor_status(void);
int connect_to_timer_daemon(void);
int connect_to_timer_status(void);
int connect_to_socket_activator(void);
int connect_to_socket_status(void);
const char *state_to_string(enum unit_state_response state);
const char *command_to_string(enum control_command cmd);

#endif /* CONTROL_H */
