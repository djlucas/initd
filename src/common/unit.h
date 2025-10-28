/* unit.h - Unit file data structures
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef UNIT_H
#define UNIT_H

#include <stdbool.h>
#include <sys/types.h>

#define MAX_UNIT_NAME 256
#define MAX_PATH 1024
#define MAX_ARGS 64
#define MAX_DEPS 32
#define MAX_ENV_VARS 64
#define MAX_CONDITIONS 32
#define MAX_EXEC_COMMANDS 16
#define MAX_RESTART_STATUS 16
#define MAX_INSTALL_ENTRIES MAX_DEPS
#define INITD_DEFAULT_START_LIMIT_INTERVAL_SEC 60
#define INITD_DEFAULT_START_LIMIT_BURST 5
#define INITD_MIN_RESTART_INTERVAL_SEC 1
#define INITD_MAX_START_LIMIT_BURST_TRACK 128

/* Unit types */
enum unit_type {
    UNIT_SERVICE,
    UNIT_TARGET,
    UNIT_TIMER,
    UNIT_SOCKET
};

/* Service types */
enum service_type {
    SERVICE_SIMPLE,
    SERVICE_FORKING,
    SERVICE_ONESHOT
};

/* Restart policy */
enum restart_policy {
    RESTART_NO,
    RESTART_ALWAYS,
    RESTART_ON_FAILURE
};

/* Unit state */
enum unit_state {
    STATE_INACTIVE,
    STATE_ACTIVATING,
    STATE_ACTIVE,
    STATE_DEACTIVATING,
    STATE_FAILED
};

/* Dependency traversal state */
enum dependency_visit_state {
    DEP_VISIT_NONE = 0,
    DEP_VISIT_IN_PROGRESS,
    DEP_VISIT_DONE
};

/* Condition types */
enum unit_condition_type {
    /* Path-based conditions (already implemented) */
    CONDITION_PATH_EXISTS,
    CONDITION_PATH_EXISTS_GLOB,
    CONDITION_PATH_IS_DIRECTORY,
    CONDITION_PATH_IS_SYMBOLIC_LINK,
    CONDITION_PATH_IS_MOUNT_POINT,
    CONDITION_PATH_IS_READ_WRITE,
    CONDITION_DIRECTORY_NOT_EMPTY,
    CONDITION_FILE_IS_EXECUTABLE,
    /* New POSIX-portable conditions */
    CONDITION_FILE_NOT_EMPTY,
    CONDITION_USER,
    CONDITION_GROUP,
    CONDITION_HOST,
    CONDITION_ARCHITECTURE,
    CONDITION_MEMORY,
    CONDITION_CPUS,
    CONDITION_ENVIRONMENT
};

struct unit_condition {
    enum unit_condition_type type;
    bool negate;
    bool is_assert;  /* true = Assert*, false = Condition* */
    char *value;
};

/* [Unit] section */
struct unit_section {
    char description[256];
    char *after[MAX_DEPS];      /* Units to start after */
    char *before[MAX_DEPS];     /* Units to start before */
    char *requires[MAX_DEPS];   /* Hard dependencies */
    char *wants[MAX_DEPS];      /* Soft dependencies */
    char *conflicts[MAX_DEPS];  /* Conflicting units */
    char *provides[MAX_DEPS];   /* Virtual names this unit provides */
    char *on_failure[MAX_DEPS]; /* Units to activate on failure */
    char *binds_to[MAX_DEPS];   /* Units whose lifecycle we bind to */
    char *part_of[MAX_DEPS];    /* Parent units that control our stop/reload */
    struct unit_condition conditions[MAX_CONDITIONS];
    int start_limit_interval_sec;
    int start_limit_burst;
    int start_limit_action;
    bool stop_when_unneeded;
    bool refuse_manual_start;
    bool refuse_manual_stop;
    bool allow_isolate;
    bool default_dependencies;
    bool start_limit_interval_set;
    bool start_limit_burst_set;
    bool start_limit_action_set;
    int after_count;
    int before_count;
    int requires_count;
    int wants_count;
    int conflicts_count;
    int provides_count;
    int on_failure_count;
    int binds_to_count;
    int part_of_count;
    int condition_count;
};

/* Kill mode for service termination */
enum kill_mode {
    KILL_CONTROL_GROUP,  /* Kill all processes in the service's cgroup/pgrp */
    KILL_PROCESS,        /* Kill only the main process */
    KILL_MIXED,          /* SIGTERM to main, SIGKILL to others */
    KILL_NONE            /* Don't kill anything */
};

enum start_limit_action {
    START_LIMIT_ACTION_NONE = 0,
    START_LIMIT_ACTION_REBOOT,
    START_LIMIT_ACTION_REBOOT_FORCE,
    START_LIMIT_ACTION_EXIT_FORCE,
    START_LIMIT_ACTION_REBOOT_IMMEDIATE
};

/* Standard I/O handling */
enum standard_io {
    STDIO_INHERIT,       /* Inherit from parent (default) */
    STDIO_NULL,          /* Redirect to /dev/null */
    STDIO_TTY,           /* Connect to TTY (use working_directory as TTY path) */
    STDIO_TTY_FORCE,     /* Like TTY but force even if not a TTY */
    STDIO_FILE,          /* Read/write from file path */
    STDIO_SOCKET,        /* Use socket FD (for socket activation) */
    STDIO_DATA           /* Read from embedded data (StandardInputText/Data) */
};

/* [Service] section */
struct service_section {
    enum service_type type;
    char *exec_start;
    char *exec_start_list[MAX_EXEC_COMMANDS];
    int exec_start_count;
    char *exec_stop;
    char *exec_stop_post[MAX_EXEC_COMMANDS];
    int exec_stop_post_count;
    char *exec_reload;
    char *exec_start_pre;
    char *exec_start_post;
    char *exec_condition[MAX_EXEC_COMMANDS];
    int exec_condition_count;
    char user[64];
    char group[64];
    char working_directory[MAX_PATH];
    char tty_path[MAX_PATH];  /* Path to TTY device for StandardInput=tty */
    char input_file[MAX_PATH];   /* Path for StandardInput=file:path */
    char output_file[MAX_PATH];  /* Path for StandardOutput=file:path */
    char error_file[MAX_PATH];   /* Path for StandardError=file:path */
    char *input_data;             /* Buffer for StandardInput=data (from StandardInputText/Data) */
    size_t input_data_size;       /* Size of input_data buffer */
    char *environment[MAX_ENV_VARS];
    int environment_count;
    char *environment_file;
    enum restart_policy restart;
    int restart_sec;
    int timeout_start_sec;
    int timeout_stop_sec;
    bool private_tmp;
    bool remain_after_exit;
    enum standard_io standard_input;
    enum standard_io standard_output;
   enum standard_io standard_error;
   enum kill_mode kill_mode;
   int limit_nofile;    /* -1 = not set, 0 = unlimited (infinity) */
   long limit_cpu;      /* LimitCPU= (-1 = not set, 0 = unlimited) */
   long limit_fsize;    /* LimitFSIZE= */
   long limit_data;     /* LimitDATA= */
   long limit_stack;    /* LimitSTACK= */
   long limit_core;     /* LimitCORE= */
   long limit_rss;      /* LimitRSS= (deprecated on Linux) */
   long limit_as;       /* LimitAS= */
   long limit_nproc;    /* LimitNPROC= */
   long limit_memlock;  /* LimitMEMLOCK= */
   long limit_locks;    /* LimitLOCKS= (obsolete on Linux) */
   long limit_sigpending; /* LimitSIGPENDING= (Linux only) */
   long limit_msgqueue; /* LimitMSGQUEUE= (Linux only) */
   long limit_nice;     /* LimitNICE= (Linux only) */
   long limit_rtprio;   /* LimitRTPRIO= (Linux only) */
   long limit_rttime;   /* LimitRTTIME= (Linux only) */
   int runtime_max_sec; /* 0 = no limit */
    int restart_prevent_statuses[MAX_RESTART_STATUS];
    int restart_force_statuses[MAX_RESTART_STATUS];
    int restart_prevent_count;
    int restart_force_count;
    char *pid_file;
    char syslog_identifier[256];  /* SyslogIdentifier= */
    int syslog_facility;          /* SyslogFacility= (LOG_USER, LOG_DAEMON, etc.) */
    int syslog_level;             /* SyslogLevel= (LOG_INFO, LOG_DEBUG, etc.) */
    bool syslog_level_prefix;     /* SyslogLevelPrefix= */
    mode_t umask_value;           /* UMask= (octal file creation mask) */
    bool no_new_privs;            /* NoNewPrivileges= (prevent privilege escalation on execve) */
    char root_directory[MAX_PATH]; /* RootDirectory= (chroot jail path) */
};

/* [Timer] section */
struct timer_section {
    char *on_calendar;
    int on_boot_sec;
    int on_startup_sec;
    int on_unit_active_sec;
    int on_unit_inactive_sec;
    bool persistent;
    int randomized_delay_sec;
};

/* [Socket] section */
struct socket_section {
    char *listen_stream;
    char *listen_datagram;
    int idle_timeout;  /* Custom: kill service after idle */
};

/* [Install] section */
struct install_section {
    char *wanted_by[MAX_DEPS];
    char *required_by[MAX_DEPS];
    char *also[MAX_INSTALL_ENTRIES];
    char *alias[MAX_INSTALL_ENTRIES];
    int wanted_by_count;
    int required_by_count;
    int also_count;
    int alias_count;
    char default_instance[256];
};

/* Complete unit file representation */
struct unit_file {
    char name[MAX_UNIT_NAME];
    char path[MAX_PATH];
    enum unit_type type;
    enum unit_state state;
    bool enabled;

    struct unit_section unit;
    union {
        struct service_section service;
        struct timer_section timer;
        struct socket_section socket;
    } config;
    struct install_section install;

    /* Runtime state */
    pid_t pid;              /* For services */
    int restart_count;
    time_t last_start;

    /* Dependency traversal bookkeeping */
    unsigned int start_traversal_id;
    unsigned int stop_traversal_id;
    enum dependency_visit_state start_visit_state;
    enum dependency_visit_state stop_visit_state;

    /* Isolation traversal bookkeeping */
    unsigned int isolate_mark_generation;
    bool isolate_needed;

    /* Linked list for dependency graph */
    struct unit_file *next;
};

#endif /* UNIT_H */
