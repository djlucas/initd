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
#define MAX_CALENDAR_ENTRIES 8
#define MAX_RESTART_STATUS 16
#define MAX_INSTALL_ENTRIES MAX_DEPS
#define MAX_DEVICE_ALLOW 16
#define MAX_CAPABILITIES 64
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
    CONDITION_ENVIRONMENT,
    /* Platform-specific conditions */
    CONDITION_VIRTUALIZATION,
    CONDITION_AC_POWER,
    CONDITION_OS_RELEASE,
    CONDITION_KERNEL_VERSION,
    /* Linux-only conditions */
    CONDITION_KERNEL_COMMAND_LINE,
    CONDITION_KERNEL_MODULE_LOADED,
    CONDITION_SECURITY,
    CONDITION_CAPABILITY,
    CONDITION_CONTROL_GROUP_CONTROLLER,
    CONDITION_MEMORY_PRESSURE,
    CONDITION_CPU_PRESSURE,
    CONDITION_IO_PRESSURE,
    CONDITION_PATH_IS_ENCRYPTED,
    CONDITION_FIRMWARE,
    CONDITION_CPU_FEATURE,
    CONDITION_VERSION,
    CONDITION_CREDENTIAL,
    CONDITION_NEEDS_UPDATE,
    CONDITION_FIRST_BOOT
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

/* Device access control for cgroup device controller */
struct device_allow {
    char path[MAX_PATH];  /* Device path or pattern (e.g., /dev/sda, block-*, char-usb) */
    bool read;            /* Allow read access */
    bool write;           /* Allow write access */
    bool mknod;           /* Allow mknod (create device nodes) */
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
    int log_level_max;            /* LogLevelMax= (maximum log level to forward, -1 = not set) */
    mode_t umask_value;           /* UMask= (octal file creation mask) */
    bool no_new_privs;            /* NoNewPrivileges= (prevent privilege escalation on execve) */
    char root_directory[MAX_PATH]; /* RootDirectory= (chroot jail path) */
    char root_image[MAX_PATH];    /* RootImage= (disk image to mount as root) */
    int restart_max_delay_sec;    /* RestartMaxDelaySec= (max exponential backoff delay, 0 = not set) */
    bool restrict_suid_sgid;      /* RestrictSUIDSGID= (remove suid/sgid bits on exec) */
    long memory_limit;            /* MemoryLimit= (address space limit in bytes, -1 = not set) */
    int timeout_abort_sec;        /* TimeoutAbortSec= (timeout for abort signal, 0 = use TimeoutStopSec) */
    int timeout_start_failure_mode; /* TimeoutStartFailureMode= (0=terminate, 1=abort, 2=kill) */
    int protect_system;           /* ProtectSystem= (0=no, 1=yes, 2=full, 3=strict) */
    int protect_home;             /* ProtectHome= (0=no, 1=yes, 2=read-only, 3=tmpfs) */
    bool private_devices;         /* PrivateDevices= (mount private /dev with minimal nodes) */
    bool protect_kernel_tunables; /* ProtectKernelTunables= (make /proc/sys, /sys read-only) */
    bool protect_control_groups;  /* ProtectControlGroups= (make /sys/fs/cgroup read-only) */
    int mount_flags;              /* MountFlags= (0=shared, 1=slave, 2=private) */
    bool dynamic_user;            /* DynamicUser= (allocate ephemeral UID/GID) */
    struct device_allow device_allow[MAX_DEVICE_ALLOW]; /* DeviceAllow= (cgroup device whitelist) */
    int device_allow_count;       /* Number of DeviceAllow entries */
    char *capability_bounding_set[MAX_CAPABILITIES]; /* CapabilityBoundingSet= (Linux capabilities to keep) */
    int capability_bounding_set_count;  /* Number of bounding set capabilities */
    char *ambient_capabilities[MAX_CAPABILITIES]; /* AmbientCapabilities= (Linux ambient capabilities) */
    int ambient_capabilities_count;     /* Number of ambient capabilities */
};

/* [Timer] section */
struct timer_section {
    char *on_calendar[MAX_CALENDAR_ENTRIES];  /* Multiple OnCalendar= entries */
    int on_calendar_count;
    int on_boot_sec;
    int on_startup_sec;
    int on_unit_active_sec;
    int on_unit_inactive_sec;
    bool persistent;
    int randomized_delay_sec;
    int accuracy_sec;  /* AccuracySec= - allowed firing window (default: 60s) */
    char *unit;        /* Unit= - service to activate (default: timer name minus .timer) */
    bool fixed_random_delay;  /* FixedRandomDelay= - use fixed random value */
    bool remain_after_elapse; /* RemainAfterElapse= - keep timer active after firing (default: true) */
    bool wake_system;  /* WakeSystem= - wake from suspend to fire timer */
    bool on_clock_change;     /* OnClockChange= - fire when system clock jumps */
    bool on_timezone_change;  /* OnTimezoneChange= - fire when timezone changes */
};

/* [Socket] section */
struct socket_section {
    char *listen_stream;
    char *listen_datagram;
    int idle_timeout;  /* Custom: kill service after idle */

    /* Easy portable directives */
    mode_t socket_mode;        /* SocketMode= - socket file permissions (default: 0666) */
    mode_t directory_mode;     /* DirectoryMode= - directory permissions for socket path */
    int backlog;               /* Backlog= - listen backlog (default: SOMAXCONN) */
    char *service;             /* Service= - service to activate (default: socket name minus .socket) */
    bool keep_alive;           /* KeepAlive= - SO_KEEPALIVE */
    int send_buffer;           /* SendBuffer= - SO_SNDBUF (bytes, -1 = not set) */
    int receive_buffer;        /* ReceiveBuffer= - SO_RCVBUF (bytes, -1 = not set) */
    bool broadcast;            /* Broadcast= - SO_BROADCAST */
    int ip_tos;                /* IPTOS= - IP_TOS (-1 = not set) */
    int ip_ttl;                /* IPTTL= - IP_TTL (-1 = not set) */
    bool remove_on_stop;       /* RemoveOnStop= - remove socket file on stop */
    char *symlinks[MAX_DEPS];  /* Symlinks= - symlinks to socket */
    int symlinks_count;

    /* Medium portable directives */
    char socket_user[64];      /* SocketUser= - Unix socket owner (default: service user) */
    char socket_group[64];     /* SocketGroup= - Unix socket group (default: service group) */
    int keep_alive_time;       /* KeepAliveTimeSec= - TCP_KEEPIDLE seconds (-1 = not set) */
    int keep_alive_interval;   /* KeepAliveIntervalSec= - TCP_KEEPINTVL seconds (-1 = not set) */
    int keep_alive_count;      /* KeepAliveProbes= - TCP_KEEPCNT count (-1 = not set) */
    bool reuse_port;           /* ReusePort= - SO_REUSEPORT (default: false) */
    bool free_bind;             /* FreeBind= - IP_FREEBIND/IP_BINDANY/SO_BINDANY */
    bool transparent;           /* Transparent= - IP_TRANSPARENT (Linux only) */
    char *tcp_congestion;       /* TCPCongestion= - TCP congestion algorithm */
    char *exec_start_pre;       /* ExecStartPre= - command before activation */
    char *exec_start_post;      /* ExecStartPost= - command after activation */
    char *exec_stop_post;       /* ExecStopPost= - command after service stops */
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
