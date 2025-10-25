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
    int after_count;
    int before_count;
    int requires_count;
    int wants_count;
    int conflicts_count;
    int provides_count;
    int on_failure_count;
};

/* Kill mode for service termination */
enum kill_mode {
    KILL_CONTROL_GROUP,  /* Kill all processes in the service's cgroup/pgrp */
    KILL_PROCESS,        /* Kill only the main process */
    KILL_MIXED,          /* SIGTERM to main, SIGKILL to others */
    KILL_NONE            /* Don't kill anything */
};

/* [Service] section */
struct service_section {
    enum service_type type;
    char *exec_start;
    char *exec_stop;
    char *exec_reload;
    char *exec_start_pre;
    char *exec_start_post;
    char user[64];
    char group[64];
    char working_directory[MAX_PATH];
    char *environment[MAX_ENV_VARS];
    int environment_count;
    char *environment_file;
    enum restart_policy restart;
    int restart_sec;
    int timeout_start_sec;
    int timeout_stop_sec;
    bool private_tmp;
    enum kill_mode kill_mode;
    int limit_nofile;    /* -1 = not set, 0 = unlimited (infinity) */
    int runtime_max_sec; /* 0 = no limit */
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
    int wanted_by_count;
    int required_by_count;
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
