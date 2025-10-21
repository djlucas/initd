/* log-enhanced.c - Enhanced logging with colors and dual output
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "log-enhanced.h"

/* Enhanced log state */
static struct {
    FILE *log_file;
    log_level_t console_level;
    log_level_t file_level;
    int use_colors;  /* 1 if stderr is a TTY */
    char ident[64];
} enhanced_log_state = {
    .log_file = NULL,
    .console_level = LOGLEVEL_INFO,
    .file_level = LOGLEVEL_DEBUG,
    .use_colors = 0,
    .ident = {0}
};

/* Level to string mapping */
static const char *level_names[] = {
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};

/* Level to color mapping (for console) */
static const char *level_colors[] = {
    COLOR_RED,      /* ERROR */
    COLOR_YELLOW,   /* WARN */
    COLOR_CYAN,     /* INFO */
    COLOR_GREY      /* DEBUG */
};

/* Initialize enhanced logging */
int log_enhanced_init(const char *ident, const char *log_file_path) {
    if (ident) {
        strncpy(enhanced_log_state.ident, ident, sizeof(enhanced_log_state.ident) - 1);
    }

    /* Initialize basic syslog buffering first so we can log failures */
    log_init(ident);

    /* Check if stderr is a TTY for color support */
    enhanced_log_state.use_colors = isatty(STDERR_FILENO);

    /* Open log file if specified */
    if (log_file_path) {
        enhanced_log_state.log_file = fopen(log_file_path, "a");
        if (!enhanced_log_state.log_file) {
            log_debug(ident, "log file %s not available yet: %s",
                      log_file_path, strerror(errno));
            return -1;
        }
        /* Unbuffered for real-time logging */
        setbuf(enhanced_log_state.log_file, NULL);
    }

    return 0;
}

/* Set console log level */
void log_set_console_level(log_level_t level) {
    enhanced_log_state.console_level = level;
}

/* Set file log level */
void log_set_file_level(log_level_t level) {
    enhanced_log_state.file_level = level;
}

/* Close enhanced logging */
void log_enhanced_close(void) {
    if (enhanced_log_state.log_file) {
        fclose(enhanced_log_state.log_file);
        enhanced_log_state.log_file = NULL;
    }
    log_close();
}

/* Format timestamp */
static void format_timestamp(char *buf, size_t size) {
    struct timespec ts;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);

    snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec / 1000000);
}

/* Internal logging function */
static void log_internal(log_level_t level, const char *unit, const char *fmt, va_list args) {
    char message[1024];
    char timestamp[32];

    /* Format the message */
    vsnprintf(message, sizeof(message), fmt, args);

    /* Log to file if level qualifies */
    if (enhanced_log_state.log_file && level <= enhanced_log_state.file_level) {
        format_timestamp(timestamp, sizeof(timestamp));
        if (unit && unit[0]) {
            fprintf(enhanced_log_state.log_file, "[%s] [%s] [%s] %s\n",
                    timestamp, level_names[level], unit, message);
        } else {
            fprintf(enhanced_log_state.log_file, "[%s] [%s] %s\n",
                    timestamp, level_names[level], message);
        }
    }

    /* Log to console if level qualifies */
    if (level <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            /* Colored output */
            fprintf(stderr, "%s[%s%-6s%s]%s %s\n",
                    COLOR_BLUE,
                    level_colors[level],
                    level_names[level],
                    COLOR_BLUE,
                    COLOR_RESET,
                    message);
        } else {
            /* Plain output */
            fprintf(stderr, "[%-6s] %s\n", level_names[level], message);
        }
    }

    /* Also send to syslog buffer (will be flushed when syslog is ready) */
    int syslog_priority = LOG_DEBUG;
    switch (level) {
        case LOGLEVEL_ERROR: syslog_priority = LOG_ERR; break;
        case LOGLEVEL_WARN:  syslog_priority = LOG_WARNING; break;
        case LOGLEVEL_INFO:  syslog_priority = LOG_INFO; break;
        case LOGLEVEL_DEBUG: syslog_priority = LOG_DEBUG; break;
    }
    log_msg(syslog_priority, unit, "%s", message);
}

/* Convenience logging functions */
void log_debug(const char *unit, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LOGLEVEL_DEBUG, unit, fmt, args);
    va_end(args);
}

void log_info(const char *unit, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LOGLEVEL_INFO, unit, fmt, args);
    va_end(args);
}

void log_warn(const char *unit, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LOGLEVEL_WARN, unit, fmt, args);
    va_end(args);
}

void log_error(const char *unit, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LOGLEVEL_ERROR, unit, fmt, args);
    va_end(args);
}

/* Service status logging (clean console output) */
void log_service_starting(const char *unit_name) {
    /* Console: [  INFO  ] Starting foo.service */
    if (LOGLEVEL_INFO <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            fprintf(stderr, "%s[%s  INFO  %s]%s Starting %s...\n",
                    COLOR_BLUE, COLOR_CYAN, COLOR_BLUE, COLOR_RESET, unit_name);
        } else {
            fprintf(stderr, "[  INFO  ] Starting %s...\n", unit_name);
        }
    }

    /* File: Detailed with timestamp */
    if (enhanced_log_state.log_file && LOGLEVEL_INFO <= enhanced_log_state.file_level) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        fprintf(enhanced_log_state.log_file, "[%s] [INFO] Starting %s\n",
                timestamp, unit_name);
    }
}

void log_service_started(const char *unit_name) {
    /* Console: [   OK   ] Started foo.service */
    if (LOGLEVEL_INFO <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            fprintf(stderr, "%s[%s   OK   %s]%s Started %s\n",
                    COLOR_BLUE, COLOR_GREEN, COLOR_BLUE, COLOR_RESET, unit_name);
        } else {
            fprintf(stderr, "[   OK   ] Started %s\n", unit_name);
        }
    }

    /* File: Detailed with timestamp */
    if (enhanced_log_state.log_file && LOGLEVEL_INFO <= enhanced_log_state.file_level) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        fprintf(enhanced_log_state.log_file, "[%s] [INFO] Started %s\n",
                timestamp, unit_name);
    }
}

void log_service_failed(const char *unit_name, const char *reason) {
    /* Console: [ FAILED ] Failed to start foo.service - reason */
    if (LOGLEVEL_ERROR <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            if (reason && reason[0]) {
                fprintf(stderr, "%s[%s FAILED %s]%s Failed to start %s - %s\n",
                        COLOR_BLUE, COLOR_RED, COLOR_BLUE, COLOR_RESET, unit_name, reason);
            } else {
                fprintf(stderr, "%s[%s FAILED %s]%s Failed to start %s\n",
                        COLOR_BLUE, COLOR_RED, COLOR_BLUE, COLOR_RESET, unit_name);
            }
        } else {
            if (reason && reason[0]) {
                fprintf(stderr, "[ FAILED ] Failed to start %s - %s\n", unit_name, reason);
            } else {
                fprintf(stderr, "[ FAILED ] Failed to start %s\n", unit_name);
            }
        }
    }

    /* File: Detailed with timestamp */
    if (enhanced_log_state.log_file && LOGLEVEL_ERROR <= enhanced_log_state.file_level) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        if (reason && reason[0]) {
            fprintf(enhanced_log_state.log_file, "[%s] [ERROR] Failed to start %s - %s\n",
                    timestamp, unit_name, reason);
        } else {
            fprintf(enhanced_log_state.log_file, "[%s] [ERROR] Failed to start %s\n",
                    timestamp, unit_name);
        }
    }
}

void log_service_stopped(const char *unit_name) {
    /* Console: [   OK   ] Stopped foo.service */
    if (LOGLEVEL_INFO <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            fprintf(stderr, "%s[%s   OK   %s]%s Stopped %s\n",
                    COLOR_BLUE, COLOR_GREEN, COLOR_BLUE, COLOR_RESET, unit_name);
        } else {
            fprintf(stderr, "[   OK   ] Stopped %s\n", unit_name);
        }
    }

    /* File: Detailed with timestamp */
    if (enhanced_log_state.log_file && LOGLEVEL_INFO <= enhanced_log_state.file_level) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        fprintf(enhanced_log_state.log_file, "[%s] [INFO] Stopped %s\n",
                timestamp, unit_name);
    }
}

void log_target_reached(const char *target_name) {
    /* Console: [   OK   ] Reached sysinit.target */
    if (LOGLEVEL_INFO <= enhanced_log_state.console_level) {
        if (enhanced_log_state.use_colors) {
            fprintf(stderr, "%s[%s   OK   %s]%s Reached %s\n",
                    COLOR_BLUE, COLOR_GREEN, COLOR_BLUE, COLOR_RESET, target_name);
        } else {
            fprintf(stderr, "[   OK   ] Reached %s\n", target_name);
        }
    }

    /* File: Detailed with timestamp */
    if (enhanced_log_state.log_file && LOGLEVEL_INFO <= enhanced_log_state.file_level) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        fprintf(enhanced_log_state.log_file, "[%s] [INFO] Reached %s\n",
                timestamp, target_name);
    }
}
