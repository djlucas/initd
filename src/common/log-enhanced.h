/* log-enhanced.h - Enhanced logging with colors and dual output
 *
 * Extends the existing log.c with:
 * - Colored console output
 * - Log file support
 * - Clean status messages for console
 * - Detailed messages for files
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef LOG_ENHANCED_H
#define LOG_ENHANCED_H

#include "log.h"

/* Log levels for filtering */
typedef enum {
    LOGLEVEL_ERROR = 0,
    LOGLEVEL_WARN = 1,
    LOGLEVEL_INFO = 2,
    LOGLEVEL_DEBUG = 3
} log_level_t;

/* ANSI color codes */
#define COLOR_RESET     "\033[0m"
#define COLOR_BLUE      "\033[1;34m"    /* Bright blue for brackets */
#define COLOR_GREEN     "\033[1;32m"    /* Bright green for OK */
#define COLOR_YELLOW    "\033[1;33m"    /* Bright yellow for WARN */
#define COLOR_RED       "\033[1;31m"    /* Bright red for FAIL */
#define COLOR_CYAN      "\033[1;36m"    /* Bright cyan for INFO */
#define COLOR_GREY      "\033[2;37m"    /* Dim grey for DEBUG */

/* ANSI cursor control */
#define CURSOR_UP       "\033[A"        /* Move cursor up one line */
#define CLEAR_LINE      "\033[K"        /* Clear from cursor to end of line */

/* Initialize enhanced logging */
int log_enhanced_init(const char *ident, const char *log_file_path);

/* Set console and file log levels */
void log_set_console_level(log_level_t level);
void log_set_file_level(log_level_t level);

/* Close enhanced logging */
void log_enhanced_close(void);

/* Convenience logging functions */
void log_debug(const char *unit, const char *fmt, ...);
void log_info(const char *unit, const char *fmt, ...);
void log_warn(const char *unit, const char *fmt, ...);
void log_error(const char *unit, const char *fmt, ...);

/* Service status logging (clean console output) */
void log_service_starting(const char *unit_name, const char *description);
void log_service_started(const char *unit_name, const char *description);
void log_service_failed(const char *unit_name, const char *description, const char *reason);
void log_service_stopped(const char *unit_name, const char *description);

/* Target status logging */
void log_target_reached(const char *target_name, const char *description);

#endif /* LOG_ENHANCED_H */
