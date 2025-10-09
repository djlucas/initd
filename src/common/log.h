/* log.h - Logging with early boot buffering and syslog integration
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef LOG_H
#define LOG_H

#include <syslog.h>
#include <stdbool.h>
#include <time.h>

/* Log priorities (match syslog) */
#define LOG_EMERG   0   /* system is unusable */
#define LOG_ALERT   1   /* action must be taken immediately */
#define LOG_CRIT    2   /* critical conditions */
#define LOG_ERR     3   /* error conditions */
#define LOG_WARNING 4   /* warning conditions */
#define LOG_NOTICE  5   /* normal but significant condition */
#define LOG_INFO    6   /* informational */
#define LOG_DEBUG   7   /* debug-level messages */

/* Initialize logging subsystem */
int log_init(const char *ident);

/* Close logging subsystem */
void log_close(void);

/* Check if syslog is ready and flush buffer if needed */
void log_check_syslog(void);

/* Log a message (with printf formatting) */
void log_msg(int priority, const char *unit, const char *fmt, ...);

/* Notify that syslog service has started */
void log_syslog_ready(void);

/* Get buffer statistics (for debugging) */
void log_get_stats(size_t *buffered, size_t *dropped, bool *syslog_ready);

#endif /* LOG_H */
