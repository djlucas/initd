/* log.c - Logging with early boot buffering and syslog integration
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <stdbool.h>
#include <unistd.h>
#include "log.h"

#define MAX_BUFFER_ENTRIES 1000
#define MAX_MESSAGE_LEN 1024
#define MAX_UNIT_LEN 256

/* Buffered log entry */
struct log_entry {
    struct timespec boot_time;  /* CLOCK_BOOTTIME */
    int priority;
    char unit[MAX_UNIT_LEN];
    char message[MAX_MESSAGE_LEN];
    struct log_entry *next;
};

/* Log buffer state */
static struct {
    struct log_entry *head;     /* Oldest entry (dequeue here) */
    struct log_entry *tail;     /* Newest entry (enqueue here) */
    size_t count;
    size_t dropped;             /* Entries dropped due to full buffer */
    bool syslog_ready;
    char ident[64];
} log_state = {0};

/* Initialize logging */
int log_init(const char *ident) {
    strncpy(log_state.ident, ident, sizeof(log_state.ident) - 1);
    log_state.syslog_ready = false;
    log_state.count = 0;
    log_state.dropped = 0;
    log_state.head = NULL;
    log_state.tail = NULL;

    /* Try to open syslog - might not be ready yet */
    openlog(log_state.ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* Test if syslog is actually working */
    /* If /dev/log doesn't exist, syslog calls will just fail silently */

    return 0;
}

/* Close logging */
void log_close(void) {
    /* Free any remaining buffered entries */
    struct log_entry *entry = log_state.head;
    while (entry) {
        struct log_entry *next = entry->next;
        free(entry);
        entry = next;
    }

    closelog();
    log_state.head = NULL;
    log_state.tail = NULL;
    log_state.count = 0;
}

/* Add entry to buffer */
static void buffer_log(int priority, const char *unit, const char *message) {
    /* Drop if buffer is full */
    if (log_state.count >= MAX_BUFFER_ENTRIES) {
        /* Drop oldest entry */
        struct log_entry *old = log_state.head;
        if (old) {
            log_state.head = old->next;
            free(old);
            log_state.count--;
            log_state.dropped++;
        }
    }

    /* Allocate new entry */
    struct log_entry *entry = malloc(sizeof(struct log_entry));
    if (!entry) {
        log_state.dropped++;
        return;
    }

    /* Fill in entry */
    clock_gettime(CLOCK_BOOTTIME, &entry->boot_time);
    entry->priority = priority;
    strncpy(entry->unit, unit ? unit : "", sizeof(entry->unit) - 1);
    entry->unit[sizeof(entry->unit) - 1] = '\0';
    strncpy(entry->message, message, sizeof(entry->message) - 1);
    entry->message[sizeof(entry->message) - 1] = '\0';
    entry->next = NULL;

    /* Add to tail of queue */
    if (log_state.tail) {
        log_state.tail->next = entry;
    } else {
        log_state.head = entry;
    }
    log_state.tail = entry;
    log_state.count++;
}

/* Flush buffered logs to syslog */
static void flush_buffer(void) {
    if (!log_state.syslog_ready || !log_state.head) {
        return;
    }

    /* Get current times for offset calculation */
    struct timespec now_real, now_boot;
    clock_gettime(CLOCK_REALTIME, &now_real);
    clock_gettime(CLOCK_BOOTTIME, &now_boot);

    /* Calculate boot time to real time offset */
    int64_t offset_sec = now_real.tv_sec - now_boot.tv_sec;

    /* Flush all buffered entries */
    struct log_entry *entry = log_state.head;
    while (entry) {
        /* Reconstruct real timestamp */
        time_t log_real_time = entry->boot_time.tv_sec + offset_sec;

        /* Format message with boot time annotation */
        char full_msg[MAX_MESSAGE_LEN + 128];
        if (entry->unit[0]) {
            snprintf(full_msg, sizeof(full_msg),
                     "[%s] [buffered from boot+%ld.%03lds] %s",
                     entry->unit,
                     entry->boot_time.tv_sec,
                     entry->boot_time.tv_nsec / 1000000,
                     entry->message);
        } else {
            snprintf(full_msg, sizeof(full_msg),
                     "[buffered from boot+%ld.%03lds] %s",
                     entry->boot_time.tv_sec,
                     entry->boot_time.tv_nsec / 1000000,
                     entry->message);
        }

        /* Send to syslog */
        syslog(entry->priority, "%s", full_msg);

        /* Next entry */
        struct log_entry *next = entry->next;
        free(entry);
        entry = next;
    }

    /* Clear buffer */
    log_state.head = NULL;
    log_state.tail = NULL;

    /* Log dropped count if any */
    if (log_state.dropped > 0) {
        syslog(LOG_WARNING, "Dropped %zu log entries during early boot (buffer full)",
               log_state.dropped);
    }

    log_state.count = 0;
}

/* Notify that syslog is ready */
void log_syslog_ready(void) {
    if (log_state.syslog_ready) {
        return; /* Already ready */
    }

    log_state.syslog_ready = true;
    flush_buffer();
}

/* Check if syslog service has started */
void log_check_syslog(void) {
    if (log_state.syslog_ready) {
        return; /* Already ready */
    }

    /* Test if /dev/log exists and is accessible */
    /* This provides syslog detection in standalone mode or when
     * supervisor doesn't have explicit Provides=syslog knowledge */
    if (access("/dev/log", W_OK) == 0) {
        log_syslog_ready();
    }
}

/* Log a message */
void log_msg(int priority, const char *unit, const char *fmt, ...) {
    char message[MAX_MESSAGE_LEN];
    va_list ap;

    /* Format message */
    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);

    if (log_state.syslog_ready) {
        /* Direct to syslog */
        if (unit && unit[0]) {
            syslog(priority, "[%s] %s", unit, message);
        } else {
            syslog(priority, "%s", message);
        }
    } else {
        /* Buffer for later */
        buffer_log(priority, unit, message);

        /* Also print to stderr for early boot visibility */
        fprintf(stderr, "%s: [%s] %s\n",
                log_state.ident,
                unit ? unit : "system",
                message);
    }
}

/* Get buffer statistics */
void log_get_stats(size_t *buffered, size_t *dropped, bool *syslog_ready) {
    if (buffered) *buffered = log_state.count;
    if (dropped) *dropped = log_state.dropped;
    if (syslog_ready) *syslog_ready = log_state.syslog_ready;
}
