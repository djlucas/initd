/* calendar.c - systemd-style calendar expression parser
 *
 * Parses calendar expressions like:
 * - "daily", "weekly", "monthly", "yearly"
 * - "Mon *-*-* 00:00:00"
 * - "*-*-* 02:00:00"
 * - "Mon,Fri *-*-1..7 18:00:00"
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include "calendar.h"

/* Calendar component - represents a parsed field */
struct calendar_component {
    int *values;        /* Array of allowed values */
    int count;          /* Number of values */
    bool wildcard;      /* True if '*' */
};

/* Parsed calendar expression */
struct calendar_spec {
    struct calendar_component weekday;   /* 0-6 (Sun-Sat) or 1-7 (Mon-Sun) */
    struct calendar_component year;      /* 1970-2099 */
    struct calendar_component month;     /* 1-12 */
    struct calendar_component day;       /* 1-31 */
    struct calendar_component hour;      /* 0-23 */
    struct calendar_component minute;    /* 0-59 */
    struct calendar_component second;    /* 0-59 */
};

/* Day of week names */
static const char *weekday_names[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

/* Month names */
static const char *month_names[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* Free calendar component */
static void free_component(struct calendar_component *comp) {
    free(comp->values);
    comp->values = NULL;
    comp->count = 0;
}

/* Free calendar spec */
static void free_calendar_spec(struct calendar_spec *spec) {
    if (!spec) return;
    free_component(&spec->weekday);
    free_component(&spec->year);
    free_component(&spec->month);
    free_component(&spec->day);
    free_component(&spec->hour);
    free_component(&spec->minute);
    free_component(&spec->second);
    free(spec);
}

/* Parse weekday name to number (0=Sun, 6=Sat) */
static int parse_weekday_name(const char *name) {
    for (int i = 0; i < 7; i++) {
        if (strncasecmp(name, weekday_names[i], 3) == 0) {
            return i;
        }
    }
    return -1;
}

/* Parse month name to number (1-12) */
static int parse_month_name(const char *name) {
    for (int i = 0; i < 12; i++) {
        if (strncasecmp(name, month_names[i], 3) == 0) {
            return i + 1;
        }
    }
    return -1;
}

/* Add value to component */
static int add_value(struct calendar_component *comp, int value) {
    int *new_values = realloc(comp->values, (comp->count + 1) * sizeof(int));
    if (!new_values) return -1;

    comp->values = new_values;
    comp->values[comp->count++] = value;
    return 0;
}

/* Parse integer with bounds checking */
static bool parse_bounded_int(const char *str, int min, int max, char **endptr_out, int *value_out) {
    if (!str || !value_out) {
        return false;
    }

    errno = 0;
    char *endptr = NULL;
    long value = strtol(str, &endptr, 10);

    if (endptr == str) {
        return false;  /* No digits consumed */
    }
    if (errno == ERANGE || value < min || value > max) {
        return false;
    }

    if (endptr_out) {
        *endptr_out = endptr;
    }
    *value_out = (int)value;
    return true;
}

/* Parse range (e.g., "1..7", "10-15") */
static int parse_range(struct calendar_component *comp, const char *str, int min, int max) {
    if (!str || !comp) {
        return -1;
    }

    char *cursor = NULL;
    int start = 0;

    if (!parse_bounded_int(str, min, max, &cursor, &start)) {
        return -1;
    }

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }

    if (*cursor == '\0') {
        return add_value(comp, start);
    }

    char delimiter = *cursor;
    if (delimiter != '.' && delimiter != '-') {
        return -1;
    }

    if (delimiter == '.') {
        if (cursor[1] != '.') {
            return -1;
        }
        cursor += 2;
    } else {
        cursor++;
    }

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }

    int end = 0;
    if (!parse_bounded_int(cursor, min, max, &cursor, &end)) {
        return -1;
    }

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }

    if (*cursor != '\0') {
        return -1;  /* Trailing garbage */
    }

    if (end < start) {
        return -1;
    }

    for (int value = start; value <= end; value++) {
        if (add_value(comp, value) < 0) {
            return -1;
        }
    }

    return 0;
}

/* Parse component field (handles *, ranges, lists) */
static int parse_component(struct calendar_component *comp, const char *str,
                           int min, int max, bool allow_names, const char **names) {
    if (strcmp(str, "*") == 0) {
        comp->wildcard = true;
        return 0;
    }

    comp->wildcard = false;
    comp->values = NULL;
    comp->count = 0;

    char *copy = strdup(str);
    if (!copy) return -1;

    /* Split by commas for lists */
    char *token = strtok(copy, ",");
    while (token) {
        /* Trim whitespace */
        while (isspace(*token)) token++;

        /* Check for name */
        if (allow_names && names && isalpha(*token)) {
            int value = -1;
            if (names == weekday_names) {
                value = parse_weekday_name(token);
            } else if (names == month_names) {
                value = parse_month_name(token);
            }

            if (value < 0) {
                free(copy);
                return -1;
            }

            if (add_value(comp, value) < 0) {
                free(copy);
                return -1;
            }
        } else {
            /* Parse numeric range or value */
            if (parse_range(comp, token, min, max) < 0) {
                free(copy);
                return -1;
            }
        }

        token = strtok(NULL, ",");
    }

    free(copy);
    return 0;
}

/* Parse full calendar expression */
static struct calendar_spec *parse_calendar_expression(const char *expr) {
    struct calendar_spec *spec = calloc(1, sizeof(struct calendar_spec));
    if (!spec) return NULL;

    /* Allocate buffer large enough for shortcuts or original expression */
    size_t len = strlen(expr);
    size_t buflen = (len > 32) ? len + 1 : 32;  /* At least 32 bytes for shortcuts */
    char *copy = malloc(buflen);
    if (!copy) {
        free(spec);
        return NULL;
    }

    /* Handle shortcuts */
    if (strcmp(expr, "minutely") == 0) {
        strcpy(copy, "* *-*-* *:*:00");
    } else if (strcmp(expr, "hourly") == 0) {
        strcpy(copy, "* *-*-* *:00:00");
    } else if (strcmp(expr, "daily") == 0) {
        strcpy(copy, "* *-*-* 00:00:00");
    } else if (strcmp(expr, "weekly") == 0) {
        strcpy(copy, "Mon *-*-* 00:00:00");
    } else if (strcmp(expr, "monthly") == 0) {
        strcpy(copy, "* *-*-01 00:00:00");
    } else if (strcmp(expr, "yearly") == 0 || strcmp(expr, "annually") == 0) {
        strcpy(copy, "* *-01-01 00:00:00");
    } else {
        strcpy(copy, expr);
    }

    /* Parse format: [WEEKDAY] YEAR-MONTH-DAY HOUR:MINUTE:SECOND */
    char weekday[64] = "*";
    char date[64] = "*-*-*";
    char time[64] = "00:00:00";

    int n = sscanf(copy, "%63s %63s %63s", weekday, date, time);

    if (n == 2) {
        /* No weekday specified - shift values */
        memmove(time, date, sizeof(time));
        memmove(date, weekday, sizeof(date));
        snprintf(weekday, sizeof(weekday), "*");
    } else if (n != 3) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    /* Parse weekday */
    if (parse_component(&spec->weekday, weekday, 0, 6, true, weekday_names) < 0) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    /* Parse date: YEAR-MONTH-DAY */
    char year[32], month[32], day[32];
    if (sscanf(date, "%31[^-]-%31[^-]-%31s", year, month, day) != 3) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    if (parse_component(&spec->year, year, 1970, 2099, false, NULL) < 0 ||
        parse_component(&spec->month, month, 1, 12, true, month_names) < 0 ||
        parse_component(&spec->day, day, 1, 31, false, NULL) < 0) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    /* Parse time: HOUR:MINUTE:SECOND */
    char hour[32], minute[32], second[32] = "00";
    int time_parts = sscanf(time, "%31[^:]:%31[^:]:%31s", hour, minute, second);

    if (time_parts < 2) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    if (parse_component(&spec->hour, hour, 0, 23, false, NULL) < 0 ||
        parse_component(&spec->minute, minute, 0, 59, false, NULL) < 0 ||
        parse_component(&spec->second, second, 0, 59, false, NULL) < 0) {
        free(copy);
        free_calendar_spec(spec);
        return NULL;
    }

    free(copy);
    return spec;
}

/* Check if value matches component */
static bool matches_component(struct calendar_component *comp, int value) {
    if (comp->wildcard) return true;

    for (int i = 0; i < comp->count; i++) {
        if (comp->values[i] == value) return true;
    }

    return false;
}

/* Check if time matches calendar spec */
static bool matches_calendar(struct calendar_spec *spec, struct tm *tm) {
    if (!matches_component(&spec->weekday, tm->tm_wday)) return false;
    if (!matches_component(&spec->year, tm->tm_year + 1900)) return false;
    if (!matches_component(&spec->month, tm->tm_mon + 1)) return false;
    if (!matches_component(&spec->day, tm->tm_mday)) return false;
    if (!matches_component(&spec->hour, tm->tm_hour)) return false;
    if (!matches_component(&spec->minute, tm->tm_min)) return false;
    if (!matches_component(&spec->second, tm->tm_sec)) return false;

    return true;
}

/* Get next valid value for a component */
static int next_value_in_component(struct calendar_component *comp, int current, int min, int max) {
    if (comp->wildcard) {
        /* Wildcard: next value is current + 1, wrapping */
        int next = current + 1;
        if (next > max) next = min;
        return next;
    }

    /* Find smallest value >= current */
    int best = -1;
    for (int i = 0; i < comp->count; i++) {
        if (comp->values[i] >= current) {
            if (best == -1 || comp->values[i] < best) {
                best = comp->values[i];
            }
        }
    }

    if (best != -1) return best;

    /* No value >= current, wrap to smallest value */
    best = max + 1;
    for (int i = 0; i < comp->count; i++) {
        if (comp->values[i] < best) {
            best = comp->values[i];
        }
    }

    return best;
}

/* Find next run time for calendar expression */
time_t calendar_next_run(const char *expr, time_t after) {
    struct calendar_spec *spec = parse_calendar_expression(expr);
    if (!spec) return 0;

    struct tm tm;
    localtime_r(&after, &tm);

    /* Start from next minute (ignore seconds for simplicity) */
    tm.tm_min++;
    tm.tm_sec = 0;
    time_t check = mktime(&tm);

    /* Maximum iterations: try for up to 2 years */
    int max_iterations = 366 * 2;
    int iterations = 0;

    while (iterations++ < max_iterations) {
        localtime_r(&check, &tm);

        /* Check if current time matches all components */
        if (matches_calendar(spec, &tm)) {
            free_calendar_spec(spec);
            return check;
        }

        /* Increment strategically based on what doesn't match */

        /* Check year */
        if (!matches_component(&spec->year, tm.tm_year + 1900)) {
            int next_year = next_value_in_component(&spec->year, tm.tm_year + 1900, 1970, 2099);
            if (next_year > tm.tm_year + 1900) {
                tm.tm_year = next_year - 1900;
                tm.tm_mon = 0;
                tm.tm_mday = 1;
                tm.tm_hour = 0;
                tm.tm_min = 0;
                check = mktime(&tm);
                continue;
            } else {
                /* Wrapped around - no match in range */
                break;
            }
        }

        /* Check month */
        if (!matches_component(&spec->month, tm.tm_mon + 1)) {
            int next_month = next_value_in_component(&spec->month, tm.tm_mon + 1, 1, 12);
            if (next_month > tm.tm_mon + 1) {
                tm.tm_mon = next_month - 1;
            } else {
                /* Wrapped to next year */
                tm.tm_year++;
                tm.tm_mon = next_month - 1;
            }
            tm.tm_mday = 1;
            tm.tm_hour = 0;
            tm.tm_min = 0;
            check = mktime(&tm);
            continue;
        }

        /* Check day */
        if (!matches_component(&spec->day, tm.tm_mday)) {
            int next_day = next_value_in_component(&spec->day, tm.tm_mday, 1, 31);
            if (next_day > tm.tm_mday && next_day <= 31) {
                tm.tm_mday = next_day;
            } else {
                /* Wrapped to next month */
                tm.tm_mon++;
                tm.tm_mday = next_day;
            }
            tm.tm_hour = 0;
            tm.tm_min = 0;
            check = mktime(&tm);
            continue;
        }

        /* Check weekday */
        if (!matches_component(&spec->weekday, tm.tm_wday)) {
            /* Increment by day until weekday matches */
            check += 86400;
            continue;
        }

        /* Check hour */
        if (!matches_component(&spec->hour, tm.tm_hour)) {
            int next_hour = next_value_in_component(&spec->hour, tm.tm_hour, 0, 23);
            if (next_hour > tm.tm_hour) {
                tm.tm_hour = next_hour;
            } else {
                /* Wrapped to next day */
                tm.tm_mday++;
                tm.tm_hour = next_hour;
            }
            tm.tm_min = 0;
            check = mktime(&tm);
            continue;
        }

        /* Check minute */
        if (!matches_component(&spec->minute, tm.tm_min)) {
            int next_min = next_value_in_component(&spec->minute, tm.tm_min, 0, 59);
            if (next_min > tm.tm_min) {
                tm.tm_min = next_min;
            } else {
                /* Wrapped to next hour */
                tm.tm_hour++;
                tm.tm_min = next_min;
            }
            check = mktime(&tm);
            continue;
        }

        /* All components should match now - increment by 1 minute */
        check += 60;
    }

    free_calendar_spec(spec);
    return 0;  /* No match found */
}

/* Validate calendar expression */
bool calendar_validate(const char *expr) {
    struct calendar_spec *spec = parse_calendar_expression(expr);
    if (!spec) return false;

    free_calendar_spec(spec);
    return true;
}
