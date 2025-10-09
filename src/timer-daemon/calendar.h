/* calendar.h - Calendar expression parser
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef CALENDAR_H
#define CALENDAR_H

#include <time.h>
#include <stdbool.h>

/* Find next run time for calendar expression after given time */
time_t calendar_next_run(const char *expr, time_t after);

/* Validate calendar expression */
bool calendar_validate(const char *expr);

#endif /* CALENDAR_H */
