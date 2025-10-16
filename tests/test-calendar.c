/* test-calendar.c - Calendar expression parser tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include "../src/timer-daemon/calendar.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_validate_shortcuts(void) {
    TEST("calendar shortcuts");
    assert(calendar_validate("minutely") == true);
    assert(calendar_validate("hourly") == true);
    assert(calendar_validate("daily") == true);
    assert(calendar_validate("weekly") == true);
    assert(calendar_validate("monthly") == true);
    assert(calendar_validate("yearly") == true);
    assert(calendar_validate("annually") == true);
    PASS();
}

void test_validate_full_format(void) {
    TEST("full calendar format");
    assert(calendar_validate("Mon *-*-* 00:00:00") == true);
    assert(calendar_validate("* *-*-* 02:00:00") == true);
    assert(calendar_validate("Mon,Fri *-*-1..7 18:00:00") == true);
    PASS();
}

void test_validate_date_time(void) {
    TEST("date-time format");
    assert(calendar_validate("*-*-* 00:00:00") == true);
    assert(calendar_validate("2025-01-01 12:30:00") == true);
    assert(calendar_validate("*-12-25 00:00:00") == true);
    PASS();
}

void test_validate_invalid(void) {
    TEST("invalid expressions");
    assert(calendar_validate("invalid") == false);
    assert(calendar_validate("99:99:99") == false);
    assert(calendar_validate("") == false);
    PASS();
}

void test_validate_overflow(void) {
    TEST("overflow and invalid ranges");
    assert(calendar_validate("* *-*-9223372036854775808 00:00:00") == false);
    assert(calendar_validate("* *-*-1..9223372036854775807 00:00:00") == false);
    assert(calendar_validate("* *-*-7..3 00:00:00") == false);
    PASS();
}

void test_next_run_daily(void) {
    TEST("next run for daily");

    /* Create a known time: 2025-01-01 12:00:00 */
    struct tm tm = {0};
    tm.tm_year = 2025 - 1900;
    tm.tm_mon = 0;
    tm.tm_mday = 1;
    tm.tm_hour = 12;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    time_t now = mktime(&tm);

    /* Next daily should be 2025-01-02 00:00:00 */
    time_t next = calendar_next_run("daily", now);
    assert(next > now);

    struct tm *next_tm = localtime(&next);
    assert(next_tm->tm_mday == 2);
    assert(next_tm->tm_hour == 0);
    assert(next_tm->tm_min == 0);

    PASS();
}

void test_next_run_hourly(void) {
    TEST("next run for hourly");

    struct tm tm = {0};
    tm.tm_year = 2025 - 1900;
    tm.tm_mon = 0;
    tm.tm_mday = 1;
    tm.tm_hour = 12;
    tm.tm_min = 30;
    tm.tm_sec = 0;
    time_t now = mktime(&tm);

    /* Next hourly should be 13:00:00 */
    time_t next = calendar_next_run("hourly", now);
    assert(next > now);

    struct tm *next_tm = localtime(&next);
    assert(next_tm->tm_hour == 13);
    assert(next_tm->tm_min == 0);

    PASS();
}

void test_next_run_specific_time(void) {
    TEST("next run for specific time");

    struct tm tm = {0};
    tm.tm_year = 2025 - 1900;
    tm.tm_mon = 0;
    tm.tm_mday = 1;
    tm.tm_hour = 10;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    time_t now = mktime(&tm);

    /* Next 14:00:00 should be today */
    time_t next = calendar_next_run("*-*-* 14:00:00", now);
    assert(next > now);

    struct tm *next_tm = localtime(&next);
    assert(next_tm->tm_mday == 1);
    assert(next_tm->tm_hour == 14);

    PASS();
}

int main(void) {
    printf("=== Calendar Expression Parser Tests ===\n\n");

    test_validate_shortcuts();
    test_validate_full_format();
    test_validate_date_time();
    test_validate_invalid();
    test_validate_overflow();
    test_next_run_daily();
    test_next_run_hourly();
    test_next_run_specific_time();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
