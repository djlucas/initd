/* test-timer-notify.c - Timer inactivity notification tests
 *
 * Copyright (c) 2025
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include "../src/common/unit.h"

/* Test helpers exposed under UNIT_TEST */
int timer_daemon_test_add_instance(struct unit_file *unit,
                                   time_t last_run,
                                   time_t last_inactive,
                                   bool enabled);
void timer_daemon_test_reset(void);
void timer_daemon_test_set_time_base(time_t boot, time_t start);
int timer_daemon_test_notify_inactive(const char *service_name, time_t now);
time_t timer_daemon_test_get_next_run(const char *timer_name);
time_t timer_daemon_test_get_last_inactive(const char *timer_name);

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

static struct unit_file *make_timer_unit(const char *name, int inactive_sec) {
    struct unit_file *unit = calloc(1, sizeof(struct unit_file));
    assert(unit);

    strncpy(unit->name, name, sizeof(unit->name) - 1);
    unit->type = UNIT_TIMER;
    unit->config.timer.on_unit_inactive_sec = inactive_sec;
    unit->config.timer.on_unit_active_sec = 0;
    unit->config.timer.on_startup_sec = 0;
    unit->config.timer.on_boot_sec = 0;
    unit->config.timer.randomized_delay_sec = 0;

    return unit;
}

static void test_notify_updates_next_run(void) {
    TEST("notify reschedules timer");

    timer_daemon_test_reset();
    timer_daemon_test_set_time_base(0, 0);

    struct unit_file *unit = make_timer_unit("example.timer", 30);
    assert(timer_daemon_test_add_instance(unit, 0, 0, true) == 0);

    time_t now = time(NULL);
    int updated = timer_daemon_test_notify_inactive("example.service", now);
    assert(updated == 1);

    time_t next = timer_daemon_test_get_next_run("example.timer");
    time_t last_inactive = timer_daemon_test_get_last_inactive("example.timer");

    assert(last_inactive == now);
    assert(next - last_inactive == 30);

    timer_daemon_test_reset();
    free(unit);
    PASS();
}

static void test_notify_ignores_unrelated_services(void) {
    TEST("notify ignores other services");

    timer_daemon_test_reset();
    timer_daemon_test_set_time_base(0, 0);

    struct unit_file *unit = make_timer_unit("other.timer", 20);
    assert(timer_daemon_test_add_instance(unit, 0, 50, true) == 0);

    time_t before_next = timer_daemon_test_get_next_run("other.timer");
    time_t before_inactive = timer_daemon_test_get_last_inactive("other.timer");

    int updated = timer_daemon_test_notify_inactive("unmatched.service", time(NULL));
    assert(updated == 0);

    time_t after_next = timer_daemon_test_get_next_run("other.timer");
    time_t after_inactive = timer_daemon_test_get_last_inactive("other.timer");

    assert(before_next == after_next);
    assert(before_inactive == after_inactive);

    timer_daemon_test_reset();
    free(unit);
    PASS();
}

int main(void) {
    test_notify_updates_next_run();
    test_notify_ignores_unrelated_services();
    return 0;
}
