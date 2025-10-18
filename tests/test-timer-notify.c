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
#include <unistd.h>
#include <sys/socket.h>
#include "../src/common/control.h"
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
void timer_daemon_test_handle_control_fd(int fd);
void timer_daemon_test_handle_status_fd(int fd);

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

static void test_status_socket_allows_read_only(void) {
    TEST("timer status socket allows read-only commands");

    timer_daemon_test_reset();
    timer_daemon_test_set_time_base(0, 0);

    struct unit_file *unit = make_timer_unit("status.timer", 0);
    unit->enabled = true;
    assert(timer_daemon_test_add_instance(unit, time(NULL), time(NULL), true) == 0);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_STATUS;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);

    assert(send_control_request(sv[0], &req) == 0);

    timer_daemon_test_handle_status_fd(sv[1]);

    struct control_response resp = {0};
    assert(recv_control_response(sv[0], &resp) == 0);
    assert(resp.code == RESP_SUCCESS);

    close(sv[0]);
    close(sv[1]);
    timer_daemon_test_reset();
    free(unit);
    PASS();
}

static void test_status_socket_blocks_mutating(void) {
    TEST("timer status socket blocks mutating commands");

    timer_daemon_test_reset();
    timer_daemon_test_set_time_base(0, 0);

    struct unit_file *unit = make_timer_unit("block.timer", 0);
    assert(timer_daemon_test_add_instance(unit, time(NULL), time(NULL), true) == 0);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_START;
    strncpy(req.unit_name, unit->name, sizeof(req.unit_name) - 1);

    assert(send_control_request(sv[0], &req) == 0);

    timer_daemon_test_handle_status_fd(sv[1]);

    struct control_response resp = {0};
    assert(recv_control_response(sv[0], &resp) == 0);
    assert(resp.code == RESP_PERMISSION_DENIED);

    close(sv[0]);
    close(sv[1]);
    timer_daemon_test_reset();
    free(unit);
    PASS();
}

int main(void) {
    test_notify_updates_next_run();
    test_notify_ignores_unrelated_services();
    test_status_socket_allows_read_only();
    test_status_socket_blocks_mutating();
    return 0;
}
