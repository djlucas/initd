/* test-timer-ipc.c - Timer IPC protocol tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../src/common/timer-ipc.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_enable_request(void) {
    TEST("enable unit request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create test request */
    struct timer_request req = {0};
    req.type = TIMER_REQ_ENABLE_UNIT;
    strncpy(req.unit_name, "test.timer", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/lib/initd/system/test.timer", sizeof(req.unit_path) - 1);

    /* Send */
    assert(send_timer_request(fds[0], &req) == 0);

    /* Receive */
    struct timer_request recv_req = {0};
    assert(recv_timer_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == TIMER_REQ_ENABLE_UNIT);
    assert(strcmp(recv_req.unit_name, "test.timer") == 0);
    assert(strcmp(recv_req.unit_path, "/lib/initd/system/test.timer") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_disable_request(void) {
    TEST("disable unit request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_request req = {0};
    req.type = TIMER_REQ_DISABLE_UNIT;
    strncpy(req.unit_name, "backup.timer", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/etc/initd/system/backup.timer", sizeof(req.unit_path) - 1);

    assert(send_timer_request(fds[0], &req) == 0);

    struct timer_request recv_req = {0};
    assert(recv_timer_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == TIMER_REQ_DISABLE_UNIT);
    assert(strcmp(recv_req.unit_name, "backup.timer") == 0);
    assert(strcmp(recv_req.unit_path, "/etc/initd/system/backup.timer") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_convert_request(void) {
    TEST("convert unit request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_request req = {0};
    req.type = TIMER_REQ_CONVERT_UNIT;
    strncpy(req.unit_name, "systemd.timer", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/lib/systemd/system/systemd.timer", sizeof(req.unit_path) - 1);

    assert(send_timer_request(fds[0], &req) == 0);

    struct timer_request recv_req = {0};
    assert(recv_timer_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == TIMER_REQ_CONVERT_UNIT);
    assert(strcmp(recv_req.unit_name, "systemd.timer") == 0);
    assert(strcmp(recv_req.unit_path, "/lib/systemd/system/systemd.timer") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_ok_response(void) {
    TEST("OK response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_response resp = {0};
    resp.type = TIMER_RESP_OK;
    resp.error_code = 0;

    assert(send_timer_response(fds[0], &resp) == 0);

    struct timer_response recv_resp = {0};
    assert(recv_timer_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == TIMER_RESP_OK);
    assert(recv_resp.error_code == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_error_response(void) {
    TEST("error response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_response resp = {0};
    resp.type = TIMER_RESP_ERROR;
    resp.error_code = 13; /* EACCES */
    strncpy(resp.error_msg, "Permission denied", sizeof(resp.error_msg) - 1);

    assert(send_timer_response(fds[0], &resp) == 0);

    struct timer_response recv_resp = {0};
    assert(recv_timer_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == TIMER_RESP_ERROR);
    assert(recv_resp.error_code == 13);
    assert(strcmp(recv_resp.error_msg, "Permission denied") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_converted_response(void) {
    TEST("unit converted response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_response resp = {0};
    resp.type = TIMER_RESP_OK;
    strncpy(resp.converted_path, "/lib/initd/system/converted.timer", sizeof(resp.converted_path) - 1);

    assert(send_timer_response(fds[0], &resp) == 0);

    struct timer_response recv_resp = {0};
    assert(recv_timer_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == TIMER_RESP_OK);
    assert(strcmp(recv_resp.converted_path, "/lib/initd/system/converted.timer") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_long_paths(void) {
    TEST("long path handling");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct timer_request req = {0};
    req.type = TIMER_REQ_ENABLE_UNIT;

    /* Create a path that's near the buffer limit */
    char long_path[1024];
    memset(long_path, 'a', sizeof(long_path) - 10);
    strcpy(long_path + sizeof(long_path) - 10, ".timer");

    strncpy(req.unit_name, "long.timer", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, long_path, sizeof(req.unit_path) - 1);

    assert(send_timer_request(fds[0], &req) == 0);

    struct timer_request recv_req = {0};
    assert(recv_timer_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == TIMER_REQ_ENABLE_UNIT);
    /* Verify it was truncated correctly (null-terminated) */
    assert(strlen(recv_req.unit_path) < sizeof(recv_req.unit_path));

    close(fds[0]);
    close(fds[1]);
    PASS();
}

int main(void) {
    printf("=== Timer IPC Protocol Tests ===\n\n");

    test_enable_request();
    test_disable_request();
    test_convert_request();
    test_ok_response();
    test_error_response();
    test_converted_response();
    test_long_paths();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
