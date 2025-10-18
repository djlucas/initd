/* test-supervisor-socket.c - Supervisor/socket activator IPC tests
 *
 * Copyright (c) 2025
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../src/common/control.h"
#include "../src/common/unit.h"

/* UT helpers from supervisor worker */
void supervisor_test_set_unit_context(struct unit_file **list, int count);
void supervisor_test_handle_control_fd(int fd);
void supervisor_test_handle_status_fd(int fd);

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

static void adopt_service(pid_t adopt_pid, enum unit_state expected_state) {
    struct unit_file unit = {0};
    strncpy(unit.name, "example.service", sizeof(unit.name) - 1);
    unit.type = UNIT_SERVICE;
    unit.state = STATE_INACTIVE;
    unit.pid = 0;

    struct unit_file *units[] = { &unit };
    supervisor_test_set_unit_context(units, 1);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_SOCKET_ADOPT;
    strncpy(req.unit_name, unit.name, sizeof(req.unit_name) - 1);
    req.aux_pid = (uint32_t)adopt_pid;

    assert(send_control_request(sv[0], &req) == 0);

    supervisor_test_handle_control_fd(sv[1]);

    struct control_response resp = {0};
    assert(recv_control_response(sv[0], &resp) == 0);
    assert(resp.code == RESP_SUCCESS);

    if (adopt_pid > 0) {
        assert(unit.pid == adopt_pid);
    } else {
        assert(unit.pid == 0);
    }
    assert(unit.state == expected_state);

    close(sv[0]);
    close(sv[1]);
}

static void test_status_socket_allows_read_only(void) {
    TEST("status socket allows read-only commands");

    struct unit_file unit = {0};
    strncpy(unit.name, "status.service", sizeof(unit.name) - 1);
    unit.type = UNIT_SERVICE;
    unit.state = STATE_ACTIVE;
    unit.pid = 4321;

    struct unit_file *units[] = { &unit };
    supervisor_test_set_unit_context(units, 1);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_STATUS;
    strncpy(req.unit_name, unit.name, sizeof(req.unit_name) - 1);

    assert(send_control_request(sv[0], &req) == 0);

    supervisor_test_handle_status_fd(sv[1]);

    struct control_response resp = {0};
    assert(recv_control_response(sv[0], &resp) == 0);
    assert(resp.code == RESP_SUCCESS);
    assert(resp.pid == unit.pid);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

static void test_status_socket_blocks_mutating(void) {
    TEST("status socket blocks mutating commands");

    struct unit_file unit = {0};
    strncpy(unit.name, "block.service", sizeof(unit.name) - 1);
    unit.type = UNIT_SERVICE;
    unit.state = STATE_INACTIVE;

    struct unit_file *units[] = { &unit };
    supervisor_test_set_unit_context(units, 1);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_START;
    strncpy(req.unit_name, unit.name, sizeof(req.unit_name) - 1);

    assert(send_control_request(sv[0], &req) == 0);

    supervisor_test_handle_status_fd(sv[1]);

    struct control_response resp = {0};
    assert(recv_control_response(sv[0], &resp) == 0);
    assert(resp.code == RESP_PERMISSION_DENIED);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

int main(void) {
    TEST("socket adopt activates service");
    adopt_service(1234, STATE_ACTIVE);
    PASS();

    TEST("socket adopt clears service");
    adopt_service(0, STATE_INACTIVE);
    PASS();

    test_status_socket_allows_read_only();
    test_status_socket_blocks_mutating();

    return 0;
}
