/* test-control.c - Control protocol tests
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
#include "../src/common/control.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_request_response(void) {
    TEST("request/response serialization");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Send request */
    struct control_request req = {0};
    req.header.length = sizeof(req);
    req.header.command = CMD_START;
    req.header.flags = 0;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);

    assert(send_control_request(sv[0], &req) == 0);

    /* Receive request */
    struct control_request recv_req = {0};
    assert(recv_control_request(sv[1], &recv_req) == 0);

    assert(recv_req.header.command == CMD_START);
    assert(strcmp(recv_req.unit_name, "test.service") == 0);

    /* Send response */
    struct control_response resp = {0};
    resp.header.length = sizeof(resp);
    resp.header.command = CMD_START;
    resp.code = RESP_SUCCESS;
    resp.state = UNIT_STATE_ACTIVE;
    resp.pid = 1234;
    strncpy(resp.message, "Started test.service", sizeof(resp.message) - 1);

    assert(send_control_response(sv[1], &resp) == 0);

    /* Receive response */
    struct control_response recv_resp = {0};
    assert(recv_control_response(sv[0], &recv_resp) == 0);

    assert(recv_resp.code == RESP_SUCCESS);
    assert(recv_resp.state == UNIT_STATE_ACTIVE);
    assert(recv_resp.pid == 1234);
    assert(strcmp(recv_resp.message, "Started test.service") == 0);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_unit_list(void) {
    TEST("unit list serialization");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Create test entries */
    struct unit_list_entry entries[3] = {
        {
            .name = "nginx.service",
            .state = UNIT_STATE_ACTIVE,
            .pid = 100,
            .description = "Nginx web server"
        },
        {
            .name = "sshd.service",
            .state = UNIT_STATE_ACTIVE,
            .pid = 200,
            .description = "SSH daemon"
        },
        {
            .name = "backup.timer",
            .state = UNIT_STATE_INACTIVE,
            .pid = 0,
            .description = "Daily backup"
        }
    };

    /* Send list */
    assert(send_unit_list(sv[0], entries, 3) == 0);

    /* Receive list */
    struct unit_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_unit_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 3);
    assert(strcmp(recv_entries[0].name, "nginx.service") == 0);
    assert(recv_entries[0].state == UNIT_STATE_ACTIVE);
    assert(recv_entries[0].pid == 100);
    assert(strcmp(recv_entries[1].name, "sshd.service") == 0);
    assert(strcmp(recv_entries[2].name, "backup.timer") == 0);

    free(recv_entries);
    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_empty_unit_list(void) {
    TEST("empty unit list");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Send empty list */
    assert(send_unit_list(sv[0], NULL, 0) == 0);

    /* Receive empty list */
    struct unit_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_unit_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 0);
    assert(recv_entries == NULL);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_state_strings(void) {
    TEST("state to string conversion");

    assert(strcmp(state_to_string(UNIT_STATE_INACTIVE), "inactive") == 0);
    assert(strcmp(state_to_string(UNIT_STATE_ACTIVATING), "activating") == 0);
    assert(strcmp(state_to_string(UNIT_STATE_ACTIVE), "active") == 0);
    assert(strcmp(state_to_string(UNIT_STATE_DEACTIVATING), "deactivating") == 0);
    assert(strcmp(state_to_string(UNIT_STATE_FAILED), "failed") == 0);

    PASS();
}

void test_command_strings(void) {
    TEST("command to string conversion");

    assert(strcmp(command_to_string(CMD_START), "start") == 0);
    assert(strcmp(command_to_string(CMD_STOP), "stop") == 0);
    assert(strcmp(command_to_string(CMD_STATUS), "status") == 0);
    assert(strcmp(command_to_string(CMD_ENABLE), "enable") == 0);
    assert(strcmp(command_to_string(CMD_LIST_UNITS), "list-units") == 0);
    assert(strcmp(command_to_string(CMD_LIST_TIMERS), "list-timers") == 0);
    assert(strcmp(command_to_string(CMD_LIST_SOCKETS), "list-sockets") == 0);

    PASS();
}

void test_timer_list(void) {
    TEST("timer list serialization");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Create test timer entries */
    struct timer_list_entry entries[2] = {
        {
            .name = "backup.timer",
            .unit = "backup.service",
            .next_run = 1234567890,
            .last_run = 1234500000,
            .state = UNIT_STATE_ACTIVE,
            .description = "Daily backup timer"
        },
        {
            .name = "update.timer",
            .unit = "update.service",
            .next_run = 1234600000,
            .last_run = 0,
            .state = UNIT_STATE_ACTIVE,
            .description = "System update timer"
        }
    };

    /* Send list */
    assert(send_timer_list(sv[0], entries, 2) == 0);

    /* Receive list */
    struct timer_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_timer_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 2);
    assert(strcmp(recv_entries[0].name, "backup.timer") == 0);
    assert(strcmp(recv_entries[0].unit, "backup.service") == 0);
    assert(recv_entries[0].next_run == 1234567890);
    assert(recv_entries[0].last_run == 1234500000);
    assert(strcmp(recv_entries[1].name, "update.timer") == 0);
    assert(recv_entries[1].last_run == 0);

    free(recv_entries);
    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_socket_list(void) {
    TEST("socket list serialization");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Create test socket entries */
    struct socket_list_entry entries[2] = {
        {
            .name = "sshd.socket",
            .listen = "[::]:22",
            .unit = "sshd.service",
            .state = UNIT_STATE_ACTIVE,
            .service_pid = 0,
            .description = "SSH server socket"
        },
        {
            .name = "docker.socket",
            .listen = "/var/run/docker.sock",
            .unit = "docker.service",
            .state = UNIT_STATE_ACTIVE,
            .service_pid = 1234,
            .description = "Docker API socket"
        }
    };

    /* Send list */
    assert(send_socket_list(sv[0], entries, 2) == 0);

    /* Receive list */
    struct socket_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_socket_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 2);
    assert(strcmp(recv_entries[0].name, "sshd.socket") == 0);
    assert(strcmp(recv_entries[0].listen, "[::]:22") == 0);
    assert(strcmp(recv_entries[0].unit, "sshd.service") == 0);
    assert(recv_entries[0].service_pid == 0);
    assert(strcmp(recv_entries[1].name, "docker.socket") == 0);
    assert(recv_entries[1].service_pid == 1234);

    free(recv_entries);
    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_empty_timer_list(void) {
    TEST("empty timer list");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Send empty list */
    assert(send_timer_list(sv[0], NULL, 0) == 0);

    /* Receive empty list */
    struct timer_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_timer_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 0);
    assert(recv_entries == NULL);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

void test_empty_socket_list(void) {
    TEST("empty socket list");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Send empty list */
    assert(send_socket_list(sv[0], NULL, 0) == 0);

    /* Receive empty list */
    struct socket_list_entry *recv_entries = NULL;
    size_t recv_count = 0;
    assert(recv_socket_list(sv[1], &recv_entries, &recv_count) == 0);

    assert(recv_count == 0);
    assert(recv_entries == NULL);

    close(sv[0]);
    close(sv[1]);
    PASS();
}

int main(void) {
    printf("=== Control Protocol Tests ===\n\n");

    test_request_response();
    test_unit_list();
    test_empty_unit_list();
    test_state_strings();
    test_command_strings();
    test_timer_list();
    test_socket_list();
    test_empty_timer_list();
    test_empty_socket_list();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
