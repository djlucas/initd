/* test-ipc.c - IPC protocol tests
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
#include "../src/common/ipc.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_request_serialization(void) {
    TEST("request serialization");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create test request */
    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);
    strncpy(req.exec_path, "/bin/test", sizeof(req.exec_path) - 1);
    req.run_uid = 1000;
    req.run_gid = 1000;

    /* Send */
    assert(send_request(fds[0], &req) == 0);

    /* Receive */
    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == REQ_START_SERVICE);
    assert(strcmp(recv_req.unit_name, "test.service") == 0);
    assert(strcmp(recv_req.exec_path, "/bin/test") == 0);
    assert(recv_req.run_uid == 1000);
    assert(recv_req.run_gid == 1000);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_response_serialization(void) {
    TEST("response serialization");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create test response */
    struct priv_response resp = {0};
    resp.type = RESP_SERVICE_STARTED;
    resp.service_pid = 12345;

    /* Send */
    assert(send_response(fds[0], &resp) == 0);

    /* Receive */
    struct priv_response recv_resp = {0};
    assert(recv_response(fds[1], &recv_resp) == 0);

    /* Verify */
    assert(recv_resp.type == RESP_SERVICE_STARTED);
    assert(recv_resp.service_pid == 12345);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_stop_service_request(void) {
    TEST("stop service request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_STOP_SERVICE;
    req.service_pid = 999;
    strncpy(req.unit_name, "service.service", sizeof(req.unit_name) - 1);

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == REQ_STOP_SERVICE);
    assert(recv_req.service_pid == 999);
    assert(strcmp(recv_req.unit_name, "service.service") == 0);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_error_response(void) {
    TEST("error response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_response resp = {0};
    resp.type = RESP_ERROR;
    resp.error_code = 42;
    strncpy(resp.error_msg, "Test error", sizeof(resp.error_msg) - 1);

    assert(send_response(fds[0], &resp) == 0);

    struct priv_response recv_resp = {0};
    assert(recv_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == RESP_ERROR);
    assert(recv_resp.error_code == 42);
    assert(strcmp(recv_resp.error_msg, "Test error") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_service_exited_response(void) {
    TEST("service exited notification");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_response resp = {0};
    resp.type = RESP_SERVICE_EXITED;
    resp.service_pid = 5555;
    resp.exit_status = 0;

    assert(send_response(fds[0], &resp) == 0);

    struct priv_response recv_resp = {0};
    assert(recv_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == RESP_SERVICE_EXITED);
    assert(recv_resp.service_pid == 5555);
    assert(recv_resp.exit_status == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_shutdown_complete_request(void) {
    TEST("shutdown complete request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_SHUTDOWN_COMPLETE;

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == REQ_SHUTDOWN_COMPLETE);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_exec_args_serialization(void) {
    TEST("exec_args serialization");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create test request with exec_args */
    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);
    strncpy(req.exec_path, "/bin/test", sizeof(req.exec_path) - 1);
    req.run_uid = 1000;
    req.run_gid = 1000;

    /* Allocate exec_args */
    char *args[] = {"/bin/test", "-arg1", "--arg2=value", NULL};
    req.exec_args = args;

    /* Send */
    assert(send_request(fds[0], &req) == 0);

    /* Receive */
    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == REQ_START_SERVICE);
    assert(strcmp(recv_req.unit_name, "test.service") == 0);
    assert(strcmp(recv_req.exec_path, "/bin/test") == 0);
    assert(recv_req.exec_args != NULL);
    assert(strcmp(recv_req.exec_args[0], "/bin/test") == 0);
    assert(strcmp(recv_req.exec_args[1], "-arg1") == 0);
    assert(strcmp(recv_req.exec_args[2], "--arg2=value") == 0);
    assert(recv_req.exec_args[3] == NULL);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_empty_exec_args(void) {
    TEST("empty exec_args");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create test request with NULL exec_args */
    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);
    req.exec_args = NULL;

    /* Send */
    assert(send_request(fds[0], &req) == 0);

    /* Receive */
    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == REQ_START_SERVICE);
    assert(recv_req.exec_args == NULL);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

int main(void) {
    printf("=== IPC Protocol Tests ===\n\n");

    test_request_serialization();
    test_response_serialization();
    test_stop_service_request();
    test_error_response();
    test_service_exited_response();
    test_shutdown_complete_request();
    test_exec_args_serialization();
    test_empty_exec_args();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
