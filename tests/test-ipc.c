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
    strncpy(req.unit_path, "/etc/initd/test.service", sizeof(req.unit_path) - 1);
    strncpy(req.exec_path, "/bin/test", sizeof(req.exec_path) - 1);
    /* Note: run_uid/run_gid ignored by master (gets from unit file) but still serialized */

    /* Send */
    assert(send_request(fds[0], &req) == 0);

    /* Receive */
    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == REQ_START_SERVICE);
    assert(strcmp(recv_req.unit_name, "test.service") == 0);
    assert(strcmp(recv_req.unit_path, "/etc/initd/test.service") == 0);
    assert(strcmp(recv_req.exec_path, "/bin/test") == 0);

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
    strncpy(req.unit_path, "/etc/initd/test.service", sizeof(req.unit_path) - 1);
    strncpy(req.exec_path, "/bin/test", sizeof(req.exec_path) - 1);

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
    assert(strcmp(recv_req.unit_path, "/etc/initd/test.service") == 0);
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

void test_invalid_request_type(void) {
    TEST("invalid request type validation");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create request with invalid type */
    struct priv_request req = {0};
    req.type = 999; /* Invalid - exceeds REQ_SHUTDOWN_COMPLETE */
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);

    /* Send should work (sender doesn't validate) */
    assert(send_request(fds[0], &req) == 0);

    /* Receive should FAIL - receiver validates and rejects invalid types */
    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) < 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_invalid_response_type(void) {
    TEST("invalid response type validation");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Create response with invalid type */
    struct priv_response resp = {0};
    resp.type = 888; /* Invalid - exceeds RESP_UNIT_CONVERTED */
    resp.error_code = 0;

    /* Send should work (sender doesn't validate) */
    assert(send_response(fds[0], &resp) == 0);

    /* Receive should FAIL - receiver validates and rejects invalid types */
    struct priv_response recv_resp = {0};
    assert(recv_response(fds[1], &recv_resp) < 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_oversized_unit_name(void) {
    TEST("oversized unit_name");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;

    /* Create oversized unit_name (> 256 chars) */
    char oversized[512];
    memset(oversized, 'x', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';

    /* strncpy will truncate */
    strncpy(req.unit_name, oversized, sizeof(req.unit_name) - 1);
    req.unit_name[sizeof(req.unit_name) - 1] = '\0';

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify it was truncated correctly (null-terminated) */
    assert(strlen(recv_req.unit_name) < sizeof(recv_req.unit_name));
    assert(strlen(recv_req.unit_name) == sizeof(recv_req.unit_name) - 1);

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_oversized_paths(void) {
    TEST("oversized unit_path and exec_path");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);

    /* Create oversized paths (> 1024 chars) */
    char oversized[2048];
    memset(oversized, 'a', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';

    strncpy(req.unit_path, oversized, sizeof(req.unit_path) - 1);
    req.unit_path[sizeof(req.unit_path) - 1] = '\0';
    strncpy(req.exec_path, oversized, sizeof(req.exec_path) - 1);
    req.exec_path[sizeof(req.exec_path) - 1] = '\0';

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify truncation */
    assert(strlen(recv_req.unit_path) < sizeof(recv_req.unit_path));
    assert(strlen(recv_req.exec_path) < sizeof(recv_req.exec_path));

    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_oversized_error_msg(void) {
    TEST("oversized error_msg");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_response resp = {0};
    resp.type = RESP_ERROR;
    resp.error_code = 1;

    /* Create oversized error message (> 256 chars) */
    char oversized[512];
    memset(oversized, 'E', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';

    strncpy(resp.error_msg, oversized, sizeof(resp.error_msg) - 1);
    resp.error_msg[sizeof(resp.error_msg) - 1] = '\0';

    assert(send_response(fds[0], &resp) == 0);

    struct priv_response recv_resp = {0};
    assert(recv_response(fds[1], &recv_resp) == 0);

    /* Verify truncation */
    assert(strlen(recv_resp.error_msg) < sizeof(recv_resp.error_msg));
    assert(strlen(recv_resp.error_msg) == sizeof(resp.error_msg) - 1);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_many_exec_args(void) {
    TEST("many exec_args");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);

    /* Create a large number of exec_args (100 arguments) */
    char **args = malloc(101 * sizeof(char *));
    for (int i = 0; i < 100; i++) {
        args[i] = malloc(32);
        snprintf(args[i], 32, "arg%d", i);
    }
    args[100] = NULL;

    req.exec_args = args;

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify all args received */
    assert(recv_req.exec_args != NULL);
    int count = 0;
    while (recv_req.exec_args[count] != NULL) {
        count++;
    }
    assert(count == 100);

    /* Cleanup */
    for (int i = 0; i < 100; i++) {
        free(args[i]);
    }
    free(args);
    free_request(&recv_req);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_oversized_exec_arg(void) {
    TEST("oversized individual exec_arg");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct priv_request req = {0};
    req.type = REQ_START_SERVICE;
    strncpy(req.unit_name, "test.service", sizeof(req.unit_name) - 1);

    /* Create exec_arg with very long individual argument */
    char *args[3];
    args[0] = malloc(5000);
    memset(args[0], 'x', 4999);
    args[0][4999] = '\0';
    args[1] = strdup("normal_arg");
    args[2] = NULL;

    req.exec_args = args;

    assert(send_request(fds[0], &req) == 0);

    struct priv_request recv_req = {0};
    assert(recv_request(fds[1], &recv_req) == 0);

    /* Verify args received */
    assert(recv_req.exec_args != NULL);
    assert(strlen(recv_req.exec_args[0]) > 0);
    assert(strcmp(recv_req.exec_args[1], "normal_arg") == 0);
    assert(recv_req.exec_args[2] == NULL);

    free(args[0]);
    free(args[1]);
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
    test_invalid_request_type();
    test_invalid_response_type();
    test_oversized_unit_name();
    test_oversized_paths();
    test_oversized_error_msg();
    test_many_exec_args();
    test_oversized_exec_arg();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
