/* test-socket-ipc.c - Socket IPC protocol tests
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
#include "../src/common/socket-ipc.h"

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
    struct socket_request req = {0};
    req.type = SOCKET_REQ_ENABLE_UNIT;
    strncpy(req.unit_name, "sshd.socket", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/lib/initd/system/sshd.socket", sizeof(req.unit_path) - 1);

    /* Send */
    assert(send_socket_request(fds[0], &req) == 0);

    /* Receive */
    struct socket_request recv_req = {0};
    assert(recv_socket_request(fds[1], &recv_req) == 0);

    /* Verify */
    assert(recv_req.type == SOCKET_REQ_ENABLE_UNIT);
    assert(strcmp(recv_req.unit_name, "sshd.socket") == 0);
    assert(strcmp(recv_req.unit_path, "/lib/initd/system/sshd.socket") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_disable_request(void) {
    TEST("disable unit request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_request req = {0};
    req.type = SOCKET_REQ_DISABLE_UNIT;
    strncpy(req.unit_name, "httpd.socket", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/etc/initd/system/httpd.socket", sizeof(req.unit_path) - 1);

    assert(send_socket_request(fds[0], &req) == 0);

    struct socket_request recv_req = {0};
    assert(recv_socket_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == SOCKET_REQ_DISABLE_UNIT);
    assert(strcmp(recv_req.unit_name, "httpd.socket") == 0);
    assert(strcmp(recv_req.unit_path, "/etc/initd/system/httpd.socket") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_convert_request(void) {
    TEST("convert unit request");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_request req = {0};
    req.type = SOCKET_REQ_CONVERT_UNIT;
    strncpy(req.unit_name, "cups.socket", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, "/lib/systemd/system/cups.socket", sizeof(req.unit_path) - 1);

    assert(send_socket_request(fds[0], &req) == 0);

    struct socket_request recv_req = {0};
    assert(recv_socket_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == SOCKET_REQ_CONVERT_UNIT);
    assert(strcmp(recv_req.unit_name, "cups.socket") == 0);
    assert(strcmp(recv_req.unit_path, "/lib/systemd/system/cups.socket") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_ok_response(void) {
    TEST("OK response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_response resp = {0};
    resp.type = SOCKET_RESP_OK;
    resp.error_code = 0;

    assert(send_socket_response(fds[0], &resp) == 0);

    struct socket_response recv_resp = {0};
    assert(recv_socket_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == SOCKET_RESP_OK);
    assert(recv_resp.error_code == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_error_response(void) {
    TEST("error response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_response resp = {0};
    resp.type = SOCKET_RESP_ERROR;
    resp.error_code = 2; /* ENOENT */
    strncpy(resp.error_msg, "Socket unit not found", sizeof(resp.error_msg) - 1);

    assert(send_socket_response(fds[0], &resp) == 0);

    struct socket_response recv_resp = {0};
    assert(recv_socket_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == SOCKET_RESP_ERROR);
    assert(recv_resp.error_code == 2);
    assert(strcmp(recv_resp.error_msg, "Socket unit not found") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_converted_response(void) {
    TEST("unit converted response");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_response resp = {0};
    resp.type = SOCKET_RESP_OK;
    strncpy(resp.converted_path, "/lib/initd/system/converted.socket", sizeof(resp.converted_path) - 1);

    assert(send_socket_response(fds[0], &resp) == 0);

    struct socket_response recv_resp = {0};
    assert(recv_socket_response(fds[1], &recv_resp) == 0);

    assert(recv_resp.type == SOCKET_RESP_OK);
    assert(strcmp(recv_resp.converted_path, "/lib/initd/system/converted.socket") == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_multiple_roundtrips(void) {
    TEST("multiple request/response roundtrips");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    /* Send multiple requests in sequence */
    for (int i = 0; i < 5; i++) {
        struct socket_request req = {0};
        req.type = SOCKET_REQ_ENABLE_UNIT;
        snprintf(req.unit_name, sizeof(req.unit_name), "test%d.socket", i);
        snprintf(req.unit_path, sizeof(req.unit_path), "/lib/initd/system/test%d.socket", i);

        assert(send_socket_request(fds[0], &req) == 0);

        struct socket_request recv_req = {0};
        assert(recv_socket_request(fds[1], &recv_req) == 0);

        assert(recv_req.type == SOCKET_REQ_ENABLE_UNIT);

        char expected_name[256];
        snprintf(expected_name, sizeof(expected_name), "test%d.socket", i);
        assert(strcmp(recv_req.unit_name, expected_name) == 0);
    }

    close(fds[0]);
    close(fds[1]);
    PASS();
}

void test_empty_strings(void) {
    TEST("empty string handling");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    struct socket_request req = {0};
    req.type = SOCKET_REQ_ENABLE_UNIT;
    /* Leave unit_name and unit_path empty */

    assert(send_socket_request(fds[0], &req) == 0);

    struct socket_request recv_req = {0};
    assert(recv_socket_request(fds[1], &recv_req) == 0);

    assert(recv_req.type == SOCKET_REQ_ENABLE_UNIT);
    assert(strlen(recv_req.unit_name) == 0);
    assert(strlen(recv_req.unit_path) == 0);

    close(fds[0]);
    close(fds[1]);
    PASS();
}

int main(void) {
    printf("=== Socket IPC Protocol Tests ===\n\n");

    test_enable_request();
    test_disable_request();
    test_convert_request();
    test_ok_response();
    test_error_response();
    test_converted_response();
    test_multiple_roundtrips();
    test_empty_strings();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
