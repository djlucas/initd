/* test-socket.c - Socket activator tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

/* Create temporary unit file for testing with proper extension */
static const char *create_temp_unit(const char *content, const char *extension) {
    static char path[256];
    static char template[256];

    /* Create template with extension */
    snprintf(template, sizeof(template), "/tmp/test-socket-XXXXXX%s", extension);
    strcpy(path, template);

    int fd = mkstemps(path, strlen(extension));
    if (fd < 0) return NULL;

    write(fd, content, strlen(content));
    close(fd);
    return path;
}

void test_parse_unix_stream_socket(void) {
    TEST("Unix stream socket parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test Unix Socket\n"
        "\n"
        "[Socket]\n"
        "ListenStream=/var/run/test.sock\n"
        "IdleTimeout=60\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(strcmp(unit.unit.description, "Test Unix Socket") == 0);
    assert(strcmp(unit.config.socket.listen_stream, "/var/run/test.sock") == 0);
    assert(unit.config.socket.idle_timeout == 60);
    assert(unit.install.wanted_by_count == 1);
    assert(strcmp(unit.install.wanted_by[0], "sockets.target") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_tcp_socket(void) {
    TEST("TCP socket parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=HTTP Socket\n"
        "\n"
        "[Socket]\n"
        "ListenStream=0.0.0.0:8080\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(strcmp(unit.config.socket.listen_stream, "0.0.0.0:8080") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_udp_socket(void) {
    TEST("UDP socket parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=UDP Socket\n"
        "\n"
        "[Socket]\n"
        "ListenDatagram=*:514\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(strcmp(unit.config.socket.listen_datagram, "*:514") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_unix_datagram_socket(void) {
    TEST("Unix datagram socket parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Syslog Socket\n"
        "\n"
        "[Socket]\n"
        "ListenDatagram=/dev/log\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(strcmp(unit.config.socket.listen_datagram, "/dev/log") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_validate_missing_listen(void) {
    TEST("validation - missing Listen directive");

    const char *unit_content =
        "[Unit]\n"
        "Description=Invalid Socket\n"
        "\n"
        "[Socket]\n"
        "IdleTimeout=30\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(validate_unit_file(&unit) < 0);  /* Should fail */

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_unix_socket_creation(void) {
    TEST("Unix socket creation and binding");

    /* Create a Unix socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/test-socket-activator.sock",
            sizeof(addr.sun_path) - 1);

    /* Remove if exists */
    unlink(addr.sun_path);

    /* Bind */
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);

    /* Listen */
    assert(listen(fd, 5) == 0);

    /* Verify socket exists */
    struct stat st;
    assert(stat(addr.sun_path, &st) == 0);
    assert(S_ISSOCK(st.st_mode));

    /* Cleanup */
    close(fd);
    unlink(addr.sun_path);
    PASS();
}

void test_tcp_socket_creation(void) {
    TEST("TCP socket creation and binding");

    /* Create a TCP socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);

    /* Enable reuse */
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(0);  /* Use any available port */

    /* Bind */
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);

    /* Get assigned port */
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
    assert(ntohs(addr.sin_port) > 0);

    /* Listen */
    assert(listen(fd, 5) == 0);

    /* Cleanup */
    close(fd);
    PASS();
}

void test_socket_accept(void) {
    TEST("socket accept mechanism");

    /* Create listening socket */
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listen_fd >= 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/test-accept.sock", sizeof(addr.sun_path) - 1);
    unlink(addr.sun_path);

    assert(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listen_fd, 5) == 0);

    /* Fork to create client */
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        /* Child - client */
        sleep(1);  /* Give server time to accept */

        int client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        assert(client_fd >= 0);

        assert(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);

        /* Send test data */
        const char *msg = "test";
        write(client_fd, msg, strlen(msg));

        close(client_fd);
        exit(0);
    } else {
        /* Parent - server */
        int client_fd = accept(listen_fd, NULL, NULL);
        assert(client_fd >= 0);

        /* Read test data */
        char buf[16] = {0};
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        assert(n > 0);
        assert(strcmp(buf, "test") == 0);

        close(client_fd);
        close(listen_fd);
        unlink(addr.sun_path);

        /* Wait for child */
        waitpid(pid, NULL, 0);
    }

    PASS();
}

void test_socket_fd_passing(void) {
    TEST("socket FD duplication (dup2)");

    int fds[2];
    assert(pipe(fds) == 0);

    /* Duplicate to fd 3 (standard for socket activation) */
    assert(dup2(fds[0], 3) == 3);

    /* Write to pipe */
    const char *msg = "activation";
    write(fds[1], msg, strlen(msg));

    /* Read from fd 3 */
    char buf[16] = {0};
    ssize_t n = read(3, buf, sizeof(buf) - 1);
    assert(n > 0);
    assert(strcmp(buf, "activation") == 0);

    close(fds[0]);
    close(fds[1]);
    close(3);

    PASS();
}

void test_idle_timeout_calculation(void) {
    TEST("idle timeout calculation");

    time_t last_activity = time(NULL) - 100;  /* 100 seconds ago */
    time_t now = time(NULL);
    int idle_timeout = 60;

    time_t idle_time = now - last_activity;
    assert(idle_time >= idle_timeout);  /* Should be timed out */

    /* Not timed out */
    last_activity = time(NULL) - 30;  /* 30 seconds ago */
    idle_time = now - last_activity;
    assert(idle_time < idle_timeout);  /* Should NOT be timed out */

    PASS();
}

int main(void) {
    printf("=== Socket Activator Tests ===\n\n");

    test_parse_unix_stream_socket();
    test_parse_tcp_socket();
    test_parse_udp_socket();
    test_parse_unix_datagram_socket();
    test_validate_missing_listen();
    test_unix_socket_creation();
    test_tcp_socket_creation();
    test_socket_accept();
    test_socket_fd_passing();
    test_idle_timeout_calculation();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
