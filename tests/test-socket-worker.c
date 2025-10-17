/* test-socket-worker.c - Socket activator worker unit tests
 *
 * Copyright (c) 2025
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

/* Forward declarations from worker (UNIT_TEST helpers) */
struct socket_instance;
struct socket_instance *socket_worker_test_create(struct unit_file *unit);
int socket_worker_test_bind(struct socket_instance *inst);
void socket_worker_test_register(struct socket_instance *inst);
void socket_worker_test_unregister_all(void);
void socket_worker_test_set_service(struct socket_instance *inst, pid_t pid,
                                    time_t start, time_t last, int runtime_max_sec);
pid_t socket_worker_test_get_service_pid(const struct socket_instance *inst);
void socket_worker_test_check_idle(void);
void socket_worker_test_check_runtime(void);
int socket_worker_test_idle_kills(void);
int socket_worker_test_runtime_kills(void);
void socket_worker_test_reset_counters(void);
void socket_worker_test_destroy(struct socket_instance *inst);

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

static const char *create_temp_unit(const char *content, const char *extension) {
    static char path[256];
    static char template[256];

    snprintf(template, sizeof(template), "/tmp/test-socket-worker-XXXXXX%s", extension);
    strcpy(path, template);

    int fd = mkstemps(path, strlen(extension));
    if (fd < 0) return NULL;

    write(fd, content, strlen(content));
    close(fd);
    return path;
}

static void test_unix_stream_listener(void) {
    TEST("Unix stream listener binding");

    const char *socket_path = "/tmp/test-socket-worker.sock";
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Stream Listener\n"
        "\n"
        "[Socket]\n"
        "ListenStream=/tmp/test-socket-worker.sock\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    struct socket_instance *inst = socket_worker_test_create(&unit);
    assert(inst != NULL);

    int fd = socket_worker_test_bind(inst);
    assert(fd >= 0);

    struct stat st;
    assert(stat(socket_path, &st) == 0);
    assert(S_ISSOCK(st.st_mode));

    socket_worker_test_destroy(inst);
    free_unit_file(&unit);
    unlink(path);
    unlink(socket_path);

    PASS();
}

static void test_idle_timeout_enforcement(void) {
    TEST("Idle timeout enforcement");

    struct unit_file unit = {0};
    strncpy(unit.name, "idle.socket", sizeof(unit.name) - 1);
    unit.type = UNIT_SOCKET;
    unit.config.socket.idle_timeout = 1;

    struct socket_instance *inst = socket_worker_test_create(&unit);
    assert(inst != NULL);

    socket_worker_test_set_service(inst, (pid_t)999999,
                                   time(NULL) - 10, time(NULL) - 10, 0);
    socket_worker_test_register(inst);
    socket_worker_test_reset_counters();

    socket_worker_test_check_idle();
    assert(socket_worker_test_idle_kills() == 1);

    socket_worker_test_unregister_all();
    socket_worker_test_destroy(inst);

    PASS();
}

static void test_runtime_limit_enforcement(void) {
    TEST("Runtime limit enforcement");

    struct unit_file unit = {0};
    strncpy(unit.name, "runtime.socket", sizeof(unit.name) - 1);
    unit.type = UNIT_SOCKET;

    struct socket_instance *inst = socket_worker_test_create(&unit);
    assert(inst != NULL);

    socket_worker_test_set_service(inst, (pid_t)999998,
                                   time(NULL) - 10, time(NULL),
                                   5 /* RuntimeMaxSec */);
    socket_worker_test_register(inst);
    socket_worker_test_reset_counters();

    socket_worker_test_check_runtime();
    assert(socket_worker_test_runtime_kills() == 1);

    socket_worker_test_unregister_all();
    socket_worker_test_destroy(inst);

    PASS();
}

int main(void) {
    test_unix_stream_listener();
    test_idle_timeout_enforcement();
    test_runtime_limit_enforcement();
    return 0;
}
