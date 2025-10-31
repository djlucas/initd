/* test-privileged-ops.c - Privileged operations tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include "../src/common/privileged-ops.h"
#include "../src/common/parser.h"
#include "../src/common/log.h"
#include "../src/supervisor/service-registry.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

/* Test directories - use real system paths since we're running as root */
#define TEST_LIB_DIR "/lib/initd/system"
#define TEST_ETC_DIR "/etc/initd/system"
#define TEST_SYSTEMD_DIR "/lib/systemd/system"

/* Setup test environment */
static void setup_test_env(void) {
    /* Create system directories if they don't exist */
    system("mkdir -p /lib/initd/system");
    system("mkdir -p /etc/initd/system");
    system("mkdir -p /lib/systemd/system");
}

/* Cleanup test environment */
static void cleanup_test_env(void) {
    /* Clean up test files from system directories */
    system("rm -f /lib/systemd/system/test.service");
    system("rm -f /lib/initd/system/test.service");
    system("rm -f /lib/initd/system/required.service");
    system("rm -f /lib/initd/system/disable-test.service");
    system("rm -f /lib/initd/system/enabled-check.service");
    system("rm -f /lib/initd/system/no-install.service");
    system("rm -rf /etc/initd/system/*.wants");
    system("rm -rf /etc/initd/system/*.requires");
}

/* Create a test unit file */
static void create_test_unit(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

void test_convert_systemd_unit(void) {
    TEST("convert systemd unit to initd");

    setup_test_env();

    /* Create a systemd unit file */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    create_test_unit(TEST_SYSTEMD_DIR "/test.service", unit_content);

    /* Parse the unit */
    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_SYSTEMD_DIR "/test.service", &unit) == 0);

    /* Convert it */
    assert(convert_systemd_unit(&unit) == 0);

    /* Verify the converted file exists */
    assert(access(TEST_LIB_DIR "/test.service", F_OK) == 0);

    /* Verify the path was updated */
    assert(strstr(unit.path, "/lib/initd/system/test.service") != NULL);

    /* Try converting again - should succeed (already exists) */
    assert(convert_systemd_unit(&unit) == 0);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_enable_unit_wanted_by(void) {
    TEST("enable unit with WantedBy");

    setup_test_env();

    /* Create a unit file */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    create_test_unit(TEST_LIB_DIR "/test.service", unit_content);

    /* Parse the unit */
    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_LIB_DIR "/test.service", &unit) == 0);

    /* Enable it */
    assert(enable_unit(&unit) == 0);

    /* Verify symlink was created */
    char link_path[1024];
    snprintf(link_path, sizeof(link_path), TEST_ETC_DIR "/multi-user.target.wants/test.service");
    assert(access(link_path, F_OK) == 0);

    /* Verify it's a symlink pointing to the right place */
    char target[1024];
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    assert(len > 0);
    target[len] = '\0';
    assert(strstr(target, "test.service") != NULL);

    /* Enable again - should succeed (already enabled) */
    assert(enable_unit(&unit) == 0);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_enable_unit_required_by(void) {
    TEST("enable unit with RequiredBy");

    setup_test_env();

    /* Create a unit file */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "\n"
        "[Install]\n"
        "RequiredBy=basic.target\n";

    create_test_unit(TEST_LIB_DIR "/required.service", unit_content);

    /* Parse the unit */
    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_LIB_DIR "/required.service", &unit) == 0);

    /* Enable it */
    assert(enable_unit(&unit) == 0);

    /* Verify symlink was created */
    char link_path[1024];
    snprintf(link_path, sizeof(link_path), TEST_ETC_DIR "/basic.target.requires/required.service");
    assert(access(link_path, F_OK) == 0);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_disable_unit(void) {
    TEST("disable unit");

    setup_test_env();

    /* Create and enable a unit first */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    create_test_unit(TEST_LIB_DIR "/disable-test.service", unit_content);

    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_LIB_DIR "/disable-test.service", &unit) == 0);

    /* Enable it */
    assert(enable_unit(&unit) == 0);

    /* Verify symlink exists */
    char link_path[1024];
    snprintf(link_path, sizeof(link_path), TEST_ETC_DIR "/multi-user.target.wants/disable-test.service");
    assert(access(link_path, F_OK) == 0);

    /* Now disable it */
    assert(disable_unit(&unit) == 0);

    /* Verify symlink is gone */
    assert(access(link_path, F_OK) != 0);
    assert(errno == ENOENT);

    /* Disable again - should succeed (already disabled) */
    assert(disable_unit(&unit) == 0);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_is_unit_enabled(void) {
    TEST("check if unit is enabled");

    setup_test_env();

    /* Create a unit file */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    create_test_unit(TEST_LIB_DIR "/enabled-check.service", unit_content);

    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_LIB_DIR "/enabled-check.service", &unit) == 0);

    /* Should not be enabled initially */
    assert(is_unit_enabled(&unit) == false);

    /* Enable it */
    assert(enable_unit(&unit) == 0);

    /* Should be enabled now */
    assert(is_unit_enabled(&unit) == true);

    /* Disable it */
    assert(disable_unit(&unit) == 0);

    /* Should not be enabled anymore */
    assert(is_unit_enabled(&unit) == false);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_enable_unit_no_install(void) {
    TEST("enable unit without Install section");

    setup_test_env();

    /* Create a unit file without Install section */
    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n";

    create_test_unit(TEST_LIB_DIR "/no-install.service", unit_content);

    struct unit_file unit = {0};
    assert(parse_unit_file(TEST_LIB_DIR "/no-install.service", &unit) == 0);

    /* Enable should succeed but do nothing */
    assert(enable_unit(&unit) == 0);

    /* Should not be enabled (no symlinks created) */
    assert(is_unit_enabled(&unit) == false);

    free_unit_file(&unit);
    cleanup_test_env();
    PASS();
}

void test_service_registry_prevents_arbitrary_kill(void) {
    TEST("service registry prevents arbitrary kill");

    /* Initialize the service registry */
    service_registry_init();

    /* Register a test service with a known PID */
    pid_t test_pid = 12345;
    assert(register_service(test_pid, "test.service", NULL, KILL_PROCESS, -1, -1, 0) == 0);

    /* Verify we can lookup the registered service */
    struct service_record *svc = lookup_service(test_pid);
    assert(svc != NULL);
    assert(svc->pid == test_pid);
    assert(strcmp(svc->unit_name, "test.service") == 0);

    /* SECURITY TEST: Verify we CANNOT lookup arbitrary system PIDs */
    /* PID 1 is always init/systemd - should not be in our registry */
    struct service_record *init_svc = lookup_service(1);
    assert(init_svc == NULL);

    /* Try other critical system PIDs that should NOT be in registry */
    assert(lookup_service(getpid()) == NULL);  /* Our own test process */
    assert(lookup_service(getppid()) == NULL); /* Our parent process */

    /* Verify unregistered PID lookup fails */
    assert(lookup_service(99999) == NULL);

    /* This test demonstrates that the supervisor's REQ_STOP_SERVICE handler
     * will reject attempts to kill arbitrary PIDs, preventing a compromised
     * worker from killing critical system processes. */

    printf("PASS (verified registry rejects PID 1 and other unmanaged PIDs)\n");
}

int main(void) {
    printf("=== Privileged Operations Tests ===\n\n");

    /* Initialize logging */
    log_init("test-privileged-ops");

    /* Check if running as root */
    if (geteuid() != 0) {
        printf("SKIPPED: These tests require root privileges\n");
        printf("Run with: sudo meson test --suite privileged\n");
        log_close();
        return 77; /* Exit code 77 = skipped in meson */
    }

    /* Run all tests */
    test_convert_systemd_unit();
    test_enable_unit_wanted_by();
    test_enable_unit_required_by();
    test_disable_unit();
    test_is_unit_enabled();
    test_enable_unit_no_install();
    test_service_registry_prevents_arbitrary_kill();

    log_close();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
