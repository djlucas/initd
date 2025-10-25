/* test-integration.c - Integration tests
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"
#include "../src/common/control.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_parse_and_validate_integration(void) {
    TEST("parse and validate integration");

    /* This test demonstrates the full workflow:
     * 1. Parse unit file
     * 2. Validate it
     * 3. Check it's ready for activation */

    const char *unit_content =
        "[Unit]\n"
        "Description=Integration Test Service\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/sleep 60\n"
        "Restart=on-failure\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    /* Create temp file */
    char path[] = "/tmp/test-integration-XXXXXX.service";
    int fd = mkstemps(path, 8);
    assert(fd >= 0);
    write(fd, unit_content, strlen(unit_content));
    close(fd);

    /* Parse */
    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    /* Validate */
    assert(validate_unit_file(&unit) == 0);

    /* Check properties */
    assert(unit.type == UNIT_SERVICE);
    assert(unit.config.service.type == SERVICE_SIMPLE);
    assert(unit.config.service.restart == RESTART_ON_FAILURE);
    assert(unit.unit.after_count == 1);
    assert(unit.install.wanted_by_count == 1);

    /* Cleanup */
    free_unit_file(&unit);
    unlink(path);

    PASS();
}

void test_state_to_string_integration(void) {
    TEST("state to string conversion integration");

    /* Test that state_to_string works with unit states */
    struct unit_file unit = {0};

    unit.state = STATE_INACTIVE;
    const char *str = state_to_string(UNIT_STATE_INACTIVE);
    assert(str != NULL);
    assert(strlen(str) > 0);

    unit.state = STATE_ACTIVE;
    str = state_to_string(UNIT_STATE_ACTIVE);
    assert(str != NULL);

    unit.state = STATE_FAILED;
    str = state_to_string(UNIT_STATE_FAILED);
    assert(str != NULL);

    (void)unit;  /* Used for state transition demonstration */

    PASS();
}

void test_command_to_string_integration(void) {
    TEST("command to string conversion integration");

    /* Test command name lookup */
    const char *str;

    str = command_to_string(CMD_START);
    assert(str != NULL);
    assert(strcmp(str, "start") == 0 || strlen(str) > 0);

    str = command_to_string(CMD_STOP);
    assert(str != NULL);

    str = command_to_string(CMD_STATUS);
    assert(str != NULL);

    PASS();
}

void test_unit_type_detection(void) {
    TEST("unit type detection from filename");

    /* Service */
    const char *service_content =
        "[Unit]\n"
        "Description=Test\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    char service_path[] = "/tmp/test-XXXXXX.service";
    int fd = mkstemps(service_path, 8);
    assert(fd >= 0);
    write(fd, service_content, strlen(service_content));
    close(fd);

    struct unit_file service_unit;
    assert(parse_unit_file(service_path, &service_unit) == 0);
    assert(service_unit.type == UNIT_SERVICE);
    free_unit_file(&service_unit);
    unlink(service_path);

    /* Timer */
    const char *timer_content =
        "[Unit]\n"
        "Description=Test Timer\n"
        "[Timer]\n"
        "OnCalendar=daily\n";

    char timer_path[] = "/tmp/test-XXXXXX.timer";
    fd = mkstemps(timer_path, 6);
    assert(fd >= 0);
    write(fd, timer_content, strlen(timer_content));
    close(fd);

    struct unit_file timer_unit;
    assert(parse_unit_file(timer_path, &timer_unit) == 0);
    assert(timer_unit.type == UNIT_TIMER);
    free_unit_file(&timer_unit);
    unlink(timer_path);

    PASS();
}

void test_dependency_parsing_integration(void) {
    TEST("dependency parsing integration");

    const char *unit_content =
        "[Unit]\n"
        "Description=Complex Dependencies\n"
        "After=a.service b.service\n"
        "Requires=c.service\n"
        "Wants=d.service e.service f.service\n"
        "Conflicts=g.service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    char path[] = "/tmp/test-deps-XXXXXX.service";
    int fd = mkstemps(path, 8);
    assert(fd >= 0);
    write(fd, unit_content, strlen(unit_content));
    close(fd);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    /* Check all dependencies parsed correctly */
    assert(unit.unit.after_count == 2);
    assert(unit.unit.requires_count == 1);
    assert(unit.unit.wants_count == 3);
    assert(unit.unit.conflicts_count == 1);

    free_unit_file(&unit);
    unlink(path);

    PASS();
}

void test_install_section_integration(void) {
    TEST("install section integration");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target graphical.target\n"
        "RequiredBy=important.target\n";

    char path[] = "/tmp/test-install-XXXXXX.service";
    int fd = mkstemps(path, 8);
    assert(fd >= 0);
    write(fd, unit_content, strlen(unit_content));
    close(fd);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    assert(unit.install.wanted_by_count == 2);
    assert(unit.install.required_by_count == 1);
    assert(strcmp(unit.install.wanted_by[0], "multi-user.target") == 0);
    assert(strcmp(unit.install.wanted_by[1], "graphical.target") == 0);
    assert(strcmp(unit.install.required_by[0], "important.target") == 0);

    free_unit_file(&unit);
    unlink(path);

    PASS();
}

void test_environment_parsing_integration(void) {
    TEST("environment variable parsing integration");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/env\n"
        "Environment=VAR1=value1\n"
        "Environment=VAR2=value2 VAR3=value3\n"
        "User=testuser\n"
        "Group=testgroup\n"
        "WorkingDirectory=/tmp\n";

    char path[] = "/tmp/test-env-XXXXXX.service";
    int fd = mkstemps(path, 8);
    assert(fd >= 0);
    write(fd, unit_content, strlen(unit_content));
    close(fd);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    assert(unit.config.service.environment_count == 2);
    assert(strcmp(unit.config.service.user, "testuser") == 0);
    assert(strcmp(unit.config.service.group, "testgroup") == 0);
    assert(strcmp(unit.config.service.working_directory, "/tmp") == 0);

    free_unit_file(&unit);
    unlink(path);

    PASS();
}

void test_service_types_integration(void) {
    TEST("service types integration");

    /* Test all service types parse correctly */
    const char *types[] = {"simple", "forking", "oneshot"};
    enum service_type expected[] = {SERVICE_SIMPLE, SERVICE_FORKING, SERVICE_ONESHOT};

    for (int i = 0; i < 3; i++) {
        char unit_content[256];
        snprintf(unit_content, sizeof(unit_content),
                 "[Unit]\nDescription=Test\n[Service]\nType=%s\nExecStart=/bin/true\n",
                 types[i]);

        char path[] = "/tmp/test-type-XXXXXX.service";
        int fd = mkstemps(path, 8);
        assert(fd >= 0);
        write(fd, unit_content, strlen(unit_content));
        close(fd);

        struct unit_file unit;
        assert(parse_unit_file(path, &unit) == 0);
        assert(unit.config.service.type == expected[i]);

        free_unit_file(&unit);
        unlink(path);
    }

    PASS();
}

void test_restart_policies_integration(void) {
    TEST("restart policies integration");

    const char *policies[] = {"no", "always", "on-failure"};
    enum restart_policy expected[] = {RESTART_NO, RESTART_ALWAYS, RESTART_ON_FAILURE};

    for (int i = 0; i < 3; i++) {
        char unit_content[256];
        snprintf(unit_content, sizeof(unit_content),
                 "[Unit]\nDescription=Test\n[Service]\nExecStart=/bin/true\nRestart=%s\n",
                 policies[i]);

        char path[] = "/tmp/test-restart-XXXXXX.service";
        int fd = mkstemps(path, 8);
        assert(fd >= 0);
        write(fd, unit_content, strlen(unit_content));
        close(fd);

        struct unit_file unit;
        assert(parse_unit_file(path, &unit) == 0);
        assert(unit.config.service.restart == expected[i]);

        free_unit_file(&unit);
        unlink(path);
    }

    PASS();
}

void test_timer_integration(void) {
    TEST("timer unit integration");

    const char *unit_content =
        "[Unit]\n"
        "Description=Backup Timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "OnBootSec=300\n"
        "OnStartupSec=60\n"
        "Persistent=true\n"
        "RandomizedDelaySec=600\n";

    char path[] = "/tmp/test-timer-XXXXXX.timer";
    int fd = mkstemps(path, 6);
    assert(fd >= 0);
    write(fd, unit_content, strlen(unit_content));
    close(fd);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);

    assert(unit.type == UNIT_TIMER);
    assert(strcmp(unit.config.timer.on_calendar, "daily") == 0);
    assert(unit.config.timer.on_boot_sec == 300);
    assert(unit.config.timer.on_startup_sec == 60);
    assert(unit.config.timer.persistent == true);
    assert(unit.config.timer.randomized_delay_sec == 600);

    free_unit_file(&unit);
    unlink(path);

    PASS();
}

void test_on_failure_parsing(void) {
    TEST("OnFailure= directive parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test Unit with OnFailure\n"
        "OnFailure=rescue.service emergency.service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/true\n";

    /* Create temp file */
    char path[] = "/tmp/test-onfailure-XXXXXX.service";
    int fd = mkstemps(path, 8);
    assert(fd >= 0);

    assert(write(fd, unit_content, strlen(unit_content)) == (ssize_t)strlen(unit_content));
    close(fd);

    /* Parse unit file */
    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SERVICE);

    /* Verify OnFailure was parsed */
    assert(unit.unit.on_failure_count == 2);
    assert(strcmp(unit.unit.on_failure[0], "rescue.service") == 0);
    assert(strcmp(unit.unit.on_failure[1], "emergency.service") == 0);

    /* Cleanup */
    free_unit_file(&unit);
    unlink(path);

    PASS();
}

int main(void) {
    printf("=== Integration Tests ===\n\n");

    test_parse_and_validate_integration();
    test_state_to_string_integration();
    test_command_to_string_integration();
    test_unit_type_detection();
    test_dependency_parsing_integration();
    test_install_section_integration();
    test_environment_parsing_integration();
    test_service_types_integration();
    test_restart_policies_integration();
    test_timer_integration();
    test_on_failure_parsing();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
