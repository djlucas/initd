/* test-parser.c - Unit file parser tests
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
    snprintf(template, sizeof(template), "/tmp/test-unit-XXXXXX%s", extension);
    strcpy(path, template);

    int fd = mkstemps(path, strlen(extension));
    if (fd < 0) return NULL;

    write(fd, content, strlen(content));
    close(fd);
    return path;
}

void test_parse_basic_service(void) {
    TEST("basic service parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test Service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/echo hello\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SERVICE);
    assert(strcmp(unit.unit.description, "Test Service") == 0);
    assert(unit.config.service.type == SERVICE_SIMPLE);
    assert(strcmp(unit.config.service.exec_start, "/bin/echo hello") == 0);
    assert(unit.install.wanted_by_count == 1);
    assert(strcmp(unit.install.wanted_by[0], "multi-user.target") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_dependencies(void) {
    TEST("dependency parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Test Dependencies\n"
        "After=network.target\n"
        "Requires=dbus.service\n"
        "Wants=bluetooth.service wifi.service\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.after_count == 1);
    assert(strcmp(unit.unit.after[0], "network.target") == 0);
    assert(unit.unit.requires_count == 1);
    assert(strcmp(unit.unit.requires[0], "dbus.service") == 0);
    assert(unit.unit.wants_count == 2);
    assert(strcmp(unit.unit.wants[0], "bluetooth.service") == 0);
    assert(strcmp(unit.unit.wants[1], "wifi.service") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_forking_service(void) {
    TEST("forking service type");

    const char *unit_content =
        "[Unit]\n"
        "Description=Forking Test\n"
        "\n"
        "[Service]\n"
        "Type=forking\n"
        "ExecStart=/usr/sbin/daemon\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "RuntimeMaxSec=120\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.type == SERVICE_FORKING);
    assert(unit.config.service.restart == RESTART_ALWAYS);
    assert(unit.config.service.restart_sec == 5);
    assert(unit.config.service.runtime_max_sec == 120);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer(void) {
    TEST("timer unit parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Daily Timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "OnBootSec=300\n"
        "Persistent=true\n"
        "RandomizedDelaySec=60\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(strcmp(unit.config.timer.on_calendar, "daily") == 0);
    assert(unit.config.timer.on_boot_sec == 300);
    assert(unit.config.timer.persistent == true);
    assert(unit.config.timer.randomized_delay_sec == 60);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_environment(void) {
    TEST("environment variables");

    const char *unit_content =
        "[Unit]\n"
        "Description=Env Test\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/test\n"
        "Environment=FOO=bar\n"
        "Environment=BAZ=qux\n"
        "User=nobody\n"
        "Group=nogroup\n"
        "WorkingDirectory=/tmp\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.environment_count == 2);
    assert(strcmp(unit.config.service.environment[0], "FOO=bar") == 0);
    assert(strcmp(unit.config.service.environment[1], "BAZ=qux") == 0);
    assert(strcmp(unit.config.service.user, "nobody") == 0);
    assert(strcmp(unit.config.service.group, "nogroup") == 0);
    assert(strcmp(unit.config.service.working_directory, "/tmp") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_conditions(void) {
    TEST("condition parsing");

    const char *unit_content =
        "[Unit]\n"
        "Description=Condition Test\n"
        "ConditionPathExists=/etc/passwd\n"
        "ConditionPathExists=!/no/such/path\n"
        "ConditionDirectoryNotEmpty=/tmp\n"
        "ConditionFileIsExecutable=/bin/true\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 4);

    assert(unit.unit.conditions[0].type == CONDITION_PATH_EXISTS);
    assert(unit.unit.conditions[0].negate == false);
    assert(strcmp(unit.unit.conditions[0].value, "/etc/passwd") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_PATH_EXISTS);
    assert(unit.unit.conditions[1].negate == true);
    assert(strcmp(unit.unit.conditions[1].value, "/no/such/path") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_DIRECTORY_NOT_EMPTY);
    assert(unit.unit.conditions[2].negate == false);
    assert(strcmp(unit.unit.conditions[2].value, "/tmp") == 0);

    assert(unit.unit.conditions[3].type == CONDITION_FILE_IS_EXECUTABLE);
    assert(unit.unit.conditions[3].negate == false);
    assert(strcmp(unit.unit.conditions[3].value, "/bin/true") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_validate_missing_execstart(void) {
    TEST("validation - missing ExecStart");

    const char *unit_content =
        "[Unit]\n"
        "Description=Invalid Service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(validate_unit_file(&unit) < 0);  /* Should fail */

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_provides(void) {
    TEST("Provides= directive");

    const char *unit_content =
        "[Unit]\n"
        "Description=Syslog Service\n"
        "Provides=syslog\n"
        "\n"
        "[Service]\n"
        "ExecStart=/usr/sbin/syslogd\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.provides_count == 1);
    assert(strcmp(unit.unit.provides[0], "syslog") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

int main(void) {
    printf("=== Unit File Parser Tests ===\n\n");

    test_parse_basic_service();
    test_parse_dependencies();
    test_parse_forking_service();
    test_parse_timer();
    test_parse_environment();
    test_parse_conditions();
    test_validate_missing_execstart();
    test_parse_provides();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
