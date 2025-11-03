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
        "RandomizedDelaySec=60\n"
        "AccuracySec=120\n"
        "Unit=custom.service\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_calendar_count == 1);
    assert(strcmp(unit.config.timer.on_calendar[0], "daily") == 0);
    assert(unit.config.timer.on_boot_sec == 300);
    assert(unit.config.timer.persistent == true);
    assert(unit.config.timer.randomized_delay_sec == 60);
    assert(unit.config.timer.accuracy_sec == 120);
    assert(strcmp(unit.config.timer.unit, "custom.service") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_defaults(void) {
    TEST("timer unit default values");

    const char *unit_content =
        "[Unit]\n"
        "Description=Simple Timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=60\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    /* AccuracySec defaults to 60 seconds (1 minute) per systemd spec */
    assert(unit.config.timer.accuracy_sec == 60);
    /* Unit defaults to NULL (derive from timer name) */
    assert(unit.config.timer.unit == NULL);
    /* RemainAfterElapse defaults to true */
    assert(unit.config.timer.remain_after_elapse == true);
    /* FixedRandomDelay defaults to false */
    assert(unit.config.timer.fixed_random_delay == false);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_multiple_calendar(void) {
    TEST("timer unit with multiple OnCalendar entries");

    const char *unit_content =
        "[Unit]\n"
        "Description=Multi-Calendar Timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "OnCalendar=weekly\n"
        "OnCalendar=monthly\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_calendar_count == 3);
    assert(strcmp(unit.config.timer.on_calendar[0], "daily") == 0);
    assert(strcmp(unit.config.timer.on_calendar[1], "weekly") == 0);
    assert(strcmp(unit.config.timer.on_calendar[2], "monthly") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_fixed_random_delay(void) {
    TEST("timer unit with FixedRandomDelay");

    const char *unit_content =
        "[Unit]\n"
        "Description=Fixed Random Timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=300\n"
        "RandomizedDelaySec=60\n"
        "FixedRandomDelay=true\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_boot_sec == 300);
    assert(unit.config.timer.randomized_delay_sec == 60);
    assert(unit.config.timer.fixed_random_delay == true);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_remain_after_elapse(void) {
    TEST("timer unit with RemainAfterElapse");

    const char *unit_content =
        "[Unit]\n"
        "Description=One-shot Timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=60\n"
        "RemainAfterElapse=false\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_boot_sec == 60);
    assert(unit.config.timer.remain_after_elapse == false);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_wake_system(void) {
    TEST("timer unit with WakeSystem");

    const char *unit_content =
        "[Unit]\n"
        "Description=Wake Timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*-*-* 06:00:00\n"
        "WakeSystem=true\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.wake_system == true);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_clock_change(void) {
    TEST("timer unit with OnClockChange");

    const char *unit_content =
        "[Unit]\n"
        "Description=Clock Change Timer\n"
        "\n"
        "[Timer]\n"
        "OnClockChange=true\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_clock_change == true);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_timer_timezone_change(void) {
    TEST("timer unit with OnTimezoneChange");

    const char *unit_content =
        "[Unit]\n"
        "Description=Timezone Change Timer\n"
        "\n"
        "[Timer]\n"
        "OnTimezoneChange=yes\n";

    const char *path = create_temp_unit(unit_content, ".timer");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_TIMER);
    assert(unit.config.timer.on_timezone_change == true);

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
        "StopWhenUnneeded=true\n"
        "RefuseManualStart=yes\n"
        "RefuseManualStop=1\n"
        "StartLimitIntervalSec=120\n"
        "StartLimitBurst=8\n"
        "StartLimitAction=reboot\n"
        "ConditionPathExists=/etc/passwd\n"
        "ConditionPathExists=!/no/such/path\n"
        "ConditionDirectoryNotEmpty=/tmp\n"
        "ConditionFileIsExecutable=/bin/true\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "PIDFile=/run/test.pid\n"
        "RestartPreventExitStatus=0 5\n"
        "RestartForceExitStatus=7\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 4);
    assert(unit.unit.stop_when_unneeded == true);
    assert(unit.unit.refuse_manual_start == true);
    assert(unit.unit.refuse_manual_stop == true);
    assert(unit.unit.start_limit_interval_set == true);
    assert(unit.unit.start_limit_interval_sec == 120);
    assert(unit.unit.start_limit_burst_set == true);
    assert(unit.unit.start_limit_burst == 8);
    assert(unit.unit.start_limit_action_set == true);
    assert(unit.unit.start_limit_action == START_LIMIT_ACTION_REBOOT);

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

    assert(unit.config.service.restart_prevent_count == 2);
    assert(unit.config.service.restart_prevent_statuses[0] == 0);
    assert(unit.config.service.restart_prevent_statuses[1] == 5);
    assert(unit.config.service.restart_force_count == 1);
    assert(unit.config.service.restart_force_statuses[0] == 7);
    assert(strcmp(unit.config.service.pid_file, "/run/test.pid") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_install_extras(void) {
    TEST("install extras parsing");

    const char *unit_content =
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "RequiredBy=graphical.target\n"
        "Also=foo.service bar.service\n"
        "Alias=alias.service alt.service\n"
        "DefaultInstance=%i\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.install.wanted_by_count == 1);
    assert(strcmp(unit.install.wanted_by[0], "multi-user.target") == 0);
    assert(unit.install.required_by_count == 1);
    assert(strcmp(unit.install.required_by[0], "graphical.target") == 0);
    assert(unit.install.also_count == 2);
    assert(strcmp(unit.install.also[0], "foo.service") == 0);
    assert(strcmp(unit.install.also[1], "bar.service") == 0);
    assert(unit.install.alias_count == 2);
    assert(strcmp(unit.install.alias[0], "alias.service") == 0);
    assert(strcmp(unit.install.alias[1], "alt.service") == 0);
    assert(strcmp(unit.install.default_instance, "%i") == 0);

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

void test_parse_allow_isolate(void) {
    TEST("AllowIsolate= directive");

    const char *unit_content =
        "[Unit]\n"
        "Description=Rescue Target\n"
        "AllowIsolate=yes\n";

    const char *path = create_temp_unit(unit_content, ".target");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.allow_isolate == true);

    free_unit_file(&unit);
    unlink(path);

    /* Test with AllowIsolate=no */
    const char *unit_content2 =
        "[Unit]\n"
        "Description=Network Target\n"
        "AllowIsolate=no\n";

    path = create_temp_unit(unit_content2, ".target");
    assert(path != NULL);

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.allow_isolate == false);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_default_dependencies(void) {
    TEST("DefaultDependencies= directive");

    /* Test DefaultDependencies=no (for sysinit services) */
    const char *unit_content =
        "[Unit]\n"
        "Description=Mount Virtual Filesystems\n"
        "DefaultDependencies=no\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/mount -t proc proc /proc\n";

    const char *path = create_temp_unit(unit_content, ".service");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.default_dependencies == false);
    /* Should NOT have implicit shutdown dependencies */
    int has_shutdown_conflict = 0;
    int has_shutdown_before = 0;
    for (int i = 0; i < unit.unit.conflicts_count; i++) {
        if (strcmp(unit.unit.conflicts[i], "shutdown.target") == 0) {
            has_shutdown_conflict = 1;
        }
    }
    for (int i = 0; i < unit.unit.before_count; i++) {
        if (strcmp(unit.unit.before[i], "shutdown.target") == 0) {
            has_shutdown_before = 1;
        }
    }
    assert(has_shutdown_conflict == 0);
    assert(has_shutdown_before == 0);

    free_unit_file(&unit);
    unlink(path);

    /* Test DefaultDependencies=yes - should get implicit Conflicts/Before shutdown.target */
    const char *unit_content2 =
        "[Unit]\n"
        "Description=Normal Service\n"
        "DefaultDependencies=yes\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    path = create_temp_unit(unit_content2, ".service");
    assert(path != NULL);

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.default_dependencies == true);
    /* Should have implicit Conflicts=shutdown.target Before=shutdown.target */
    has_shutdown_conflict = 0;
    has_shutdown_before = 0;
    for (int i = 0; i < unit.unit.conflicts_count; i++) {
        if (strcmp(unit.unit.conflicts[i], "shutdown.target") == 0) {
            has_shutdown_conflict = 1;
        }
    }
    for (int i = 0; i < unit.unit.before_count; i++) {
        if (strcmp(unit.unit.before[i], "shutdown.target") == 0) {
            has_shutdown_before = 1;
        }
    }
    assert(has_shutdown_conflict == 1);
    assert(has_shutdown_before == 1);

    free_unit_file(&unit);
    unlink(path);

    /* Test default (should be true and get implicit dependencies) */
    const char *unit_content3 =
        "[Unit]\n"
        "Description=Service Without Explicit DefaultDependencies\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n";

    path = create_temp_unit(unit_content3, ".service");
    assert(path != NULL);

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.default_dependencies == true);  /* Should default to true */
    /* Should have implicit shutdown dependencies */
    has_shutdown_conflict = 0;
    has_shutdown_before = 0;
    for (int i = 0; i < unit.unit.conflicts_count; i++) {
        if (strcmp(unit.unit.conflicts[i], "shutdown.target") == 0) {
            has_shutdown_conflict = 1;
        }
    }
    for (int i = 0; i < unit.unit.before_count; i++) {
        if (strcmp(unit.unit.before[i], "shutdown.target") == 0) {
            has_shutdown_before = 1;
        }
    }
    assert(has_shutdown_conflict == 1);
    assert(has_shutdown_before == 1);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_socket_exec_commands(void) {
    TEST("socket Exec* lifecycle commands");

    const char *unit_content =
        "[Unit]\n"
        "Description=Socket with Lifecycle Commands\n"
        "\n"
        "[Socket]\n"
        "ListenStream=/run/test.sock\n"
        "ExecStartPre=/usr/bin/logger \"Starting socket\"\n"
        "ExecStartPost=/usr/local/bin/notify-ready test\n"
        "ExecStopPost=/usr/local/bin/cleanup-test\n";

    const char *path = create_temp_unit(unit_content, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(strcmp(unit.config.socket.listen_stream, "/run/test.sock") == 0);
    assert(unit.config.socket.exec_start_pre != NULL);
    assert(strcmp(unit.config.socket.exec_start_pre, "/usr/bin/logger \"Starting socket\"") == 0);
    assert(unit.config.socket.exec_start_post != NULL);
    assert(strcmp(unit.config.socket.exec_start_post, "/usr/local/bin/notify-ready test") == 0);
    assert(unit.config.socket.exec_stop_post != NULL);
    assert(strcmp(unit.config.socket.exec_stop_post, "/usr/local/bin/cleanup-test") == 0);

    free_unit_file(&unit);
    unlink(path);
    PASS();
}

void test_parse_socket_accept(void) {
    TEST("socket Accept= directive");

    /* Test Accept=yes */
    const char *unit_content_yes =
        "[Unit]\n"
        "Description=inetd-style Socket\n"
        "\n"
        "[Socket]\n"
        "ListenStream=8080\n"
        "Accept=yes\n";

    const char *path = create_temp_unit(unit_content_yes, ".socket");
    assert(path != NULL);

    struct unit_file unit;
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(unit.config.socket.accept == true);

    free_unit_file(&unit);
    unlink(path);

    /* Test Accept=no (default) */
    const char *unit_content_no =
        "[Unit]\n"
        "Description=Standard Socket\n"
        "\n"
        "[Socket]\n"
        "ListenStream=/run/app.sock\n"
        "Accept=no\n";

    path = create_temp_unit(unit_content_no, ".socket");
    assert(path != NULL);

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(unit.config.socket.accept == false);

    free_unit_file(&unit);
    unlink(path);

    /* Test default (Accept not specified, should be false) */
    const char *unit_content_default =
        "[Unit]\n"
        "Description=Socket with default Accept\n"
        "\n"
        "[Socket]\n"
        "ListenStream=9000\n";

    path = create_temp_unit(unit_content_default, ".socket");
    assert(path != NULL);

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.type == UNIT_SOCKET);
    assert(unit.config.socket.accept == false);  /* Default: false */

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
    test_parse_timer_defaults();
    test_parse_timer_multiple_calendar();
    test_parse_timer_fixed_random_delay();
    test_parse_timer_remain_after_elapse();
    test_parse_timer_wake_system();
    test_parse_timer_clock_change();
    test_parse_timer_timezone_change();
    test_parse_environment();
    test_parse_conditions();
    test_parse_install_extras();
    test_validate_missing_execstart();
    test_parse_provides();
    test_parse_allow_isolate();
    test_parse_default_dependencies();
    test_parse_socket_exec_commands();
    test_parse_socket_accept();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
