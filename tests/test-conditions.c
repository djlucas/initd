/* test-conditions.c - Test POSIX-portable Condition/Assert directives
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

/* Helper to create unique temp files */
static char *create_temp_unit_file(const char *content) {
    static char template[] = "/tmp/test-cond-XXXXXX.service";
    char *path = strdup(template);

    /* Create unique file */
    int fd = mkstemps(path, 8); /* 8 = strlen(".service") */
    assert(fd >= 0);

    /* Write content */
    write(fd, content, strlen(content));
    close(fd);

    return path;
}

/* Cleanup temp file */
static void cleanup_temp_file(const char *path) {
    if (path) {
        unlink(path);
        free((void *)path);
    }
}

/* Test ConditionFileNotEmpty */
static void test_condition_file_not_empty(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionFileNotEmpty=/etc/passwd\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_FILE_NOT_EMPTY);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "/etc/passwd") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionFileNotEmpty parsing works\n");
}

/* Test ConditionUser */
static void test_condition_user(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionUser=root\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_USER);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "root") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionUser parsing works\n");
}

/* Test ConditionGroup */
static void test_condition_group(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionGroup=wheel\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_GROUP);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "wheel") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionGroup parsing works\n");
}

/* Test ConditionHost */
static void test_condition_host(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionHost=localhost\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_HOST);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "localhost") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionHost parsing works\n");
}

/* Test ConditionArchitecture */
static void test_condition_architecture(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionArchitecture=x86-64\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_ARCHITECTURE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "x86-64") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionArchitecture parsing works\n");
}

/* Test ConditionMemory */
static void test_condition_memory(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionMemory=1G\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_MEMORY);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "1G") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionMemory parsing works\n");
}

/* Test ConditionCPUs */
static void test_condition_cpus(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionCPUs=>=2\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 1);
    assert(unit.unit.conditions[0].type == CONDITION_CPUS);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, ">=2") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionCPUs parsing works\n");
}

/* Test ConditionEnvironment */
static void test_condition_environment(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionEnvironment=PATH\n"
        "ConditionEnvironment=HOME=/root\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);
    assert(unit.unit.conditions[0].type == CONDITION_ENVIRONMENT);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "PATH") == 0);
    assert(unit.unit.conditions[1].type == CONDITION_ENVIRONMENT);
    assert(strcmp(unit.unit.conditions[1].value, "HOME=/root") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionEnvironment parsing works\n");
}

/* Test Assert* directives */
static void test_assert_directives(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "AssertPathExists=/etc/passwd\n"
        "AssertUser=root\n"
        "AssertArchitecture=x86-64\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_PATH_EXISTS);
    assert(unit.unit.conditions[0].is_assert == true);
    assert(strcmp(unit.unit.conditions[0].value, "/etc/passwd") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_USER);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "root") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_ARCHITECTURE);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "x86-64") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ Assert* directives parsing works\n");
}

/* Test negation with new directives */
static void test_condition_negation(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionUser=!root\n"
        "AssertFileNotEmpty=!/tmp/should_not_be_empty\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_USER);
    assert(unit.unit.conditions[0].negate == true);
    assert(strcmp(unit.unit.conditions[0].value, "root") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_FILE_NOT_EMPTY);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(unit.unit.conditions[1].negate == true);
    assert(strcmp(unit.unit.conditions[1].value, "/tmp/should_not_be_empty") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ Condition/Assert negation works\n");
}

static void test_condition_virtualization(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "virt-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionVirtualization=kvm\n"
        "ConditionVirtualization=docker\n"
        "AssertVirtualization=vm\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_VIRTUALIZATION);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "kvm") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_VIRTUALIZATION);
    assert(unit.unit.conditions[1].is_assert == false);
    assert(strcmp(unit.unit.conditions[1].value, "docker") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_VIRTUALIZATION);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "vm") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionVirtualization/AssertVirtualization parsing works\n");
}

static void test_condition_ac_power(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "ac-power-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionACPower=true\n"
        "AssertACPower=false\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_AC_POWER);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "true") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_AC_POWER);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "false") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionACPower/AssertACPower parsing works\n");
}

static void test_condition_os_release(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "os-release-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionOSRelease=ID=debian\n"
        "ConditionOSRelease=VERSION_ID=12\n"
        "AssertOSRelease=NAME=Debian GNU/Linux\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_OS_RELEASE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "ID=debian") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_OS_RELEASE);
    assert(unit.unit.conditions[1].is_assert == false);
    assert(strcmp(unit.unit.conditions[1].value, "VERSION_ID=12") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_OS_RELEASE);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "NAME=Debian GNU/Linux") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionOSRelease/AssertOSRelease parsing works\n");
}

static void test_condition_kernel_version(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "kernel-version-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionKernelVersion=>=5.10\n"
        "ConditionKernelVersion=<6.0\n"
        "AssertKernelVersion=>=4.0\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_KERNEL_VERSION);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, ">=5.10") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_KERNEL_VERSION);
    assert(unit.unit.conditions[1].is_assert == false);
    assert(strcmp(unit.unit.conditions[1].value, "<6.0") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_KERNEL_VERSION);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, ">=4.0") == 0);

    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ ConditionKernelVersion/AssertKernelVersion parsing works\n");
}

int main(void) {
    printf("Testing Condition*/Assert* directives...\n");

    /* POSIX-portable tests */
    test_condition_file_not_empty();
    test_condition_user();
    test_condition_group();
    test_condition_host();
    test_condition_architecture();
    test_condition_memory();
    test_condition_cpus();
    test_condition_environment();
    test_assert_directives();
    test_condition_negation();

    /* Platform-specific tests */
    test_condition_virtualization();
    test_condition_ac_power();
    test_condition_os_release();
    test_condition_kernel_version();

    printf("\n✓ All condition/assert tests passed!\n");
    return 0;
}
