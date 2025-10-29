/* test-linux-conditions.c - Test Linux-only Condition/Assert directives
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

/* Helper to create temporary unit file */
static const char *create_temp_unit_file(const char *content) {
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/test-unit-XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);

    ssize_t written = write(fd, content, strlen(content));
    assert(written == (ssize_t)strlen(content));
    close(fd);

    return path;
}

static void cleanup_temp_file(char *path) {
    unlink(path);
}

static void test_condition_kernel_command_line(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "cmdline-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionKernelCommandLine=quiet\n"
        "AssertKernelCommandLine=root=/dev/sda1\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_KERNEL_COMMAND_LINE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "quiet") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_KERNEL_COMMAND_LINE);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "root=/dev/sda1") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionKernelCommandLine/AssertKernelCommandLine parsing works\n");
}

static void test_condition_kernel_module_loaded(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "module-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionKernelModuleLoaded=ext4\n"
        "AssertKernelModuleLoaded=loop\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_KERNEL_MODULE_LOADED);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "ext4") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_KERNEL_MODULE_LOADED);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "loop") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionKernelModuleLoaded/AssertKernelModuleLoaded parsing works\n");
}

static void test_condition_security(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "security-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionSecurity=selinux\n"
        "ConditionSecurity=apparmor\n"
        "AssertSecurity=ima\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_SECURITY);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "selinux") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_SECURITY);
    assert(strcmp(unit.unit.conditions[1].value, "apparmor") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_SECURITY);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "ima") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionSecurity/AssertSecurity parsing works\n");
}

static void test_condition_capability(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "capability-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionCapability=CAP_NET_ADMIN\n"
        "AssertCapability=CAP_SYS_ADMIN\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_CAPABILITY);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "CAP_NET_ADMIN") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_CAPABILITY);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "CAP_SYS_ADMIN") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionCapability/AssertCapability parsing works\n");
}

static void test_condition_cgroup_controller(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "cgroup-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionControlGroupController=cpu\n"
        "ConditionControlGroupController=memory\n"
        "AssertControlGroupController=pids\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_CONTROL_GROUP_CONTROLLER);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "cpu") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_CONTROL_GROUP_CONTROLLER);
    assert(strcmp(unit.unit.conditions[1].value, "memory") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_CONTROL_GROUP_CONTROLLER);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "pids") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionControlGroupController/AssertControlGroupController parsing works\n");
}

static void test_condition_pressure(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "pressure-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionMemoryPressure=10%\n"
        "ConditionCPUPressure=5%\n"
        "ConditionIOPressure=20%\n"
        "AssertMemoryPressure=50%\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 4);

    assert(unit.unit.conditions[0].type == CONDITION_MEMORY_PRESSURE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "10%") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_CPU_PRESSURE);
    assert(strcmp(unit.unit.conditions[1].value, "5%") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_IO_PRESSURE);
    assert(strcmp(unit.unit.conditions[2].value, "20%") == 0);

    assert(unit.unit.conditions[3].type == CONDITION_MEMORY_PRESSURE);
    assert(unit.unit.conditions[3].is_assert == true);
    assert(strcmp(unit.unit.conditions[3].value, "50%") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ Condition*Pressure/Assert*Pressure parsing works\n");
}

static void test_condition_path_is_encrypted(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "encrypted-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionPathIsEncrypted=/home\n"
        "AssertPathIsEncrypted=/var\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_PATH_IS_ENCRYPTED);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "/home") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_PATH_IS_ENCRYPTED);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "/var") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionPathIsEncrypted/AssertPathIsEncrypted parsing works\n");
}

static void test_condition_firmware(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "firmware-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionFirmware=uefi\n"
        "AssertFirmware=device-tree\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_FIRMWARE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "uefi") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_FIRMWARE);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "device-tree") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionFirmware/AssertFirmware parsing works\n");
}

static void test_condition_cpu_feature(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "cpufeature-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionCPUFeature=sse4_2\n"
        "ConditionCPUFeature=avx2\n"
        "AssertCPUFeature=aes\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 3);

    assert(unit.unit.conditions[0].type == CONDITION_CPU_FEATURE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "sse4_2") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_CPU_FEATURE);
    assert(strcmp(unit.unit.conditions[1].value, "avx2") == 0);

    assert(unit.unit.conditions[2].type == CONDITION_CPU_FEATURE);
    assert(unit.unit.conditions[2].is_assert == true);
    assert(strcmp(unit.unit.conditions[2].value, "aes") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionCPUFeature/AssertCPUFeature parsing works\n");
}

static void test_condition_version(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "version-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionVersion=>=245\n"
        "AssertVersion=<300\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_VERSION);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, ">=245") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_VERSION);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "<300") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionVersion/AssertVersion parsing works\n");
}

static void test_condition_credential(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "credential-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionCredential=my-credential\n"
        "AssertCredential=required-cred\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_CREDENTIAL);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "my-credential") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_CREDENTIAL);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "required-cred") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionCredential/AssertCredential parsing works\n");
}

static void test_condition_needs_update(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "needsupdate-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionNeedsUpdate=/etc\n"
        "AssertNeedsUpdate=/var\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_NEEDS_UPDATE);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "/etc") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_NEEDS_UPDATE);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "/var") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionNeedsUpdate/AssertNeedsUpdate parsing works\n");
}

static void test_condition_first_boot(void) {
    struct unit_file unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.name, "firstboot-test.service", sizeof(unit.name));
    unit.type = UNIT_SERVICE;

    const char *path = create_temp_unit_file(
        "[Unit]\n"
        "ConditionFirstBoot=yes\n"
        "AssertFirstBoot=no\n"
        "\n"
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );

    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.unit.condition_count == 2);

    assert(unit.unit.conditions[0].type == CONDITION_FIRST_BOOT);
    assert(unit.unit.conditions[0].is_assert == false);
    assert(strcmp(unit.unit.conditions[0].value, "yes") == 0);

    assert(unit.unit.conditions[1].type == CONDITION_FIRST_BOOT);
    assert(unit.unit.conditions[1].is_assert == true);
    assert(strcmp(unit.unit.conditions[1].value, "no") == 0);

    free_unit_file(&unit);
    cleanup_temp_file((char *)path);

    printf("✓ ConditionFirstBoot/AssertFirstBoot parsing works\n");
}

int main(void) {
    printf("Testing Linux-only Condition*/Assert* directives...\n");

    test_condition_kernel_command_line();
    test_condition_kernel_module_loaded();
    test_condition_security();
    test_condition_capability();
    test_condition_cgroup_controller();
    test_condition_pressure();
    test_condition_path_is_encrypted();
    test_condition_firmware();
    test_condition_cpu_feature();
    test_condition_version();
    test_condition_credential();
    test_condition_needs_update();
    test_condition_first_boot();

    printf("\n✓ All Linux-only condition/assert tests passed!\n");
    return 0;
}
