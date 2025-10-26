/* test-service-features.c - Test PrivateTmp, LimitNOFILE, KillMode
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include <unistd.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

/* Helper to create unique temp files */
static char *create_temp_unit_file(const char *content) {
    static char template[] = "/tmp/test-service-XXXXXX.service";
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
static void cleanup_temp_file(char *path) {
    if (path) {
        unlink(path);
        free(path);
    }
}

/* Test parsing PrivateTmp */
static void test_parse_private_tmp(void) {
    struct unit_file unit = {0};

    /* Test PrivateTmp=true */
    char *path1 = create_temp_unit_file(
        "[Unit]\n"
        "Description=Test PrivateTmp\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/true\n"
        "PrivateTmp=true\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.private_tmp == true);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test PrivateTmp=false */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "PrivateTmp=false\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.private_tmp == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    printf("✓ PrivateTmp parsing works\n");
}

/* Test parsing LimitNOFILE */
static void test_parse_limit_nofile(void) {
    struct unit_file unit = {0};

    /* Test numeric value */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "LimitNOFILE=65536\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.limit_nofile == 65536);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test infinity */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "LimitNOFILE=infinity\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.limit_nofile == 0); /* 0 = infinity */
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default (not set) */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.limit_nofile == -1); /* -1 = not set */
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ LimitNOFILE parsing works\n");
}

/* Test parsing KillMode */
static void test_parse_kill_mode(void) {
    struct unit_file unit = {0};

    /* Test process mode */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "KillMode=process\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_PROCESS);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test control-group mode */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "KillMode=control-group\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_CONTROL_GROUP);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test mixed mode */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "KillMode=mixed\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_MIXED);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    /* Test none mode */
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "KillMode=none\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_NONE);
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    /* Test default (should be process) */
    char *path5 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path5, &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_PROCESS); /* Default */
    free_unit_file(&unit);
    cleanup_temp_file(path5);

    printf("✓ KillMode parsing works\n");
}

/* Test all features together */
static void test_combined_features(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "PrivateTmp=true\n"
        "LimitNOFILE=infinity\n"
        "KillMode=control-group\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.private_tmp == true);
    assert(unit.config.service.limit_nofile == 0); /* infinity */
    assert(unit.config.service.kill_mode == KILL_CONTROL_GROUP);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ Combined features parsing works\n");
}

/* Test parsing RemainAfterExit */
static void test_parse_remain_after_exit(void) {
    struct unit_file unit = {0};

    /* Test RemainAfterExit=yes */
    char *path1 = create_temp_unit_file(
        "[Unit]\n"
        "Description=Test RemainAfterExit\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/bin/true\n"
        "RemainAfterExit=yes\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.remain_after_exit == true);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test RemainAfterExit=no */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RemainAfterExit=no\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.remain_after_exit == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default (RemainAfterExit not specified) */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.remain_after_exit == false);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ RemainAfterExit parsing works\n");
}

/* Test parsing StandardInput */
static void test_parse_standard_input(void) {
    struct unit_file unit = {0};

    /* Test StandardInput=null */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardInput=null\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_NULL);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test StandardInput=tty */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardInput=tty\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_TTY);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test StandardInput=tty-force */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardInput=tty-force\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_TTY_FORCE);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    /* Test default (inherit) */
    memset(&unit, 0, sizeof(unit));
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_INHERIT);
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    printf("✓ StandardInput parsing works\n");
}

/* Test parsing StandardOutput */
static void test_parse_standard_output(void) {
    struct unit_file unit = {0};

    /* Test StandardOutput=null */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardOutput=null\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.standard_output == STDIO_NULL);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test StandardOutput=tty */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardOutput=tty\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.standard_output == STDIO_TTY);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test StandardOutput=inherit */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardOutput=inherit\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.standard_output == STDIO_INHERIT);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ StandardOutput parsing works\n");
}

/* Test parsing StandardError */
static void test_parse_standard_error(void) {
    struct unit_file unit = {0};

    /* Test StandardError=null */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardError=null\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.standard_error == STDIO_NULL);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test StandardError=tty */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardError=tty\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.standard_error == STDIO_TTY);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    printf("✓ StandardError parsing works\n");
}

/* Test parsing TTYPath */
static void test_parse_tty_path(void) {
    struct unit_file unit = {0};

    /* Test TTYPath with /dev/console */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "TTYPath=/dev/console\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(strcmp(unit.config.service.tty_path, "/dev/console") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test TTYPath with /dev/tty1 */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "TTYPath=/dev/tty1\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(strcmp(unit.config.service.tty_path, "/dev/tty1") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    printf("✓ TTYPath parsing works\n");
}

/* Test combined StandardInput/Output/Error with TTYPath */
static void test_combined_stdio(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/sbin/sulogin\n"
        "StandardInput=tty-force\n"
        "StandardOutput=tty\n"
        "StandardError=tty\n"
        "TTYPath=/dev/console\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_TTY_FORCE);
    assert(unit.config.service.standard_output == STDIO_TTY);
    assert(unit.config.service.standard_error == STDIO_TTY);
    assert(strcmp(unit.config.service.tty_path, "/dev/console") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ Combined StandardInput/Output/Error with TTYPath parsing works\n");
}

int main(void) {
    printf("Testing service features (PrivateTmp, LimitNOFILE, KillMode, RemainAfterExit, StandardInput/Output/Error)...\n");

    test_parse_private_tmp();
    test_parse_limit_nofile();
    test_parse_kill_mode();
    test_combined_features();
    test_parse_remain_after_exit();
    test_parse_standard_input();
    test_parse_standard_output();
    test_parse_standard_error();
    test_parse_tty_path();
    test_combined_stdio();

    printf("\n✓ All service feature tests passed!\n");
    return 0;
}
