/* test-service-features.c - Test PrivateTmp, Limit* directives, KillMode
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
#include <syslog.h>
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

/* Test parsing all Limit* directives */
static void test_parse_all_limits(void) {
    struct unit_file unit = {0};

    /* Test all limit directives with numeric values */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "LimitCPU=300\n"
        "LimitFSIZE=1073741824\n"
        "LimitDATA=536870912\n"
        "LimitSTACK=8388608\n"
        "LimitCORE=0\n"
        "LimitRSS=268435456\n"
        "LimitAS=1073741824\n"
        "LimitNPROC=512\n"
        "LimitMEMLOCK=65536\n"
        "LimitLOCKS=1024\n"
        "LimitSIGPENDING=4096\n"
        "LimitMSGQUEUE=819200\n"
        "LimitNICE=0\n"
        "LimitRTPRIO=50\n"
        "LimitRTTIME=1000000\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.limit_cpu == 300);
    assert(unit.config.service.limit_fsize == 1073741824);
    assert(unit.config.service.limit_data == 536870912);
    assert(unit.config.service.limit_stack == 8388608);
    assert(unit.config.service.limit_core == 0);
    assert(unit.config.service.limit_rss == 268435456);
    assert(unit.config.service.limit_as == 1073741824);
    assert(unit.config.service.limit_nproc == 512);
    assert(unit.config.service.limit_memlock == 65536);
    assert(unit.config.service.limit_locks == 1024);
    assert(unit.config.service.limit_sigpending == 4096);
    assert(unit.config.service.limit_msgqueue == 819200);
    assert(unit.config.service.limit_nice == 0);
    assert(unit.config.service.limit_rtprio == 50);
    assert(unit.config.service.limit_rttime == 1000000);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test infinity values */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "LimitCPU=infinity\n"
        "LimitFSIZE=infinity\n"
        "LimitCORE=infinity\n"
        "LimitAS=infinity\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.limit_cpu == 0);     /* 0 = infinity */
    assert(unit.config.service.limit_fsize == 0);
    assert(unit.config.service.limit_core == 0);
    assert(unit.config.service.limit_as == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default values (not set) */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.limit_cpu == -1);    /* -1 = not set */
    assert(unit.config.service.limit_fsize == -1);
    assert(unit.config.service.limit_data == -1);
    assert(unit.config.service.limit_stack == -1);
    assert(unit.config.service.limit_core == -1);
    assert(unit.config.service.limit_rss == -1);
    assert(unit.config.service.limit_as == -1);
    assert(unit.config.service.limit_nproc == -1);
    assert(unit.config.service.limit_memlock == -1);
    assert(unit.config.service.limit_locks == -1);
    assert(unit.config.service.limit_sigpending == -1);
    assert(unit.config.service.limit_msgqueue == -1);
    assert(unit.config.service.limit_nice == -1);
    assert(unit.config.service.limit_rtprio == -1);
    assert(unit.config.service.limit_rttime == -1);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ All Limit* directives parsing works\n");
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

    /* Test StandardOutput=journal (systemd compat - maps to STDIO_INHERIT) */
    memset(&unit, 0, sizeof(unit));
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardOutput=journal\n"
    );
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.standard_output == STDIO_INHERIT);
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    /* Test StandardOutput=syslog (maps to STDIO_INHERIT) */
    memset(&unit, 0, sizeof(unit));
    char *path5 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardOutput=syslog\n"
    );
    assert(parse_unit_file(path5, &unit) == 0);
    assert(unit.config.service.standard_output == STDIO_INHERIT);
    free_unit_file(&unit);
    cleanup_temp_file(path5);

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

/* Test StandardInput/Output/Error=file:path */
static void test_stdio_file(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardInput=file:/tmp/input.txt\n"
        "StandardOutput=file:/var/log/output.log\n"
        "StandardError=file:/var/log/error.log\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_FILE);
    assert(unit.config.service.standard_output == STDIO_FILE);
    assert(unit.config.service.standard_error == STDIO_FILE);
    assert(strcmp(unit.config.service.input_file, "/tmp/input.txt") == 0);
    assert(strcmp(unit.config.service.output_file, "/var/log/output.log") == 0);
    assert(strcmp(unit.config.service.error_file, "/var/log/error.log") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ StandardInput/Output/Error=file:path parsing works\n");
}

/* Test StandardInput/Output/Error=socket */
static void test_stdio_socket(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=socket\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_SOCKET);
    assert(unit.config.service.standard_output == STDIO_SOCKET);
    assert(unit.config.service.standard_error == STDIO_SOCKET);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ StandardInput/Output/Error=socket parsing works\n");
}

/* Test StandardInput=data with StandardInputText= */
static void test_stdio_data_text(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/cat\n"
        "StandardInput=data\n"
        "StandardInputText=Hello World\n"
        "StandardInputText=Second line\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_DATA);
    assert(unit.config.service.input_data != NULL);
    assert(unit.config.service.input_data_size > 0);
    /* Check that the data contains both lines with newlines */
    assert(strstr(unit.config.service.input_data, "Hello World\n") != NULL);
    assert(strstr(unit.config.service.input_data, "Second line\n") != NULL);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ StandardInput=data with StandardInputText= parsing works\n");
}

/* Test StandardInput=data with StandardInputData= (base64) */
static void test_stdio_data_base64(void) {
    struct unit_file unit = {0};

    /* "Hello World\n" in base64 is "SGVsbG8gV29ybGQK" */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/cat\n"
        "StandardInput=data\n"
        "StandardInputData=SGVsbG8gV29ybGQK\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.standard_input == STDIO_DATA);
    assert(unit.config.service.input_data != NULL);
    assert(unit.config.service.input_data_size == 12); /* "Hello World\n" */
    assert(memcmp(unit.config.service.input_data, "Hello World\n", 12) == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ StandardInput=data with StandardInputData= (base64) parsing works\n");
}

/* Test Syslog directives */
static void test_syslog_directives(void) {
    struct unit_file unit = {0};

    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "SyslogIdentifier=my-service\n"
        "SyslogFacility=daemon\n"
        "SyslogLevel=info\n"
        "SyslogLevelPrefix=yes\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(strcmp(unit.config.service.syslog_identifier, "my-service") == 0);
    assert(unit.config.service.syslog_facility == LOG_DAEMON);
    assert(unit.config.service.syslog_level == LOG_INFO);
    assert(unit.config.service.syslog_level_prefix == true);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    printf("✓ Syslog directives parsing works\n");
}

/* Test UMask */
static void test_umask_directive(void) {
    struct unit_file unit = {0};

    /* Test octal umask */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "UMask=0022\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.umask_value == 0022);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test another umask value */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "UMask=0077\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.umask_value == 0077);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    printf("✓ UMask directive parsing works\n");
}

/* Test NoNewPrivileges */
static void test_no_new_privs_directive(void) {
    struct unit_file unit = {0};

    /* Test NoNewPrivileges=true */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "NoNewPrivileges=true\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.no_new_privs == true);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test NoNewPrivileges=false (default) */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "NoNewPrivileges=false\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.no_new_privs == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test NoNewPrivileges=yes */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "NoNewPrivileges=yes\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.no_new_privs == true);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ NoNewPrivileges directive parsing works\n");
}

/* Test RootDirectory */
static void test_root_directory_directive(void) {
    struct unit_file unit = {0};

    /* Test absolute path */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RootDirectory=/var/chroot/myservice\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(strcmp(unit.config.service.root_directory, "/var/chroot/myservice") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test another path */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RootDirectory=/srv/jail\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(strcmp(unit.config.service.root_directory, "/srv/jail") == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test empty (default) */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.root_directory[0] == '\0');
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ RootDirectory directive parsing works\n");
}

/* Test MemoryLimit */
static void test_memory_limit_directive(void) {
    struct unit_file unit = {0};

    /* Test numeric value */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "MemoryLimit=1073741824\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.memory_limit == 1073741824);  /* 1 GB */
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test infinity */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "MemoryLimit=infinity\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.memory_limit == 0);  /* 0 = unlimited */
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default (not set) */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.memory_limit == -1);  /* -1 = not set */
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ MemoryLimit directive parsing works\n");
}

/* Test RestrictSUIDSGID */
static void test_restrict_suid_sgid_directive(void) {
    struct unit_file unit = {0};

    /* Test default (false) */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.restrict_suid_sgid == false);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test RestrictSUIDSGID=no */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RestrictSUIDSGID=no\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.restrict_suid_sgid == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test RestrictSUIDSGID=yes */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RestrictSUIDSGID=yes\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.restrict_suid_sgid == true);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ RestrictSUIDSGID directive parsing works\n");
}

/* Test RestartMaxDelaySec */
static void test_restart_max_delay_sec_directive(void) {
    struct unit_file unit = {0};

    /* Test numeric value */
    char *path = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RestartMaxDelaySec=300\n"
    );
    assert(parse_unit_file(path, &unit) == 0);
    assert(unit.config.service.restart_max_delay_sec == 300);
    free_unit_file(&unit);
    cleanup_temp_file(path);

    /* Test another value */
    memset(&unit, 0, sizeof(unit));
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
        "RestartMaxDelaySec=60\n"
    );
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.restart_max_delay_sec == 60);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default (not set) */
    memset(&unit, 0, sizeof(unit));
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.restart_max_delay_sec == 0);  /* 0 = not set */
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ RestartMaxDelaySec directive parsing works\n");
}

/* Test TimeoutAbortSec directive */
static void test_timeout_abort_sec_directive(void) {
    struct unit_file unit = {0};
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "TimeoutAbortSec=10\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.timeout_abort_sec == 10);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "TimeoutAbortSec=0\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.timeout_abort_sec == 0);  /* 0 = use TimeoutStopSec */
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default (not set) */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.timeout_abort_sec == 0);  /* 0 = not set, use TimeoutStopSec */
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ TimeoutAbortSec directive parsing works\n");
}

/* Test TimeoutStartFailureMode directive */
static void test_timeout_start_failure_mode_directive(void) {
    struct unit_file unit = {0};

    /* Test "terminate" */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "TimeoutStartFailureMode=terminate\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.timeout_start_failure_mode == 0);  /* 0 = terminate */
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test "abort" */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "TimeoutStartFailureMode=abort\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.timeout_start_failure_mode == 1);  /* 1 = abort */
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test "kill" */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "TimeoutStartFailureMode=kill\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.timeout_start_failure_mode == 2);  /* 2 = kill */
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    /* Test default (not set) */
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.timeout_start_failure_mode == 0);  /* 0 = default (terminate) */
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    printf("✓ TimeoutStartFailureMode directive parsing works\n");
}

/* Test ProtectSystem directive */
static void test_protect_system_directive(void) {
    struct unit_file unit = {0};

    /* Test no */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ProtectSystem=no\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.protect_system == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test yes */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ProtectSystem=yes\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.protect_system == 1);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test full */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ProtectSystem=full\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.protect_system == 2);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    /* Test strict */
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ProtectSystem=strict\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.protect_system == 3);
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    /* Test default */
    char *path5 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path5, &unit) == 0);
    assert(unit.config.service.protect_system == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path5);

    printf("✓ ProtectSystem directive parsing works\n");
}

/* Test ProtectHome directive */
static void test_protect_home_directive(void) {
    struct unit_file unit = {0};

    /* Test no */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ProtectHome=no\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.protect_home == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test yes */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ProtectHome=yes\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.protect_home == 1);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test read-only */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ProtectHome=read-only\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.protect_home == 2);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    /* Test tmpfs */
    char *path4 = create_temp_unit_file(
        "[Service]\n"
        "ProtectHome=tmpfs\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path4, &unit) == 0);
    assert(unit.config.service.protect_home == 3);
    free_unit_file(&unit);
    cleanup_temp_file(path4);

    /* Test default */
    char *path5 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path5, &unit) == 0);
    assert(unit.config.service.protect_home == 0);
    free_unit_file(&unit);
    cleanup_temp_file(path5);

    printf("✓ ProtectHome directive parsing works\n");
}

/* Test PrivateDevices directive */
static void test_private_devices_directive(void) {
    struct unit_file unit = {0};

    /* Test yes */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "PrivateDevices=yes\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.private_devices == true);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test no */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "PrivateDevices=no\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.private_devices == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.private_devices == false);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ PrivateDevices directive parsing works\n");
}

/* Test ProtectKernelTunables directive */
static void test_protect_kernel_tunables_directive(void) {
    struct unit_file unit = {0};

    /* Test yes */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ProtectKernelTunables=yes\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.protect_kernel_tunables == true);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test no */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ProtectKernelTunables=no\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.protect_kernel_tunables == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.protect_kernel_tunables == false);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ ProtectKernelTunables directive parsing works\n");
}

/* Test ProtectControlGroups directive */
static void test_protect_control_groups_directive(void) {
    struct unit_file unit = {0};

    /* Test yes */
    char *path1 = create_temp_unit_file(
        "[Service]\n"
        "ProtectControlGroups=yes\n"
    );
    assert(parse_unit_file(path1, &unit) == 0);
    assert(unit.config.service.protect_control_groups == true);
    free_unit_file(&unit);
    cleanup_temp_file(path1);

    /* Test no */
    char *path2 = create_temp_unit_file(
        "[Service]\n"
        "ProtectControlGroups=no\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path2, &unit) == 0);
    assert(unit.config.service.protect_control_groups == false);
    free_unit_file(&unit);
    cleanup_temp_file(path2);

    /* Test default */
    char *path3 = create_temp_unit_file(
        "[Service]\n"
        "ExecStart=/bin/true\n"
    );
    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file(path3, &unit) == 0);
    assert(unit.config.service.protect_control_groups == false);
    free_unit_file(&unit);
    cleanup_temp_file(path3);

    printf("✓ ProtectControlGroups directive parsing works\n");
}

int main(void) {
    printf("Testing service features (PrivateTmp, Limit* directives, KillMode, RemainAfterExit, StandardInput/Output/Error, Syslog, UMask, NoNewPrivileges, RootDirectory, MemoryLimit, RestrictSUIDSGID, RestartMaxDelaySec, TimeoutAbortSec, TimeoutStartFailureMode, ProtectSystem, ProtectHome, PrivateDevices, ProtectKernelTunables, ProtectControlGroups)...\n");

    test_parse_private_tmp();
    test_parse_limit_nofile();
    test_parse_all_limits();
    test_parse_kill_mode();
    test_combined_features();
    test_parse_remain_after_exit();
    test_parse_standard_input();
    test_parse_standard_output();
    test_parse_standard_error();
    test_parse_tty_path();
    test_combined_stdio();
    test_stdio_file();
    test_stdio_socket();
    test_stdio_data_text();
    test_stdio_data_base64();
    test_syslog_directives();
    test_umask_directive();
    test_no_new_privs_directive();
    test_root_directory_directive();
    test_memory_limit_directive();
    test_restrict_suid_sgid_directive();
    test_restart_max_delay_sec_directive();
    test_timeout_abort_sec_directive();
    test_timeout_start_failure_mode_directive();
    test_protect_system_directive();
    test_protect_home_directive();
    test_private_devices_directive();
    test_protect_kernel_tunables_directive();
    test_protect_control_groups_directive();

    printf("\n✓ All service feature tests passed!\n");
    return 0;
}
