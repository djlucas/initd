/* test-service-features.c - Test PrivateTmp, LimitNOFILE, KillMode
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include "../src/common/unit.h"
#include "../src/common/parser.h"

/* Test parsing PrivateTmp */
static void test_parse_private_tmp(void) {
    struct unit_file unit = {0};

    /* Create temp file with PrivateTmp=true */
    FILE *f = fopen("/tmp/test-privatetmp.service", "w");
    assert(f != NULL);
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Test PrivateTmp\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "Type=simple\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "PrivateTmp=true\n");
    fclose(f);

    assert(parse_unit_file("/tmp/test-privatetmp.service", &unit) == 0);
    assert(unit.config.service.private_tmp == true);

    /* Test false */
    f = fopen("/tmp/test-privatetmp2.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "PrivateTmp=false\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-privatetmp2.service", &unit) == 0);
    assert(unit.config.service.private_tmp == false);

    printf("✓ PrivateTmp parsing works\n");
}

/* Test parsing LimitNOFILE */
static void test_parse_limit_nofile(void) {
    struct unit_file unit = {0};

    /* Test numeric value */
    FILE *f = fopen("/tmp/test-limitnofile.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "LimitNOFILE=65536\n");
    fclose(f);

    assert(parse_unit_file("/tmp/test-limitnofile.service", &unit) == 0);
    assert(unit.config.service.limit_nofile == 65536);

    /* Test infinity */
    f = fopen("/tmp/test-limitnofile2.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "LimitNOFILE=infinity\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-limitnofile2.service", &unit) == 0);
    assert(unit.config.service.limit_nofile == 0); /* 0 = infinity */

    /* Test default (not set) */
    f = fopen("/tmp/test-limitnofile3.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-limitnofile3.service", &unit) == 0);
    assert(unit.config.service.limit_nofile == -1); /* -1 = not set */

    printf("✓ LimitNOFILE parsing works\n");
}

/* Test parsing KillMode */
static void test_parse_kill_mode(void) {
    struct unit_file unit = {0};

    /* Test process mode */
    FILE *f = fopen("/tmp/test-killmode.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "KillMode=process\n");
    fclose(f);

    assert(parse_unit_file("/tmp/test-killmode.service", &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_PROCESS);

    /* Test control-group mode */
    f = fopen("/tmp/test-killmode2.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "KillMode=control-group\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-killmode2.service", &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_CONTROL_GROUP);

    /* Test mixed mode */
    f = fopen("/tmp/test-killmode3.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "KillMode=mixed\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-killmode3.service", &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_MIXED);

    /* Test none mode */
    f = fopen("/tmp/test-killmode4.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "KillMode=none\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-killmode4.service", &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_NONE);

    /* Test default (should be process) */
    f = fopen("/tmp/test-killmode5.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fclose(f);

    memset(&unit, 0, sizeof(unit));
    assert(parse_unit_file("/tmp/test-killmode5.service", &unit) == 0);
    assert(unit.config.service.kill_mode == KILL_PROCESS); /* Default */

    printf("✓ KillMode parsing works\n");
}

/* Test all features together */
static void test_combined_features(void) {
    struct unit_file unit = {0};

    FILE *f = fopen("/tmp/test-combined.service", "w");
    assert(f != NULL);
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "PrivateTmp=true\n");
    fprintf(f, "LimitNOFILE=infinity\n");
    fprintf(f, "KillMode=control-group\n");
    fclose(f);

    assert(parse_unit_file("/tmp/test-combined.service", &unit) == 0);
    assert(unit.config.service.private_tmp == true);
    assert(unit.config.service.limit_nofile == 0); /* infinity */
    assert(unit.config.service.kill_mode == KILL_CONTROL_GROUP);

    printf("✓ Combined features parsing works\n");
}

int main(void) {
    printf("Testing service features (PrivateTmp, LimitNOFILE, KillMode)...\n");

    test_parse_private_tmp();
    test_parse_limit_nofile();
    test_parse_kill_mode();
    test_combined_features();

    printf("\n✓ All service feature tests passed!\n");
    return 0;
}
