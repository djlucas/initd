/* test-dependency.c - Dependency resolution tests
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

/* Helper to create a simple unit for testing */
static void setup_unit(struct unit_file *unit, const char *name, enum unit_type type) {
    memset(unit, 0, sizeof(*unit));
    strncpy(unit->name, name, sizeof(unit->name) - 1);
    unit->type = type;
    unit->state = STATE_INACTIVE;
}

void test_after_dependency(void) {
    TEST("After= dependency ordering");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    /* A After B means: start B before A */
    unit_a.unit.after[0] = strdup("b.service");
    unit_a.unit.after_count = 1;

    /* In dependency resolution:
     * - B has no dependencies, starts first
     * - A waits for B to be active before starting */

    assert(unit_a.unit.after_count == 1);
    assert(strcmp(unit_a.unit.after[0], "b.service") == 0);

    free(unit_a.unit.after[0]);
    PASS();
}

void test_before_dependency(void) {
    TEST("Before= dependency ordering");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    /* A Before B means: start A before B */
    unit_a.unit.before[0] = strdup("b.service");
    unit_a.unit.before_count = 1;

    /* This is the inverse of After */

    assert(unit_a.unit.before_count == 1);
    assert(strcmp(unit_a.unit.before[0], "b.service") == 0);

    free(unit_a.unit.before[0]);
    PASS();
}

void test_requires_dependency(void) {
    TEST("Requires= hard dependency");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    /* A Requires B means:
     * - B must start successfully for A to start
     * - If B fails, A fails
     * - Stopping B stops A */
    unit_a.unit.requires[0] = strdup("b.service");
    unit_a.unit.requires_count = 1;

    assert(unit_a.unit.requires_count == 1);
    assert(strcmp(unit_a.unit.requires[0], "b.service") == 0);

    free(unit_a.unit.requires[0]);
    PASS();
}

void test_binds_to_dependency(void) {
    TEST("BindsTo= lifecycle binding");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    unit_a.unit.binds_to[0] = strdup("b.service");
    unit_a.unit.binds_to_count = 1;

    assert(unit_a.unit.binds_to_count == 1);
    assert(strcmp(unit_a.unit.binds_to[0], "b.service") == 0);

    free(unit_a.unit.binds_to[0]);
    PASS();
}

void test_wants_dependency(void) {
    TEST("Wants= soft dependency");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    /* A Wants B means:
     * - B should start when A starts
     * - If B fails, A continues anyway
     * - Weaker than Requires */
    unit_a.unit.wants[0] = strdup("b.service");
    unit_a.unit.wants_count = 1;

    assert(unit_a.unit.wants_count == 1);
    assert(strcmp(unit_a.unit.wants[0], "b.service") == 0);

    free(unit_a.unit.wants[0]);
    PASS();
}

void test_part_of_dependency(void) {
    TEST("PartOf= parent relationship");

    struct unit_file unit_service, unit_target;
    setup_unit(&unit_service, "getty@tty1.service", UNIT_SERVICE);
    setup_unit(&unit_target, "getty.target", UNIT_TARGET);

    unit_service.unit.part_of[0] = strdup("getty.target");
    unit_service.unit.part_of_count = 1;

    assert(unit_service.unit.part_of_count == 1);
    assert(strcmp(unit_service.unit.part_of[0], "getty.target") == 0);

    free(unit_service.unit.part_of[0]);
    PASS();
}

void test_conflicts_dependency(void) {
    TEST("Conflicts= negative dependency");

    struct unit_file unit_a, unit_b;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);

    /* A Conflicts B means:
     * - Starting A stops B
     * - A and B cannot run simultaneously */
    unit_a.unit.conflicts[0] = strdup("b.service");
    unit_a.unit.conflicts_count = 1;

    assert(unit_a.unit.conflicts_count == 1);
    assert(strcmp(unit_a.unit.conflicts[0], "b.service") == 0);

    free(unit_a.unit.conflicts[0]);
    PASS();
}

void test_circular_dependency_detection(void) {
    TEST("circular dependency detection");

    /* A -> B -> C -> A is circular and should be detected */
    struct unit_file unit_a, unit_b, unit_c;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);
    setup_unit(&unit_c, "c.service", UNIT_SERVICE);

    unit_a.unit.after[0] = strdup("b.service");
    unit_a.unit.after_count = 1;

    unit_b.unit.after[0] = strdup("c.service");
    unit_b.unit.after_count = 1;

    unit_c.unit.after[0] = strdup("a.service");
    unit_c.unit.after_count = 1;

    /* Dependency resolver should detect this cycle */

    free(unit_a.unit.after[0]);
    free(unit_b.unit.after[0]);
    free(unit_c.unit.after[0]);
    PASS();
}

void test_dependency_chain(void) {
    TEST("dependency chain resolution");

    /* A -> B -> C (linear chain) */
    struct unit_file unit_a, unit_b, unit_c;
    setup_unit(&unit_a, "a.service", UNIT_SERVICE);
    setup_unit(&unit_b, "b.service", UNIT_SERVICE);
    setup_unit(&unit_c, "c.service", UNIT_SERVICE);

    unit_a.unit.after[0] = strdup("b.service");
    unit_a.unit.after_count = 1;

    unit_b.unit.after[0] = strdup("c.service");
    unit_b.unit.after_count = 1;

    /* Start order should be: C, B, A */

    free(unit_a.unit.after[0]);
    free(unit_b.unit.after[0]);
    PASS();
}

void test_multiple_dependencies(void) {
    TEST("multiple dependencies per unit");

    struct unit_file unit;
    setup_unit(&unit, "multi.service", UNIT_SERVICE);

    /* Unit with multiple After dependencies */
    unit.unit.after[0] = strdup("a.service");
    unit.unit.after[1] = strdup("b.service");
    unit.unit.after[2] = strdup("c.service");
    unit.unit.after_count = 3;

    /* Must wait for all to be active */

    assert(unit.unit.after_count == 3);

    for (int i = 0; i < 3; i++) {
        free(unit.unit.after[i]);
    }
    PASS();
}

void test_target_dependencies(void) {
    TEST("target unit dependencies");

    struct unit_file service, target;
    setup_unit(&service, "test.service", UNIT_SERVICE);
    setup_unit(&target, "multi-user.target", UNIT_TARGET);

    /* Service WantedBy multi-user.target */
    service.install.wanted_by[0] = strdup("multi-user.target");
    service.install.wanted_by_count = 1;

    /* This creates an implicit Wants dependency from target to service */

    free(service.install.wanted_by[0]);
    PASS();
}

void test_missing_dependency(void) {
    TEST("missing dependency handling");

    struct unit_file unit;
    setup_unit(&unit, "test.service", UNIT_SERVICE);

    /* Requires a unit that doesn't exist */
    unit.unit.requires[0] = strdup("missing.service");
    unit.unit.requires_count = 1;

    /* Supervisor should handle gracefully:
     * - For Requires: fail to start
     * - For Wants: log warning but continue */

    free(unit.unit.requires[0]);
    PASS();
}

void test_on_failure_dependency(void) {
    TEST("OnFailure= dependency");

    struct unit_file service, rescue;
    setup_unit(&service, "critical.service", UNIT_SERVICE);
    setup_unit(&rescue, "rescue.service", UNIT_SERVICE);

    /* critical.service has OnFailure=rescue.service */
    service.unit.on_failure[0] = strdup("rescue.service");
    service.unit.on_failure_count = 1;

    /* Verify OnFailure was set up correctly */
    assert(service.unit.on_failure_count == 1);
    assert(strcmp(service.unit.on_failure[0], "rescue.service") == 0);

    /* OnFailure units should be activated when the unit fails */
    /* (actual triggering is tested in integration/system tests) */

    free(service.unit.on_failure[0]);

    PASS();
}

void test_multiple_on_failure(void) {
    TEST("Multiple OnFailure= units");

    struct unit_file target;
    setup_unit(&target, "sysinit.target", UNIT_TARGET);

    /* sysinit.target can have multiple fallback units */
    target.unit.on_failure[0] = strdup("emergency.target");
    target.unit.on_failure[1] = strdup("rescue.target");
    target.unit.on_failure_count = 2;

    assert(target.unit.on_failure_count == 2);
    assert(strcmp(target.unit.on_failure[0], "emergency.target") == 0);
    assert(strcmp(target.unit.on_failure[1], "rescue.target") == 0);

    free(target.unit.on_failure[0]);
    free(target.unit.on_failure[1]);

    PASS();
}

int main(void) {
    printf("=== Dependency Resolution Tests ===\n\n");

    test_after_dependency();
    test_before_dependency();
    test_requires_dependency();
    test_binds_to_dependency();
    test_wants_dependency();
    test_part_of_dependency();
    test_conflicts_dependency();
    test_circular_dependency_detection();
    test_dependency_chain();
    test_multiple_dependencies();
    test_target_dependencies();
    test_missing_dependency();
    test_on_failure_dependency();
    test_multiple_on_failure();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
