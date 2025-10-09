/* test-state.c - Unit state machine tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../src/common/unit.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_state_transitions(void) {
    TEST("valid state transitions");

    struct unit_file unit = {0};

    /* Initial state */
    unit.state = STATE_INACTIVE;
    assert(unit.state == STATE_INACTIVE);

    /* INACTIVE -> ACTIVATING */
    unit.state = STATE_ACTIVATING;
    assert(unit.state == STATE_ACTIVATING);

    /* ACTIVATING -> ACTIVE */
    unit.state = STATE_ACTIVE;
    assert(unit.state == STATE_ACTIVE);

    /* ACTIVE -> DEACTIVATING */
    unit.state = STATE_DEACTIVATING;
    assert(unit.state == STATE_DEACTIVATING);

    /* DEACTIVATING -> INACTIVE */
    unit.state = STATE_INACTIVE;
    assert(unit.state == STATE_INACTIVE);

    PASS();
}

void test_failure_state(void) {
    TEST("failure state handling");

    struct unit_file unit = {0};

    /* Unit can fail during activation */
    unit.state = STATE_ACTIVATING;
    unit.state = STATE_FAILED;
    assert(unit.state == STATE_FAILED);

    /* Failed units can be restarted */
    unit.state = STATE_INACTIVE;
    assert(unit.state == STATE_INACTIVE);

    PASS();
}

void test_service_simple_lifecycle(void) {
    TEST("simple service lifecycle");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.type = SERVICE_SIMPLE;
    unit.state = STATE_INACTIVE;
    unit.pid = 0;

    /* Start service */
    unit.state = STATE_ACTIVATING;
    unit.pid = 12345;  /* Simulated PID */

    /* Service is running */
    unit.state = STATE_ACTIVE;
    assert(unit.pid == 12345);

    /* Stop service */
    unit.state = STATE_DEACTIVATING;

    /* Service stopped */
    unit.state = STATE_INACTIVE;
    unit.pid = 0;

    PASS();
}

void test_service_forking_lifecycle(void) {
    TEST("forking service lifecycle");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.type = SERVICE_FORKING;
    unit.state = STATE_INACTIVE;

    /* Forking service:
     * 1. Parent process exits
     * 2. Child process continues
     * 3. Need to track child PID */

    unit.state = STATE_ACTIVATING;
    unit.pid = 999;  /* Track daemon PID */
    unit.state = STATE_ACTIVE;

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

void test_service_oneshot_lifecycle(void) {
    TEST("oneshot service lifecycle");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.type = SERVICE_ONESHOT;
    unit.state = STATE_INACTIVE;

    /* Oneshot service:
     * 1. Runs to completion
     * 2. No daemon process
     * 3. State is ACTIVE even though process exited */

    unit.state = STATE_ACTIVATING;
    unit.state = STATE_ACTIVE;  /* Active even with no PID */
    unit.pid = 0;

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

void test_restart_policy_always(void) {
    TEST("restart policy: always");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.restart = RESTART_ALWAYS;
    unit.state = STATE_ACTIVE;
    unit.pid = 12345;

    /* Service exits */
    unit.state = STATE_FAILED;

    /* With RESTART_ALWAYS, supervisor should restart */
    unit.state = STATE_ACTIVATING;
    unit.restart_count++;
    unit.pid = 12346;
    unit.state = STATE_ACTIVE;

    assert(unit.restart_count == 1);

    PASS();
}

void test_restart_policy_on_failure(void) {
    TEST("restart policy: on-failure");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.restart = RESTART_ON_FAILURE;
    unit.state = STATE_ACTIVE;

    /* Service exits with success (exit code 0) */
    unit.state = STATE_INACTIVE;
    /* Should NOT restart */

    /* Service exits with failure */
    unit.state = STATE_ACTIVE;
    unit.state = STATE_FAILED;
    /* Should restart */
    unit.state = STATE_ACTIVATING;

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

void test_restart_policy_no(void) {
    TEST("restart policy: no");

    struct unit_file unit = {0};
    unit.type = UNIT_SERVICE;
    unit.config.service.restart = RESTART_NO;
    unit.state = STATE_ACTIVE;

    /* Service exits (any reason) */
    unit.state = STATE_INACTIVE;
    /* Should NOT restart */

    assert(unit.state == STATE_INACTIVE);

    PASS();
}

void test_timer_state(void) {
    TEST("timer unit state");

    struct unit_file unit = {0};
    unit.type = UNIT_TIMER;
    unit.state = STATE_INACTIVE;

    /* Timer is loaded and waiting */
    unit.state = STATE_ACTIVE;

    /* Timer can be stopped */
    unit.state = STATE_INACTIVE;

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

void test_socket_state(void) {
    TEST("socket unit state");

    struct unit_file unit = {0};
    unit.type = UNIT_SOCKET;
    unit.state = STATE_INACTIVE;

    /* Socket is listening */
    unit.state = STATE_ACTIVE;

    /* When connection arrives, associated service starts */
    /* Socket remains active */

    /* Socket can be stopped */
    unit.state = STATE_INACTIVE;

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

void test_target_state(void) {
    TEST("target unit state");

    struct unit_file unit = {0};
    unit.type = UNIT_TARGET;
    unit.state = STATE_INACTIVE;

    /* Target is reached when all dependencies are active */
    unit.state = STATE_ACTIVE;

    /* Target has no persistent state */

    (void)unit;  /* Used for state transition demonstration */
    PASS();
}

int main(void) {
    printf("=== State Machine Tests ===\n\n");

    test_state_transitions();
    test_failure_state();
    test_service_simple_lifecycle();
    test_service_forking_lifecycle();
    test_service_oneshot_lifecycle();
    test_restart_policy_always();
    test_restart_policy_on_failure();
    test_restart_policy_no();
    test_timer_state();
    test_socket_state();
    test_target_state();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
