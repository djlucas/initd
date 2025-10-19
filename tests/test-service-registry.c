/* test-service-registry.c - Service registry tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "../src/supervisor/service-registry.h"
#include "../src/common/unit.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_register_service(void) {
    TEST("register service");

    service_registry_init();

    /* Register a service */
    int result = register_service(1234, "test.service", NULL, KILL_CONTROL_GROUP);
    assert(result == 0);

    /* Verify count */
    assert(service_registry_count() == 1);

    PASS();
}

void test_lookup_service(void) {
    TEST("lookup service");

    service_registry_init();

    /* Register a service */
    register_service(5678, "lookup-test.service", NULL, KILL_PROCESS);

    /* Lookup the service */
    struct service_record *svc = lookup_service(5678);
    assert(svc != NULL);
    assert(svc->pid == 5678);
    assert(svc->pgid == 5678);
    assert(svc->kill_mode == KILL_PROCESS);
    assert(strcmp(svc->unit_name, "lookup-test.service") == 0);

    PASS();
}

void test_lookup_nonexistent(void) {
    TEST("lookup nonexistent service");

    service_registry_init();

    /* Register a service */
    register_service(1111, "exists.service", NULL, KILL_PROCESS);

    /* Lookup a different PID */
    struct service_record *svc = lookup_service(9999);
    assert(svc == NULL);

    PASS();
}

void test_unregister_service(void) {
    TEST("unregister service");

    service_registry_init();

    /* Register two services */
    register_service(1000, "service1.service", NULL, KILL_PROCESS);
    register_service(2000, "service2.service", NULL, KILL_CONTROL_GROUP);
    assert(service_registry_count() == 2);

    /* Unregister the first one */
    unregister_service(1000);
    assert(service_registry_count() == 1);

    /* Verify it's gone */
    assert(lookup_service(1000) == NULL);

    /* Verify the second one is still there */
    struct service_record *svc = lookup_service(2000);
    assert(svc != NULL);
    assert(strcmp(svc->unit_name, "service2.service") == 0);

    PASS();
}

void test_unregister_nonexistent(void) {
    TEST("unregister nonexistent service");

    service_registry_init();

    /* Unregister a service that doesn't exist - should not crash */
    unregister_service(12345);

    /* Registry should be empty */
    assert(service_registry_count() == 0);

    PASS();
}

void test_multiple_services(void) {
    TEST("multiple services");

    service_registry_init();

    /* Register multiple services */
    for (int i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "service%d.service", i);
        int result = register_service(1000 + i, name, NULL, KILL_PROCESS);
        assert(result == 0);
    }

    assert(service_registry_count() == 10);

    /* Verify all can be looked up */
    for (int i = 0; i < 10; i++) {
        struct service_record *svc = lookup_service(1000 + i);
        assert(svc != NULL);
        assert(svc->pid == 1000 + i);
    }

    /* Unregister some */
    unregister_service(1003);
    unregister_service(1007);
    assert(service_registry_count() == 8);

    /* Verify unregistered ones are gone */
    assert(lookup_service(1003) == NULL);
    assert(lookup_service(1007) == NULL);

    /* Verify others still exist */
    assert(lookup_service(1000) != NULL);
    assert(lookup_service(1009) != NULL);

    PASS();
}

void test_registry_full(void) {
    TEST("registry full");

    service_registry_init();

    /* Fill the registry */
    int i;
    for (i = 0; i < MAX_SERVICES; i++) {
        char name[64];
        snprintf(name, sizeof(name), "service%d.service", i);
        int result = register_service(10000 + i, name, NULL, KILL_PROCESS);
        assert(result == 0);
    }

    assert(service_registry_count() == MAX_SERVICES);

    /* Try to add one more - should fail */
    int result = register_service(99999, "overflow.service", NULL, KILL_PROCESS);
    assert(result == -1);

    /* Count should still be MAX_SERVICES */
    assert(service_registry_count() == MAX_SERVICES);

    /* Unregister one */
    unregister_service(10000);
    assert(service_registry_count() == MAX_SERVICES - 1);

    /* Now we should be able to add one */
    result = register_service(99999, "now-fits.service", NULL, KILL_PROCESS);
    assert(result == 0);
    assert(service_registry_count() == MAX_SERVICES);

    PASS();
}

void test_reregister_same_pid(void) {
    TEST("reregister same PID");

    service_registry_init();

    /* Register a service */
    register_service(3000, "original.service", NULL, KILL_PROCESS);

    /* Try to register with the same PID - will create a second entry
     * (this is intentional - PIDs can be reused by OS) */
    register_service(3000, "duplicate.service", NULL, KILL_CONTROL_GROUP);

    /* Should have 2 entries */
    assert(service_registry_count() == 2);

    /* Lookup will return the first match */
    struct service_record *svc = lookup_service(3000);
    assert(svc != NULL);
    assert(strcmp(svc->unit_name, "original.service") == 0);

    PASS();
}

void test_kill_modes(void) {
    TEST("different kill modes");

    service_registry_init();

    /* Register services with different kill modes */
    register_service(4001, "none.service", NULL, KILL_NONE);
    register_service(4002, "process.service", NULL, KILL_PROCESS);
    register_service(4003, "group.service", NULL, KILL_CONTROL_GROUP);
    register_service(4004, "mixed.service", NULL, KILL_MIXED);

    /* Verify kill modes are preserved */
    assert(lookup_service(4001)->kill_mode == KILL_NONE);
    assert(lookup_service(4002)->kill_mode == KILL_PROCESS);
    assert(lookup_service(4003)->kill_mode == KILL_CONTROL_GROUP);
    assert(lookup_service(4004)->kill_mode == KILL_MIXED);

    PASS();
}

void test_long_unit_name(void) {
    TEST("long unit name truncation");

    service_registry_init();

    /* Create a very long unit name */
    char long_name[512];
    memset(long_name, 'x', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    /* Register with long name */
    register_service(5000, long_name, NULL, KILL_PROCESS);

    /* Lookup and verify it was truncated but still stored */
    struct service_record *svc = lookup_service(5000);
    assert(svc != NULL);
    assert(strlen(svc->unit_name) < sizeof(long_name));
    assert(strlen(svc->unit_name) == 255);  /* MAX - 1 for NUL */

    PASS();
}

/* DoS Prevention Tests */

void test_lookup_by_name(void) {
    TEST("lookup service by name");

    service_registry_init();

    /* Register some services */
    register_service(6001, "webapp.service", NULL, KILL_PROCESS);
    register_service(6002, "database.service", NULL, KILL_CONTROL_GROUP);

    /* Lookup by name */
    struct service_record *svc = lookup_service_by_name("webapp.service");
    assert(svc != NULL);
    assert(svc->pid == 6001);
    assert(strcmp(svc->unit_name, "webapp.service") == 0);

    svc = lookup_service_by_name("database.service");
    assert(svc != NULL);
    assert(svc->pid == 6002);

    /* Lookup nonexistent */
    svc = lookup_service_by_name("nonexistent.service");
    assert(svc == NULL);

    PASS();
}

void test_has_registry_capacity(void) {
    TEST("DoS prevention: registry capacity check");

    service_registry_init();

    /* Empty registry should have capacity */
    assert(has_registry_capacity() == 1);

    /* Fill registry almost to MAX */
    for (int i = 0; i < MAX_SERVICES - 1; i++) {
        char name[64];
        snprintf(name, sizeof(name), "service%d.service", i);
        register_service(7000 + i, name, NULL, KILL_PROCESS);
    }

    /* Should still have capacity for one more */
    assert(has_registry_capacity() == 1);
    assert(service_registry_count() == MAX_SERVICES - 1);

    /* Add the last one */
    register_service(7999, "last.service", NULL, KILL_PROCESS);
    assert(service_registry_count() == MAX_SERVICES);

    /* Now registry is full - no capacity */
    assert(has_registry_capacity() == 0);

    /* Unregister one */
    unregister_service(7000);

    /* Should have capacity again */
    assert(has_registry_capacity() == 1);

    PASS();
}

void test_restart_rate_limiting(void) {
    TEST("DoS prevention: restart rate limiting");

    service_registry_init();

    const char *unit_name = "crashy.service";

    /* First start should always be allowed */
    assert(can_restart_service(unit_name) == 1);
    record_restart_attempt(unit_name);

    /* Immediate restart should be blocked (MIN_RESTART_INTERVAL_SEC = 1) */
    assert(can_restart_service(unit_name) == 0);

    /* Wait minimum interval plus buffer for time(NULL) granularity */
    sleep(MIN_RESTART_INTERVAL_SEC + 2);

    /* Now should be allowed */
    assert(can_restart_service(unit_name) == 1);
    record_restart_attempt(unit_name);

    PASS();
}

void test_restart_window_limit(void) {
    TEST("DoS prevention: restart window limit");

    service_registry_init();

    const char *unit_name = "restart-bomb.service";

    /* Record MAX_RESTARTS_PER_WINDOW attempts with proper intervals */
    for (int i = 0; i < MAX_RESTARTS_PER_WINDOW; i++) {
        assert(can_restart_service(unit_name) == 1);
        record_restart_attempt(unit_name);

        /* Sleep to avoid MIN_RESTART_INTERVAL check
         * +2 instead of +1 to account for time(NULL) granularity */
        sleep(MIN_RESTART_INTERVAL_SEC + 2);
    }

    /* Next attempt should be blocked (exceeded window limit) */
    assert(can_restart_service(unit_name) == 0);

    printf("\n    (Sleeping %d seconds to test window expiration...)\n    ", RESTART_WINDOW_SEC + 3);
    fflush(stdout);

    /* Wait for window to expire */
    sleep(RESTART_WINDOW_SEC + 3);

    /* Now should be allowed again (old attempts expired) */
    assert(can_restart_service(unit_name) == 1);

    PASS();
}

void test_restart_different_services(void) {
    TEST("DoS prevention: per-service tracking");

    service_registry_init();

    /* Different services should have independent rate limits */
    const char *service1 = "service-a.service";
    const char *service2 = "service-b.service";

    /* Record attempts for service1 */
    assert(can_restart_service(service1) == 1);
    record_restart_attempt(service1);

    sleep(MIN_RESTART_INTERVAL_SEC + 1);

    /* service2 should not be affected by service1's restarts */
    assert(can_restart_service(service2) == 1);
    record_restart_attempt(service2);

    /* Immediate restart of service2 should be blocked */
    assert(can_restart_service(service2) == 0);

    /* But service1 can still restart after its minimum interval */
    sleep(MIN_RESTART_INTERVAL_SEC + 1);
    assert(can_restart_service(service1) == 1);
    record_restart_attempt(service1);

    /* And service2 can restart after its interval */
    sleep(MIN_RESTART_INTERVAL_SEC + 1);
    assert(can_restart_service(service2) == 1);

    PASS();
}

int main(void) {
    printf("=== Service Registry Tests ===\n\n");

    test_register_service();
    test_lookup_service();
    test_lookup_nonexistent();
    test_unregister_service();
    test_unregister_nonexistent();
    test_multiple_services();
    test_registry_full();
    test_reregister_same_pid();
    test_kill_modes();
    test_long_unit_name();

    printf("\n--- DoS Prevention Tests ---\n");
    printf("NOTE: These tests include sleep() calls to test time-based rate limiting.\n");
    printf("      The restart window test sleeps for %d seconds. Please be patient!\n\n",
           RESTART_WINDOW_SEC + 2);

    test_lookup_by_name();
    test_has_registry_capacity();
    test_restart_rate_limiting();
    test_restart_window_limit();
    test_restart_different_services();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
