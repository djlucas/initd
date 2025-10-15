/* test-service-registry.c - Service registry tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
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
    int result = register_service(1234, "test.service", KILL_CONTROL_GROUP);
    assert(result == 0);

    /* Verify count */
    assert(service_registry_count() == 1);

    PASS();
}

void test_lookup_service(void) {
    TEST("lookup service");

    service_registry_init();

    /* Register a service */
    register_service(5678, "lookup-test.service", KILL_PROCESS);

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
    register_service(1111, "exists.service", KILL_PROCESS);

    /* Lookup a different PID */
    struct service_record *svc = lookup_service(9999);
    assert(svc == NULL);

    PASS();
}

void test_unregister_service(void) {
    TEST("unregister service");

    service_registry_init();

    /* Register two services */
    register_service(1000, "service1.service", KILL_PROCESS);
    register_service(2000, "service2.service", KILL_CONTROL_GROUP);
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
        int result = register_service(1000 + i, name, KILL_PROCESS);
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
        int result = register_service(10000 + i, name, KILL_PROCESS);
        assert(result == 0);
    }

    assert(service_registry_count() == MAX_SERVICES);

    /* Try to add one more - should fail */
    int result = register_service(99999, "overflow.service", KILL_PROCESS);
    assert(result == -1);

    /* Count should still be MAX_SERVICES */
    assert(service_registry_count() == MAX_SERVICES);

    /* Unregister one */
    unregister_service(10000);
    assert(service_registry_count() == MAX_SERVICES - 1);

    /* Now we should be able to add one */
    result = register_service(99999, "now-fits.service", KILL_PROCESS);
    assert(result == 0);
    assert(service_registry_count() == MAX_SERVICES);

    PASS();
}

void test_reregister_same_pid(void) {
    TEST("reregister same PID");

    service_registry_init();

    /* Register a service */
    register_service(3000, "original.service", KILL_PROCESS);

    /* Try to register with the same PID - will create a second entry
     * (this is intentional - PIDs can be reused by OS) */
    register_service(3000, "duplicate.service", KILL_CONTROL_GROUP);

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
    register_service(4001, "none.service", KILL_NONE);
    register_service(4002, "process.service", KILL_PROCESS);
    register_service(4003, "group.service", KILL_CONTROL_GROUP);
    register_service(4004, "mixed.service", KILL_MIXED);

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
    register_service(5000, long_name, KILL_PROCESS);

    /* Lookup and verify it was truncated but still stored */
    struct service_record *svc = lookup_service(5000);
    assert(svc != NULL);
    assert(strlen(svc->unit_name) < sizeof(long_name));
    assert(strlen(svc->unit_name) == 255);  /* MAX - 1 for NUL */

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

    printf("\n=== All tests passed! ===\n");
    return 0;
}
