#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/unit.h"

void supervisor_test_set_unit_context(struct unit_file **list, int count);
void supervisor_test_reset_generations(void);
void supervisor_test_handle_control_fd(int fd);
void supervisor_test_handle_status_fd(int fd);
int supervisor_test_start_unit(struct unit_file *unit);
int supervisor_test_start_unit_override(struct unit_file *unit);
void supervisor_test_dependency_ready(const char *name);
void supervisor_test_reset_waiters(void);

static struct unit_file *alloc_unit(const char *name, enum unit_type type) {
    struct unit_file *unit = calloc(1, sizeof(*unit));
    assert(unit);
    strncpy(unit->name, name, sizeof(unit->name) - 1);
    unit->type = type;
    unit->state = STATE_INACTIVE;
    unit->unit.default_dependencies = false;
    return unit;
}

static void add_dep(char **list, int *count, const char *name) {
    list[*count] = strdup(name);
    assert(list[*count] != NULL);
    (*count)++;
}

static void free_unit(struct unit_file *unit) {
    for (int i = 0; i < unit->unit.after_count; i++) {
        free(unit->unit.after[i]);
    }
    for (int i = 0; i < unit->unit.before_count; i++) {
        free(unit->unit.before[i]);
    }
    for (int i = 0; i < unit->unit.requires_count; i++) {
        free(unit->unit.requires[i]);
    }
    for (int i = 0; i < unit->unit.wants_count; i++) {
        free(unit->unit.wants[i]);
    }
    if (unit->type == UNIT_SERVICE) {
        free(unit->config.service.exec_start);
    }
    free(unit);
}

static void prepare_context(struct unit_file **units, int count) {
    supervisor_test_set_unit_context(units, count);
    supervisor_test_reset_generations();
    supervisor_test_reset_waiters();
}

static void cleanup_context(struct unit_file **units, int count) {
    supervisor_test_reset_waiters();
    supervisor_test_set_unit_context(NULL, 0);
    for (int i = 0; i < count; i++) {
        free_unit(units[i]);
    }
}

static void test_requires_ordering(void) {
    struct unit_file *swap = alloc_unit("swap.service", UNIT_TARGET);
    struct unit_file *checkfs = alloc_unit("checkfs.service", UNIT_TARGET);
    struct unit_file *remount = alloc_unit("remount-root.service", UNIT_TARGET);

    add_dep(checkfs->unit.after, &checkfs->unit.after_count, "swap.service");
    add_dep(remount->unit.requires, &remount->unit.requires_count, "checkfs.service");

    struct unit_file *units[] = {swap, checkfs, remount};
    prepare_context(units, 3);

    assert(supervisor_test_start_unit(remount) == 0);
    assert(checkfs->state == STATE_ACTIVE);
    assert(remount->state == STATE_ACTIVE);

    cleanup_context(units, 3);
}

static void test_wait_queue_release(void) {
    struct unit_file *checkfs = alloc_unit("checkfs.service", UNIT_TARGET);
    struct unit_file *remount = alloc_unit("remount-root.service", UNIT_TARGET);

    checkfs->state = STATE_ACTIVATING;
    add_dep(remount->unit.requires, &remount->unit.requires_count, "checkfs.service");

    struct unit_file *units[] = {checkfs, remount};
    prepare_context(units, 2);

    assert(supervisor_test_start_unit(remount) == 0);
    assert(remount->waiting_for_dependencies);

    checkfs->state = STATE_ACTIVE;
    supervisor_test_dependency_ready("checkfs.service");

    assert(!remount->waiting_for_dependencies);
    assert(remount->state == STATE_ACTIVE);

    cleanup_context(units, 2);
}

static void test_requires_failure_propagation(void) {
    struct unit_file *checkfs = alloc_unit("checkfs.service", UNIT_TARGET);
    struct unit_file *remount = alloc_unit("remount-root.service", UNIT_TARGET);

    checkfs->state = STATE_ACTIVATING;
    add_dep(remount->unit.requires, &remount->unit.requires_count, "checkfs.service");

    struct unit_file *units[] = {checkfs, remount};
    prepare_context(units, 2);

    assert(supervisor_test_start_unit(remount) == 0);
    assert(remount->waiting_for_dependencies);

    checkfs->state = STATE_FAILED;
    supervisor_test_dependency_ready("checkfs.service");

    assert(remount->state == STATE_FAILED);

    cleanup_context(units, 2);
}

static void test_emergency_override(void) {
    struct unit_file *broken = alloc_unit("broken.service", UNIT_SERVICE);
    broken->config.service.exec_start = strdup("/bin/false");

    struct unit_file *emergency = alloc_unit("emergency.target", UNIT_TARGET);
    add_dep(emergency->unit.requires, &emergency->unit.requires_count, "broken.service");

    struct unit_file *units[] = {broken, emergency};
    prepare_context(units, 2);

    assert(supervisor_test_start_unit(emergency) < 0);
    emergency->state = STATE_INACTIVE;
    supervisor_test_reset_generations();
    supervisor_test_reset_waiters();

    assert(supervisor_test_start_unit_override(emergency) == 0);
    assert(emergency->state == STATE_ACTIVE);

    cleanup_context(units, 2);
}

int main(void) {
    test_requires_ordering();
    test_wait_queue_release();
    test_requires_failure_propagation();
    test_emergency_override();
    printf("supervisor worker DAG tests passed\n");
    return 0;
}
