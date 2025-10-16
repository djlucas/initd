#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/common/unit.h"

void supervisor_test_set_unit_context(struct unit_file **units, int count);
void supervisor_test_reset_generations(void);
void supervisor_test_mark_isolate(struct unit_file *target);

static struct unit_file *make_unit(const char *name, enum unit_type type) {
    struct unit_file *unit = calloc(1, sizeof(struct unit_file));
    assert(unit != NULL);
    strncpy(unit->name, name, sizeof(unit->name) - 1);
    unit->type = type;
    unit->state = (type == UNIT_TARGET) ? STATE_INACTIVE : STATE_ACTIVE;
    return unit;
}

static void add_dependency(char **list, int *count, const char *name) {
    list[*count] = strdup(name);
    assert(list[*count] != NULL);
    (*count)++;
}

int main(void) {
    struct unit_file *basic = make_unit("basic.target", UNIT_TARGET);
    struct unit_file *multi = make_unit("multi-user.target", UNIT_TARGET);
    struct unit_file *graphical = make_unit("graphical.target", UNIT_TARGET);
    struct unit_file *dm = make_unit("display-manager.service", UNIT_SERVICE);
    struct unit_file *getty = make_unit("getty.service", UNIT_SERVICE);
    struct unit_file *misc = make_unit("misc.service", UNIT_SERVICE);

    add_dependency(graphical->unit.requires, &graphical->unit.requires_count, "multi-user.target");
    add_dependency(multi->unit.requires, &multi->unit.requires_count, "basic.target");

    add_dependency(graphical->unit.wants, &graphical->unit.wants_count, "display-manager.service");
    add_dependency(multi->unit.wants, &multi->unit.wants_count, "getty.service");

    struct unit_file *units[] = {basic, multi, graphical, dm, getty, misc};
    supervisor_test_set_unit_context(units, 6);
    supervisor_test_reset_generations();

    supervisor_test_mark_isolate(graphical);

    assert(graphical->isolate_needed);
    assert(multi->isolate_needed);
    assert(basic->isolate_needed);
    assert(dm->isolate_needed);
    assert(getty->isolate_needed);
    assert(!misc->isolate_needed);

    for (int i = 0; i < 6; i++) {
        struct unit_file *u = units[i];
        for (int j = 0; j < u->unit.requires_count; j++) free(u->unit.requires[j]);
        for (int j = 0; j < u->unit.wants_count; j++) free(u->unit.wants[j]);
        free(u);
    }

    printf("Isolate dependency closure test passed\n");
    return 0;
}
