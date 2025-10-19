#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/common/ipc.h"
#include "../src/common/log.h"
#include "../src/common/parser.h"
#include "../src/supervisor/service-registry.h"

/* Test entry point exposed by initd-supervisor.c when built with UNIT_TEST */
extern int supervisor_handle_request_for_test(struct priv_request *req, struct priv_response *resp);

static const char *find_binary(const char *paths[], size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (paths[i] && access(paths[i], X_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

static char *make_temp_path(const char *prefix) {
    char *tmpl = NULL;
    if (asprintf(&tmpl, "/tmp/%sXXXXXX", prefix) < 0) {
        return NULL;
    }
    int fd = mkstemp(tmpl);
    if (fd >= 0) {
        close(fd);
        unlink(tmpl); /* We only need the unique path, not the file */
    } else {
        free(tmpl);
        tmpl = NULL;
    }
    return tmpl;
}

static void write_unit_file(const char *path,
                            const char *exec_start,
                            const char *exec_start_pre,
                            const char *exec_start_post,
                            const char *exec_stop,
                            const char *exec_reload) {
    FILE *f = fopen(path, "w");
    assert(f != NULL);

    fprintf(f,
            "[Unit]\n"
            "Description=Lifecycle test unit\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s\n",
            exec_start);

    if (exec_start_pre) {
        fprintf(f, "ExecStartPre=%s\n", exec_start_pre);
    }
    if (exec_start_post) {
        fprintf(f, "ExecStartPost=%s\n", exec_start_post);
    }
    if (exec_stop) {
        fprintf(f, "ExecStop=%s\n", exec_stop);
    }
    if (exec_reload) {
        fprintf(f, "ExecReload=%s\n", exec_reload);
    }

    fprintf(f, "TimeoutStopSec=1\n");
    fclose(f);
}

static void wait_for_pid(pid_t pid) {
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        break;
    }
}

static void test_exec_lifecycle_success(void) {
    const char *touch_candidates[] = {"/usr/bin/touch", "/bin/touch"};
    const char *sleep_candidates[] = {"/bin/sleep", "/usr/bin/sleep"};

    const char *touch_path = find_binary(touch_candidates, 2);
    const char *sleep_path = find_binary(sleep_candidates, 2);
    assert(touch_path != NULL);
    assert(sleep_path != NULL);

    char *pre_path = make_temp_path("initd-pre-");
    char *post_path = make_temp_path("initd-post-");
    char *stop_path = make_temp_path("initd-stop-");
    char *reload_path = make_temp_path("initd-reload-");
    assert(pre_path && post_path && stop_path && reload_path);

    char unit_path[] = "/tmp/initd-exec-lifecycle-XXXXXX.service";
    int fd = mkstemps(unit_path, 8);
    assert(fd >= 0);
    close(fd);

    char exec_start_cmd[256];
    char exec_start_pre_cmd[256];
    char exec_start_post_cmd[256];
    char exec_stop_cmd[256];
    char exec_reload_cmd[256];

    snprintf(exec_start_cmd, sizeof(exec_start_cmd), "%s 30", sleep_path);
    snprintf(exec_start_pre_cmd, sizeof(exec_start_pre_cmd), "%s %s", touch_path, pre_path);
    snprintf(exec_start_post_cmd, sizeof(exec_start_post_cmd), "%s %s", touch_path, post_path);
    snprintf(exec_stop_cmd, sizeof(exec_stop_cmd), "%s %s", touch_path, stop_path);
    snprintf(exec_reload_cmd, sizeof(exec_reload_cmd), "%s %s", touch_path, reload_path);

    write_unit_file(unit_path,
                    exec_start_cmd,
                    exec_start_pre_cmd,
                    exec_start_post_cmd,
                    exec_stop_cmd,
                    exec_reload_cmd);

    struct priv_request req = {0};
    struct priv_response resp = {0};
    strncpy(req.unit_name, "exec-lifecycle.service", sizeof(req.unit_name) - 1);
    strncpy(req.unit_path, unit_path, sizeof(req.unit_path) - 1);
    req.type = REQ_START_SERVICE;

    service_registry_init();
    log_init("exec-lifecycle-test");

    /* Start service (should trigger ExecStartPre/Post) */
    assert(supervisor_handle_request_for_test(&req, &resp) == 0);
    assert(resp.type == RESP_SERVICE_STARTED);
    assert(resp.service_pid > 0);

    assert(access(pre_path, F_OK) == 0);
    assert(access(post_path, F_OK) == 0);

    /* Reload service (ExecReload expected) */
    struct priv_request reload_req = {0};
    struct priv_response reload_resp = {0};
    reload_req.type = REQ_RELOAD_SERVICE;
    reload_req.service_pid = resp.service_pid;
    strncpy(reload_req.unit_name, req.unit_name, sizeof(reload_req.unit_name) - 1);
    strncpy(reload_req.unit_path, req.unit_path, sizeof(reload_req.unit_path) - 1);

    assert(supervisor_handle_request_for_test(&reload_req, &reload_resp) == 0);
    assert(reload_resp.type == RESP_SERVICE_RELOADED);
    assert(access(reload_path, F_OK) == 0);

    /* Stop service (ExecStop expected) */
    struct priv_request stop_req = {0};
    struct priv_response stop_resp = {0};
    stop_req.type = REQ_STOP_SERVICE;
    stop_req.service_pid = resp.service_pid;
    strncpy(stop_req.unit_name, req.unit_name, sizeof(stop_req.unit_name) - 1);
    strncpy(stop_req.unit_path, req.unit_path, sizeof(stop_req.unit_path) - 1);

    assert(supervisor_handle_request_for_test(&stop_req, &stop_resp) == 0);
    assert(stop_resp.type == RESP_SERVICE_STOPPED);
    wait_for_pid(resp.service_pid);
    assert(access(stop_path, F_OK) == 0);

    unlink(unit_path);
    unlink(pre_path);
    unlink(post_path);
    unlink(stop_path);
    unlink(reload_path);
    free(pre_path);
    free(post_path);
    free(stop_path);
    free(reload_path);
}

static void test_reload_without_exec_reload(void) {
    const char *sleep_candidates[] = {"/bin/sleep", "/usr/bin/sleep"};
    const char *sleep_path = find_binary(sleep_candidates, 2);
    assert(sleep_path != NULL);

    service_registry_init();

    char unit_path[] = "/tmp/initd-exec-reload-missing-XXXXXX.service";
    int fd = mkstemps(unit_path, 8);
    assert(fd >= 0);
    close(fd);

    char exec_start_cmd[256];
    snprintf(exec_start_cmd, sizeof(exec_start_cmd), "%s 30", sleep_path);

    write_unit_file(unit_path, exec_start_cmd, NULL, NULL, NULL, NULL);

    struct priv_request start_req = {0};
    struct priv_response start_resp = {0};
    strncpy(start_req.unit_name, "exec-reload-missing.service", sizeof(start_req.unit_name) - 1);
    strncpy(start_req.unit_path, unit_path, sizeof(start_req.unit_path) - 1);
    start_req.type = REQ_START_SERVICE;

    /* allow restart tracker to reset */
    sleep(1);
    assert(supervisor_handle_request_for_test(&start_req, &start_resp) == 0);
    assert(start_resp.type == RESP_SERVICE_STARTED);

    struct priv_request reload_req = {0};
    struct priv_response reload_resp = {0};
    reload_req.type = REQ_RELOAD_SERVICE;
    reload_req.service_pid = start_resp.service_pid;
    strncpy(reload_req.unit_name, start_req.unit_name, sizeof(reload_req.unit_name) - 1);
    strncpy(reload_req.unit_path, start_req.unit_path, sizeof(reload_req.unit_path) - 1);

    assert(supervisor_handle_request_for_test(&reload_req, &reload_resp) == 0);
    assert(reload_resp.type == RESP_ERROR);
    assert(reload_resp.error_code == ENOTSUP);

    struct priv_request stop_req = {0};
    struct priv_response stop_resp = {0};
    stop_req.type = REQ_STOP_SERVICE;
    stop_req.service_pid = start_resp.service_pid;
    strncpy(stop_req.unit_name, start_req.unit_name, sizeof(stop_req.unit_name) - 1);
    strncpy(stop_req.unit_path, start_req.unit_path, sizeof(stop_req.unit_path) - 1);

    assert(supervisor_handle_request_for_test(&stop_req, &stop_resp) == 0);
    wait_for_pid(start_resp.service_pid);

    unlink(unit_path);
}

int main(void) {
    if (getuid() != 0) {
        printf("Testing Exec* lifecycle handling... SKIP (not root)\n");
        return 77;
    }
    printf("Testing Exec* lifecycle handling...\n");
    test_exec_lifecycle_success();
    test_reload_without_exec_reload();
    printf("✓ Exec* lifecycle tests passed\n");
    return 0;
}
