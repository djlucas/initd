/* test-offline-enable.c - Offline enable/disable integration tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#define TEST_UNIT_NAME "offline-enable-test.service"
#define TEST_TEMPLATE_NAME "offline-template@.service"
#define TEST_TEMPLATE_INSTANCE "offline-template@test.service"
#define TEST_UNIT_DIR "/lib/initd/system"
#define TEST_ETC_DIR "/etc/initd/system"
#define TEST_WANTS_DIR "/etc/initd/system/multi-user.target.wants"
#define TEST_UNIT_PATH TEST_UNIT_DIR "/" TEST_UNIT_NAME
#define TEST_SYMLINK_PATH TEST_WANTS_DIR "/" TEST_UNIT_NAME
#define TEST_TEMPLATE_PATH TEST_UNIT_DIR "/" TEST_TEMPLATE_NAME
#define TEST_TEMPLATE_SYMLINK TEST_WANTS_DIR "/" TEST_TEMPLATE_INSTANCE

/* External main from initctl */
extern int initd_test_initctl_main(int argc, char *argv[]);

static bool created_lib_initd = false;
static bool created_lib_initd_system = false;
static bool created_etc_initd = false;
static bool created_etc_initd_system = false;
static bool created_wants_dir = false;

static int mkdir_parents(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len;

    if (!path || path[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    len = strnlen(path, sizeof(tmp));
    if (len == 0 || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(tmp, path, len);
    tmp[len] = '\0';

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

static int ensure_directory(const char *path, bool *created) {
    struct stat st;

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Path %s exists but is not a directory\n", path);
            errno = ENOTDIR;
            return -1;
        }
        if (created) {
            *created = false;
        }
        return 0;
    }

    if (errno != ENOENT) {
        fprintf(stderr, "Failed to stat %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (mkdir_parents(path, 0755) < 0) {
        fprintf(stderr, "Failed to create %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (created) {
        *created = true;
    }
    return 0;
}

static int setup_test_environment(void) {
    if (ensure_directory("/lib/initd", &created_lib_initd) < 0) {
        return -1;
    }
    if (ensure_directory(TEST_UNIT_DIR, &created_lib_initd_system) < 0) {
        return -1;
    }
    if (ensure_directory("/etc/initd", &created_etc_initd) < 0) {
        return -1;
    }
    if (ensure_directory(TEST_ETC_DIR, &created_etc_initd_system) < 0) {
        return -1;
    }
    if (ensure_directory(TEST_WANTS_DIR, &created_wants_dir) < 0) {
        return -1;
    }

    unlink(TEST_UNIT_PATH);
    unlink(TEST_SYMLINK_PATH);

    FILE *f = fopen(TEST_UNIT_PATH, "w");
    if (!f) {
        fprintf(stderr, "Failed to create test unit file: %s\n", strerror(errno));
        return -1;
    }

    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Offline enable test service\n");
    fprintf(f, "\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=/bin/true\n");
    fprintf(f, "\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    fclose(f);

    unlink(TEST_TEMPLATE_PATH);
    FILE *tmpl = fopen(TEST_TEMPLATE_PATH, "w");
    if (!tmpl) {
        fprintf(stderr, "Failed to create template unit file: %s\n", strerror(errno));
        return -1;
    }

    fprintf(tmpl, "[Unit]\n");
    fprintf(tmpl, "Description=Offline template service for %%I\n");
    fprintf(tmpl, "\n");
    fprintf(tmpl, "[Service]\n");
    fprintf(tmpl, "Type=oneshot\n");
    fprintf(tmpl, "ExecStart=/bin/true %%I\n");
    fprintf(tmpl, "\n");
    fprintf(tmpl, "[Install]\n");
    fprintf(tmpl, "WantedBy=multi-user.target\n");
    fclose(tmpl);

    return 0;
}

static void cleanup_environment(void) {
    unlink(TEST_SYMLINK_PATH);
    unlink(TEST_TEMPLATE_SYMLINK);
    unlink(TEST_UNIT_PATH);
    unlink(TEST_TEMPLATE_PATH);
    system("rm -rf /tmp/initd-offline-runtime");
    if (created_wants_dir) {
        rmdir(TEST_WANTS_DIR);
    }
    if (created_etc_initd_system) {
        rmdir(TEST_ETC_DIR);
    }
    if (created_etc_initd) {
        rmdir("/etc/initd");
    }
    if (created_lib_initd_system) {
        rmdir(TEST_UNIT_DIR);
    }
    if (created_lib_initd) {
        rmdir("/lib/initd");
    }
}

static int check_symlink_exists(const char *link_path) {
    struct stat st;
    return lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode);
}

static int run_initctl(const char *command, const char *unit) {
    char *argv[4];
    int argc = 0;

    argv[argc++] = "initctl";
    argv[argc++] = (char *)command;
    if (unit) {
        argv[argc++] = (char *)unit;
    }
    argv[argc] = NULL;

    return initd_test_initctl_main(argc, argv);
}

int main(void) {
    int failures = 0;

    printf("=== Offline Enable/Disable Tests ===\n\n");

    if (getuid() != 0) {
        printf("Testing: offline enable (root required)... SKIP (not root)\n");
        printf("Note: Run as root to test offline enable/disable\n");
        printf("\n=== Tests skipped ===\n");
        return 77;
    }

    if (setup_test_environment() < 0) {
        fprintf(stderr, "FAIL: setup failed\n");
        cleanup_environment();
        return 1;
    }

    setenv("INITD_RUNTIME_DIR", "/tmp/initd-offline-runtime", 1);
    system("rm -rf /tmp/initd-offline-runtime");

    printf("Testing: is-enabled before enable...");
    fflush(stdout);
    int ret = run_initctl("is-enabled", TEST_UNIT_NAME);
    if (ret == 1) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 1, got %d)\n", ret);
        failures++;
    }

    printf("Testing: offline enable...");
    fflush(stdout);
    ret = run_initctl("enable", TEST_UNIT_NAME);
    if (ret == 0 && check_symlink_exists(TEST_SYMLINK_PATH)) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (enable returned %d, symlink %s)\n",
               ret, check_symlink_exists(TEST_SYMLINK_PATH) ? "exists" : "missing");
        failures++;
    }

    printf("Testing: is-enabled after enable...");
    fflush(stdout);
    ret = run_initctl("is-enabled", TEST_UNIT_NAME);
    if (ret == 0) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 0, got %d)\n", ret);
        failures++;
    }

    printf("Testing: offline disable...");
    fflush(stdout);
    ret = run_initctl("disable", TEST_UNIT_NAME);
    if (ret == 0 && !check_symlink_exists(TEST_SYMLINK_PATH)) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (disable returned %d, symlink %s)\n",
               ret, check_symlink_exists(TEST_SYMLINK_PATH) ? "still exists" : "missing");
        failures++;
    }

    printf("Testing: is-enabled after disable...");
    fflush(stdout);
    ret = run_initctl("is-enabled", TEST_UNIT_NAME);
    if (ret == 1) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 1, got %d)\n", ret);
        failures++;
    }

    printf("Testing: template is-enabled before enable...");
    fflush(stdout);
    ret = run_initctl("is-enabled", TEST_TEMPLATE_INSTANCE);
    if (ret == 1) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 1, got %d)\n", ret);
        failures++;
    }

    printf("Testing: template enable...");
    fflush(stdout);
    ret = run_initctl("enable", TEST_TEMPLATE_INSTANCE);
    if (ret == 0 && check_symlink_exists(TEST_TEMPLATE_SYMLINK)) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (enable returned %d, symlink %s)\n",
               ret, check_symlink_exists(TEST_TEMPLATE_SYMLINK) ? "exists" : "missing");
        failures++;
    }

    printf("Testing: template is-enabled after enable...");
    fflush(stdout);
    ret = run_initctl("is-enabled", TEST_TEMPLATE_INSTANCE);
    if (ret == 0) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 0, got %d)\n", ret);
        failures++;
    }

    printf("Testing: template disable...");
    fflush(stdout);
    ret = run_initctl("disable", TEST_TEMPLATE_INSTANCE);
    if (ret == 0 && !check_symlink_exists(TEST_TEMPLATE_SYMLINK)) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (disable returned %d, symlink %s)\n",
               ret, check_symlink_exists(TEST_TEMPLATE_SYMLINK) ? "still exists" : "missing");
        failures++;
    }

    printf("Testing: template is-enabled after disable...");
    fflush(stdout);
    ret = run_initctl("is-enabled", TEST_TEMPLATE_INSTANCE);
    if (ret == 1) {
        printf(" PASS\n");
    } else {
        printf(" FAIL (expected exit 1, got %d)\n", ret);
        failures++;
    }

    cleanup_environment();

    if (failures == 0) {
        printf("\n=== All tests passed! ===\n");
        return 0;
    }

    printf("\n=== %d test(s) failed ===\n", failures);
    return 1;
}
