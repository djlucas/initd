/* test-offline-enable.c - Offline enable/disable integration tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_UNIT_NAME "offline-enable-test.service"
#define TEST_UNIT_DIR "/lib/initd/system"
#define TEST_ETC_DIR "/etc/initd/system"
#define TEST_WANTS_DIR "/etc/initd/system/multi-user.target.wants"
#define TEST_UNIT_PATH TEST_UNIT_DIR "/" TEST_UNIT_NAME
#define TEST_SYMLINK_PATH TEST_WANTS_DIR "/" TEST_UNIT_NAME

/* External main from initctl */
extern int initd_test_initctl_main(int argc, char *argv[]);

static int ensure_directory(const char *path) {
    if (mkdir(path, 0755) < 0) {
        if (errno == EEXIST) {
            return 0;
        }
        fprintf(stderr, "Failed to create %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int setup_test_environment(void) {
    if (ensure_directory(TEST_UNIT_DIR) < 0) {
        return -1;
    }
    if (ensure_directory(TEST_ETC_DIR) < 0) {
        return -1;
    }
    if (ensure_directory(TEST_WANTS_DIR) < 0) {
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

    return 0;
}

static void cleanup_environment(void) {
    unlink(TEST_SYMLINK_PATH);
    unlink(TEST_UNIT_PATH);
    system("rm -rf /tmp/initd-offline-runtime");
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

    cleanup_environment();

    if (failures == 0) {
        printf("\n=== All tests passed! ===\n");
        return 0;
    }

    printf("\n=== %d test(s) failed ===\n", failures);
    return 1;
}
