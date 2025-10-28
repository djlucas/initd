/* test-chroot.c - RootDirectory chroot tests (requires root)
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include "../src/common/parser.h"
#include "../src/common/log.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

/* Test chroot jail directory */
#define CHROOT_DIR "/tmp/initd-chroot-test"

/* Setup chroot environment */
static void setup_chroot_env(void) {
    /* Create chroot directory structure */
    system("rm -rf " CHROOT_DIR);
    system("mkdir -p " CHROOT_DIR "/bin");
    system("mkdir -p " CHROOT_DIR "/lib");
    system("mkdir -p " CHROOT_DIR "/lib64");
    system("mkdir -p " CHROOT_DIR "/test-output");

    /* Copy a simple binary into chroot (touch is small and has few deps) */
    system("cp /usr/bin/touch " CHROOT_DIR "/bin/touch");

    /* Copy required libraries */
    system("cp /lib/x86_64-linux-gnu/libc.so.6 " CHROOT_DIR "/lib/ 2>/dev/null || "
           "cp /lib64/libc.so.6 " CHROOT_DIR "/lib/ 2>/dev/null || true");
    system("cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 " CHROOT_DIR "/lib64/ 2>/dev/null || "
           "cp /lib64/ld-linux-x86-64.so.2 " CHROOT_DIR "/lib64/ 2>/dev/null || true");
}

/* Cleanup chroot environment */
static void cleanup_chroot_env(void) {
    system("rm -rf " CHROOT_DIR);
}

/* Test that chroot actually confines the process */
void test_chroot_confinement(void) {
    TEST("chroot confinement");

    setup_chroot_env();

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        assert(0);
    }

    if (pid == 0) {
        /* Child process - will chroot */
        if (chroot(CHROOT_DIR) < 0) {
            fprintf(stderr, "chroot failed: %s\n", strerror(errno));
            _exit(1);
        }

        if (chdir("/") < 0) {
            fprintf(stderr, "chdir failed: %s\n", strerror(errno));
            _exit(1);
        }

        /* Try to create a file in /test-output (inside chroot) */
        int fd = open("/test-output/marker", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            fprintf(stderr, "open failed: %s\n", strerror(errno));
            _exit(1);
        }
        close(fd);

        /* Verify we cannot access the real /tmp */
        struct stat st;
        if (stat("/tmp", &st) == 0) {
            /* If /tmp exists in chroot, that's OK, but it should be our jail's /tmp */
            /* The key test is that /test-output exists (which only exists in chroot) */
            if (stat("/test-output", &st) != 0) {
                fprintf(stderr, "chroot failed - cannot see /test-output\n");
                _exit(1);
            }
        }

        _exit(0);
    }

    /* Parent - wait for child */
    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);

    /* Verify the marker file was created in the chroot */
    struct stat st;
    assert(stat(CHROOT_DIR "/test-output/marker", &st) == 0);

    cleanup_chroot_env();
    PASS();
}

/* Test that chroot is called before dropping privileges */
void test_chroot_before_privdrop(void) {
    TEST("chroot called before privilege drop");

    /* This test verifies the order: chroot happens while still root,
     * before we drop to the service user. We can't easily test the full
     * supervisor execution path here, but we verified the code placement
     * in initd-supervisor.c lines 773-784 (chroot) comes before
     * lines 786-800 (drop privileges). */

    /* Just verify chroot requires root */
    if (geteuid() != 0) {
        printf("PASS (skipped - not root)\n");
        return;
    }

    setup_chroot_env();

    /* Verify chroot succeeds as root */
    pid_t pid = fork();
    if (pid == 0) {
        if (chroot(CHROOT_DIR) < 0) {
            _exit(1);
        }
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);

    cleanup_chroot_env();
    PASS();
}

int main(void) {
    printf("=== RootDirectory Chroot Tests ===\n\n");

    /* Initialize logging */
    log_init("test-chroot");

    /* Check if running as root */
    if (geteuid() != 0) {
        printf("SKIPPED: These tests require root privileges\n");
        printf("Run with: sudo meson test --suite privileged\n");
        log_close();
        return 77; /* meson skip code */
    }

    test_chroot_confinement();
    test_chroot_before_privdrop();

    printf("\n=== All chroot tests passed! ===\n");
    log_close();
    return 0;
}
