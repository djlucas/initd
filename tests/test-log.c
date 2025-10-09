/* test-log.c - Logging system tests
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>
#include "../src/common/log.h"

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout)

#define PASS() \
    printf("PASS\n")

void test_log_init(void) {
    TEST("log initialization");

    assert(log_init("test-initd") == 0);

    /* After init:
     * - Buffer should be empty
     * - Syslog may not be ready yet */

    size_t buffered, dropped;
    bool syslog_ready;
    log_get_stats(&buffered, &dropped, &syslog_ready);

    assert(buffered == 0);
    assert(dropped == 0);

    log_close();
    PASS();
}

void test_log_buffering(void) {
    TEST("early boot log buffering");

    assert(log_init("test-initd") == 0);

    /* Before syslog is ready, messages should be buffered */
    log_msg(LOG_INFO, "test-unit", "Test message 1");
    log_msg(LOG_INFO, "test-unit", "Test message 2");
    log_msg(LOG_INFO, "test-unit", "Test message 3");

    size_t buffered, dropped;
    bool syslog_ready;
    log_get_stats(&buffered, &dropped, &syslog_ready);

    /* Messages should be buffered */
    assert(buffered == 3);
    assert(dropped == 0);
    assert(syslog_ready == false);

    log_close();
    PASS();
}

void test_log_syslog_ready(void) {
    TEST("syslog ready notification");

    assert(log_init("test-initd") == 0);

    /* Buffer some messages */
    log_msg(LOG_INFO, "test-unit", "Buffered message");

    size_t buffered_before;
    bool syslog_ready_before;
    log_get_stats(&buffered_before, NULL, &syslog_ready_before);
    assert(buffered_before > 0);
    assert(syslog_ready_before == false);

    /* Notify that syslog is ready */
    log_syslog_ready();

    /* Buffer should be flushed */
    size_t buffered_after;
    bool syslog_ready_after;
    log_get_stats(&buffered_after, NULL, &syslog_ready_after);
    assert(buffered_after == 0);
    assert(syslog_ready_after == true);

    log_close();
    PASS();
}

void test_log_direct_to_syslog(void) {
    TEST("direct logging to syslog");

    assert(log_init("test-initd") == 0);

    /* Mark syslog as ready */
    log_syslog_ready();

    /* New messages should go directly to syslog, not buffered */
    log_msg(LOG_INFO, "test-unit", "Direct message");

    size_t buffered;
    log_get_stats(&buffered, NULL, NULL);
    assert(buffered == 0);

    log_close();
    PASS();
}

void test_log_priorities(void) {
    TEST("different log priorities");

    assert(log_init("test-initd") == 0);

    /* Test different syslog priorities */
    log_msg(LOG_EMERG, "test", "Emergency");
    log_msg(LOG_ALERT, "test", "Alert");
    log_msg(LOG_CRIT, "test", "Critical");
    log_msg(LOG_ERR, "test", "Error");
    log_msg(LOG_WARNING, "test", "Warning");
    log_msg(LOG_NOTICE, "test", "Notice");
    log_msg(LOG_INFO, "test", "Info");
    log_msg(LOG_DEBUG, "test", "Debug");

    size_t buffered;
    log_get_stats(&buffered, NULL, NULL);
    assert(buffered == 8);

    log_close();
    PASS();
}

void test_log_buffer_overflow(void) {
    TEST("log buffer overflow handling");

    assert(log_init("test-initd") == 0);

    /* Fill buffer beyond capacity (MAX_BUFFER_ENTRIES = 1000) */
    for (int i = 0; i < 1050; i++) {
        log_msg(LOG_INFO, "test", "Message %d", i);
    }

    size_t buffered, dropped;
    log_get_stats(&buffered, &dropped, NULL);

    /* Should have dropped oldest messages */
    assert(buffered <= 1000);  /* At most MAX_BUFFER_ENTRIES */
    assert(dropped == 50);     /* 1050 - 1000 = 50 dropped */

    log_close();
    PASS();
}

void test_log_with_null_unit(void) {
    TEST("logging with NULL unit name");

    assert(log_init("test-initd") == 0);

    /* NULL unit should be handled gracefully */
    log_msg(LOG_INFO, NULL, "System message");

    size_t buffered;
    log_get_stats(&buffered, NULL, NULL);
    assert(buffered == 1);

    log_close();
    PASS();
}

void test_log_check_syslog(void) {
    TEST("syslog detection");

    assert(log_init("test-initd") == 0);

    /* log_check_syslog() tests for /dev/log */
    log_check_syslog();

    /* If /dev/log exists and is writable, syslog should be marked ready */
    /* Otherwise, should remain in buffering mode */

    log_close();
    PASS();
}

void test_log_message_formatting(void) {
    TEST("log message formatting");

    assert(log_init("test-initd") == 0);

    /* Test formatted messages */
    log_msg(LOG_INFO, "test-unit", "Number: %d, String: %s", 42, "test");

    size_t buffered;
    log_get_stats(&buffered, NULL, NULL);
    assert(buffered == 1);

    log_close();
    PASS();
}

void test_log_multiple_init(void) {
    TEST("multiple init/close cycles");

    assert(log_init("test-initd-1") == 0);
    log_msg(LOG_INFO, "test", "Message 1");
    log_close();

    assert(log_init("test-initd-2") == 0);
    log_msg(LOG_INFO, "test", "Message 2");

    /* Should start fresh */
    size_t buffered;
    log_get_stats(&buffered, NULL, NULL);
    assert(buffered == 1);

    log_close();
    PASS();
}

int main(void) {
    printf("=== Logging System Tests ===\n\n");

    test_log_init();
    test_log_buffering();
    test_log_syslog_ready();
    test_log_direct_to_syslog();
    test_log_priorities();
    test_log_buffer_overflow();
    test_log_with_null_unit();
    test_log_check_syslog();
    test_log_message_formatting();
    test_log_multiple_init();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
