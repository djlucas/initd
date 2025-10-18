#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include <pwd.h>

#define TEST_MARKER_DIR "/tmp/initd-user-persist-markers"

extern int initd_test_initctl_main(int argc, char **argv);

static char user_home_template[] = "/tmp/initd-user-home-XXXXXX";
static char *user_home_dir = NULL;
static char config_path[PATH_MAX];
static char marker_path[PATH_MAX];

#define TEST(name)                              \
    do {                                        \
        printf("Testing: %s ... ", (name));     \
        fflush(stdout);                         \
    } while (0)

#define PASS()          \
    do {                \
        printf("PASS\n"); \
    } while (0)

static void ensure_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) < 0) {
        if (errno == EEXIST) {
            return;
        }
        perror("mkdir");
        exit(1);
    }
}

/* Stub implementations to avoid root requirements */
struct passwd *initctl_test_getpwnam(const char *name) {
    static struct passwd pw;
    if (strcmp(name, "alice") != 0) {
        return NULL;
    }

    pw.pw_name = (char *)"alice";
    pw.pw_passwd = (char *)"*";
    pw.pw_uid = 1500;
    pw.pw_gid = 1600;
    pw.pw_dir = user_home_dir;
    pw.pw_shell = (char *)"/bin/sh";
    return &pw;
}

uid_t initctl_test_getuid(void) {
    return 0;
}

uid_t initctl_test_geteuid(void) {
    return 0;
}

int initctl_test_chown(const char *path, uid_t uid, gid_t gid) {
    (void)path;
    (void)uid;
    (void)gid;
    return 0;
}

int initctl_test_fchown(int fd, uid_t uid, gid_t gid) {
    (void)fd;
    (void)uid;
    (void)gid;
    return 0;
}

static void run_command(char **argv, int argc) {
    int ret = initd_test_initctl_main(argc, argv);
    if (ret != 0) {
        fprintf(stderr, "initctl_main returned %d\n", ret);
        exit(2);
    }
}

static bool parse_line_enabled(const char *line, const char *key) {
    size_t len = strlen(key);
    if (strncmp(line, key, len) != 0) {
        return false;
    }
    const char *value = line + len;
    while (*value == ' ' || *value == '\t' || *value == '=') {
        value++;
    }
    return (strncmp(value, "enabled", 7) == 0);
}

static void assert_config(bool supervisor, bool timer, bool socket) {
    FILE *f = fopen(config_path, "r");
    if (!f) {
        perror("fopen config");
        exit(3);
    }

    bool sup_seen = false;
    bool tim_seen = false;
    bool soc_seen = false;
    bool sup_val = false;
    bool tim_val = false;
    bool soc_val = false;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "supervisor", 10) == 0) {
            sup_seen = true;
            sup_val = parse_line_enabled(line, "supervisor");
        } else if (strncmp(line, "timer", 5) == 0) {
            tim_seen = true;
            tim_val = parse_line_enabled(line, "timer");
        } else if (strncmp(line, "socket", 6) == 0) {
            soc_seen = true;
            soc_val = parse_line_enabled(line, "socket");
        }
    }

    fclose(f);

    assert(sup_seen && tim_seen && soc_seen);
    assert(sup_val == supervisor);
    assert(tim_val == timer);
    assert(soc_val == socket);
}

static void assert_marker(bool expect_present) {
    int rc = access(marker_path, F_OK);
    if (expect_present) {
        assert(rc == 0);
    } else {
        assert(rc != 0);
    }
}

static void test_enable_creates_config_and_marker(void) {
    TEST("user enable seeds config and marker");
    char *argv[] = {"initctl", "user", "enable", "alice", NULL};
    run_command(argv, 4);
    assert_config(true, true, true);
    assert_marker(true);
    PASS();
}

static void test_disable_timer_only_updates_config(void) {
    TEST("user disable timer toggles config only");
    char *argv[] = {"initctl", "user", "disable", "alice", "timer", NULL};
    run_command(argv, 5);
    assert_config(true, false, true);
    assert_marker(true);
    PASS();
}

static void test_disable_remaining_removes_marker(void) {
    TEST("disabling remaining daemons removes marker");
    char *argv[] = {"initctl", "user", "disable", "alice", "supervisor", "socket", NULL};
    run_command(argv, 6);
    assert_config(false, false, false);
    assert_marker(false);
    PASS();
}

int main(void) {
    ensure_directory(TEST_MARKER_DIR, 0755);

    char *home = mkdtemp(user_home_template);
    if (!home) {
        perror("mkdtemp");
        return 1;
    }
    user_home_dir = home;

    snprintf(config_path, sizeof(config_path),
             "%s/.config/initd/user-daemons.conf", user_home_dir);
    snprintf(marker_path, sizeof(marker_path),
             "%s/alice", TEST_MARKER_DIR);

    unlink(config_path);
    unlink(marker_path);

    test_enable_creates_config_and_marker();
    test_disable_timer_only_updates_config();
    test_disable_remaining_removes_marker();

    return 0;
}
