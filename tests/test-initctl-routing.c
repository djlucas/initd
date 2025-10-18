#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/control.h"

extern int initd_test_initctl_main(int argc, char **argv);

#define SYSTEM_RUNTIME_DIR "/tmp/initd-routing-system"

#define TEST(name)                              \
    do {                                        \
        printf("Testing: %s ... ", (name));     \
        fflush(stdout);                         \
    } while (0)

#define PASS()          \
    do {                \
        printf("PASS\n"); \
    } while (0)

struct routing_expectation {
    const char *socket_name;
    enum control_command expected_command;
    const char *expected_unit;
    enum unit_state_response response_state;
    pid_t response_pid;
};

static char user_runtime_parent_template[] = "/tmp/initd-routing-user-XXXXXX";
static char *user_runtime_parent = NULL;
static char user_runtime_dir[PATH_MAX];

static void ensure_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) < 0) {
        if (errno == EEXIST) {
            return;
        }
        perror("mkdir");
        exit(1);
    }
}

static void read_full(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) {
            perror("read");
            exit(2);
        }
        len -= (size_t)n;
        p += n;
    }
}

static void write_full(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) {
            perror("write");
            exit(3);
        }
        len -= (size_t)n;
        p += n;
    }
}

static void server_process(const struct routing_expectation *expect,
                           const char *runtime_dir,
                           int ready_fd) {
    char socket_path[PATH_MAX];
    struct sockaddr_un addr;
    int server_fd, client_fd;
    char ready = '1';

    snprintf(socket_path, sizeof(socket_path), "%s/%s",
             runtime_dir, expect->socket_name);

    unlink(socket_path);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(10);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(11);
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(12);
    }

    if (write(ready_fd, &ready, 1) != 1) {
        perror("write ready");
        exit(13);
    }
    close(ready_fd);

    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        exit(14);
    }

    struct control_request req;
    read_full(client_fd, &req, sizeof(req));

    if (req.header.command != expect->expected_command) {
        fprintf(stderr,
                "unexpected command: got %u expected %u\n",
                req.header.command, expect->expected_command);
        exit(20);
    }

    if (strcmp(req.unit_name, expect->expected_unit) != 0) {
        fprintf(stderr,
                "unexpected unit: got '%s' expected '%s'\n",
                req.unit_name, expect->expected_unit);
        exit(21);
    }

    struct control_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.header.length = sizeof(resp);
    resp.header.command = req.header.command;
    resp.code = RESP_SUCCESS;
    resp.state = expect->response_state;
    resp.pid = expect->response_pid;
    snprintf(resp.message, sizeof(resp.message), "%s ok", expect->expected_unit);

    write_full(client_fd, &resp, sizeof(resp));

    close(client_fd);
    close(server_fd);
    unlink(socket_path);
    exit(0);
}

static pid_t spawn_server(const struct routing_expectation *expect,
                          const char *runtime_dir) {
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) < 0) {
        perror("pipe");
        exit(30);
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(31);
    }

    if (pid == 0) {
        close(pipefd[0]);
        server_process(expect, runtime_dir, pipefd[1]);
    }

    close(pipefd[1]);
    char notify;
    if (read(pipefd[0], &notify, 1) != 1) {
        perror("read notify");
        exit(32);
    }
    close(pipefd[0]);

    return pid;
}

static void wait_for_server(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        exit(40);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "server exited abnormally: status=%d\n", status);
        exit(41);
    }
}

static void run_initctl(char **argv,
                        int argc,
                        const struct routing_expectation *expect,
                        const char *runtime_dir,
                        bool user_scope) {
    pid_t server_pid = spawn_server(expect, runtime_dir);

    setenv(INITD_RUNTIME_DIR_ENV, runtime_dir, 1);
    if (user_scope) {
        setenv("XDG_RUNTIME_DIR", user_runtime_parent, 1);
    } else {
        unsetenv("XDG_RUNTIME_DIR");
    }

    int ret = initd_test_initctl_main(argc, argv);
    if (ret != 0) {
        fprintf(stderr, "initctl_main returned %d\n", ret);
        exit(50);
    }

    wait_for_server(server_pid);
}

static void test_system_service_status(void) {
    TEST("system scope service status routes to supervisor.status.sock");
    char *argv[] = {"initctl", "status", "demo.service", NULL};
    struct routing_expectation expect = {
        .socket_name = "supervisor.status.sock",
        .expected_command = CMD_STATUS,
        .expected_unit = "demo.service",
        .response_state = UNIT_STATE_ACTIVE,
        .response_pid = 4242,
    };
    run_initctl(argv, 3, &expect, SYSTEM_RUNTIME_DIR, false);
    PASS();
}

static void test_system_service_start(void) {
    TEST("system scope service start routes to supervisor.sock");
    char *argv[] = {"initctl", "start", "demo", NULL};
    struct routing_expectation expect = {
        .socket_name = "supervisor.sock",
        .expected_command = CMD_START,
        .expected_unit = "demo.service",
        .response_state = UNIT_STATE_ACTIVE,
        .response_pid = 5252,
    };
    run_initctl(argv, 3, &expect, SYSTEM_RUNTIME_DIR, false);
    PASS();
}

static void test_system_timer_status(void) {
    TEST("system scope timer status routes to timer.status.sock");
    char *argv[] = {"initctl", "status", "backup.timer", NULL};
    struct routing_expectation expect = {
        .socket_name = "timer.status.sock",
        .expected_command = CMD_STATUS,
        .expected_unit = "backup.timer",
        .response_state = UNIT_STATE_ACTIVE,
        .response_pid = 0,
    };
    run_initctl(argv, 3, &expect, SYSTEM_RUNTIME_DIR, false);
    PASS();
}

static void test_system_socket_start(void) {
    TEST("system scope socket start routes to socket-activator.sock");
    char *argv[] = {"initctl", "start", "ssh.socket", NULL};
    struct routing_expectation expect = {
        .socket_name = "socket-activator.sock",
        .expected_command = CMD_START,
        .expected_unit = "ssh.socket",
        .response_state = UNIT_STATE_ACTIVE,
        .response_pid = 0,
    };
    run_initctl(argv, 3, &expect, SYSTEM_RUNTIME_DIR, false);
    PASS();
}

static void test_user_service_status(void) {
    TEST("user scope service status routes to per-user supervisor.status.sock");
    char *argv[] = {"initctl", "--user", "status", "demo", NULL};
    struct routing_expectation expect = {
        .socket_name = "supervisor.status.sock",
        .expected_command = CMD_STATUS,
        .expected_unit = "demo.service",
        .response_state = UNIT_STATE_ACTIVE,
        .response_pid = 2121,
    };
    run_initctl(argv, 4, &expect, user_runtime_dir, true);
    PASS();
}

int main(void) {
    ensure_directory(SYSTEM_RUNTIME_DIR, 0755);

    user_runtime_parent = mkdtemp(user_runtime_parent_template);
    if (!user_runtime_parent) {
        perror("mkdtemp");
        return 1;
    }

    snprintf(user_runtime_dir, sizeof(user_runtime_dir),
             "%s/initd", user_runtime_parent);
    ensure_directory(user_runtime_dir, 0700);

    test_system_service_status();
    test_system_service_start();
    test_system_timer_status();
    test_system_socket_start();
    test_user_service_status();

    return 0;
}
