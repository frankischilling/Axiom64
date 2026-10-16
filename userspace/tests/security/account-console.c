// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/auth.h"
#include "../../accounts/database.h"
#include "../../accounts/logbook.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_CONSOLE_FAIL line=%d errno=%d expression=%s\n", __LINE__,     \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static const char *service, *frontend;
static char database[PATH_MAX], records[PATH_MAX], homes[PATH_MAX], shell[PATH_MAX];
static const char *password = "Console-private-Authentication-72",
                  *mismatch = "Console-private-Mismatch-83";

struct call {
    pid_t pid;
    int master, slave;
    size_t size, cursor;
    char text[65536];
};

static void observed(const char* name) {
    printf("\nACCOUNT_CONSOLE_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void path(char output[PATH_MAX], const char* parent, const char* name) {
    CHECK(snprintf(output, PATH_MAX, "%s/%s", parent, name) < PATH_MAX);
}

static void receive(struct call* call) {
    CHECK(call->size + 1 < sizeof(call->text));
    ssize_t count =
        read(call->master, call->text + call->size, sizeof(call->text) - call->size - 1);
    if (count < 0 && errno == EIO)
        return;
    CHECK(count >= 0);
    call->size += (size_t)count;
    call->text[call->size] = 0;
    CHECK(!strstr(call->text, "Console-pri"));
}

static void until(struct call* call, const char* marker) {
    for (;;) {
        const char* found = strstr(call->text + call->cursor, marker);
        if (found) {
            call->cursor = (size_t)(found - call->text) + strlen(marker);
            return;
        }
        struct pollfd pollfd = {call->master, POLLIN, 0};
        CHECK(poll(&pollfd, 1, 10000) == 1 && (pollfd.revents & POLLIN));
        receive(call);
    }
}

static void send(struct call* call, const char* bytes, int secret) {
    if (secret) {
        struct termios attributes = {0};
        CHECK(tcgetattr(call->master, &attributes) == 0 && !(attributes.c_lflag & (ECHO | ECHONL)));
    }
    CHECK(write(call->master, bytes, strlen(bytes)) == (ssize_t)strlen(bytes));
    CHECK(write(call->master, "\n", 1) == 1);
}

static void start(struct call* call, uid_t uid, int no_terminal) {
    *call = (struct call){0};
    call->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(call->master >= 0 && grantpt(call->master) == 0 && unlockpt(call->master) == 0);
    char tty[64];
    CHECK(ptsname_r(call->master, tty, sizeof(tty)) == 0);
    call->slave = open(tty, O_RDWR | O_NOCTTY);
    CHECK(call->slave >= 0);
    call->pid = fork();
    CHECK(call->pid >= 0);
    if (!call->pid) {
        close(call->master);
        CHECK(setsid() == getpid() && ioctl(call->slave, TIOCSCTTY, 0) == 0);
        for (int fd = 0; fd < 3; fd++)
            CHECK(dup2(call->slave, fd) == fd);
        if (call->slave > 2)
            close(call->slave);
        if (no_terminal == 2) {
            int input = open(tty, O_RDONLY | O_NOCTTY);
            CHECK(input >= 0 && dup2(input, 0) == 0);
            close(input);
        } else if (no_terminal) {
            int null = open("/dev/null", O_RDWR);
            CHECK(null >= 0 && dup2(null, 0) == 0);
            close(null);
        }
        CHECK(setgroups(0, NULL) == 0 && setresgid(uid, uid, uid) == 0 &&
              setresuid(uid, uid, uid) == 0 && setenv("ACCESS_FORGED", "inherited", 1) == 0);
        execl(service, service, "--database", database, "--records", records, "--access", frontend,
              "--home-root", homes, "--shell", shell, (char*)NULL);
        _exit(126);
    }
}

static void finish(struct call* call, int expected) {
    int status;
    for (;;) {
        pid_t result = waitpid(call->pid, &status, WNOHANG);
        CHECK(result >= 0);
        struct pollfd pollfd = {call->master, POLLIN, 0};
        CHECK(poll(&pollfd, 1, result ? 0 : 100) >= 0);
        if (pollfd.revents & POLLIN)
            receive(call);
        if (result) {
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
            break;
        }
    }
    close(call->master);
    close(call->slave);
    fputs(call->text, stdout);
    fflush(stdout);
}

static void unpublished(void) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 1, &db) == 0 && account_database_fresh(db));
    account_database_end(db);
    char home[PATH_MAX];
    path(home, homes, "admin");
    struct stat value;
    CHECK(lstat(home, &value) == -1 && errno == ENOENT);
}

static void active(int expected) {
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(records, 0, &book) == 0);
    CHECK(account_logbook_active(book, 1000) == expected);
    account_logbook_close(book);
}

static pid_t worker(pid_t parent) {
    DIR* processes = opendir("/proc");
    CHECK(processes);
    pid_t selected = 0;
    struct dirent* entry;
    while ((entry = readdir(processes))) {
        int pid = atoi(entry->d_name);
        if (pid <= 0)
            continue;
        char path[64];
        CHECK(snprintf(path, sizeof(path), "/proc/%d/status", pid) < (int)sizeof(path));
        FILE* input = fopen(path, "r");
        if (!input) {
            CHECK(errno == ENOENT || errno == ESRCH);
            continue;
        }
        char* line = NULL;
        size_t capacity = 0;
        int value;
        while (getline(&line, &capacity, input) >= 0)
            if (sscanf(line, "PPid:%d", &value) == 1 && value == parent) {
                CHECK(!selected);
                selected = pid;
            }
        free(line);
        CHECK(fclose(input) == 0);
    }
    CHECK(closedir(processes) == 0 && selected > 0);
    return selected;
}

static void login(struct call* call, const char* observer) {
    send(call, "admin", 0);
    until(call, "Password: ");
    send(call, password, 1);
    until(call, "$ ");
    active(1);
    char home[PATH_MAX], command[PATH_MAX * 3];
    path(home, homes, "admin");
    CHECK(snprintf(command, sizeof(command), "%s 1000 %s", observer, home) < (int)sizeof(command));
    send(call, command, 0);
    until(call, "ACCOUNT_ACCESS_EXEC_PASS uid=1000");
    until(call, "$ ");
    send(call, "exit 0", 0);
    until(call, "login: ");
    active(0);
}

static void unsafe_worker(struct call* call) {
    start(call, 0, 0);
    until(call, "Administrator name: ");
    send(call, "admin", 0);
    finish(call, 1);
    CHECK(!strstr(call->text, "New password:") && !strstr(call->text, "$ "));
    unpublished();
}

int main(int argc, char** argv) {
    CHECK(argc == 6 && !getuid() && !geteuid() && !getegid());
    service = argv[2];
    frontend = argv[3];
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0);
    CHECK(chmod(service, 0755) == 0 && chmod(frontend, 04755) == 0);
    path(database, argv[1], "db");
    path(records, argv[1], "records");
    path(homes, argv[1], "home");
    path(shell, argv[1], "sh");
    CHECK(symlink(argv[4], shell) == 0);
    struct call call;
    start(&call, 1000, 0);
    finish(&call, 1);
    unpublished();
    start(&call, 0, 1);
    finish(&call, 1);
    unpublished();
    observed("root_identity_and_foreground_terminal_required_without_account_publication");
    CHECK(chmod(frontend, 0755) == 0);
    unsafe_worker(&call);
    CHECK(chmod(frontend, 04755) == 0);
    char duplicate[PATH_MAX];
    path(duplicate, argv[1], "duplicate-worker");
    CHECK(link(frontend, duplicate) == 0);
    unsafe_worker(&call);
    CHECK(unlink(duplicate) == 0);
    CHECK(chown(frontend, 1001, 1001) == 0 && chmod(frontend, 04755) == 0);
    unsafe_worker(&call);
    CHECK(chown(frontend, 0, 0) == 0 && chmod(frontend, 04755) == 0);
    CHECK(symlink(frontend, duplicate) == 0);
    const char* actual_frontend = frontend;
    frontend = duplicate;
    unsafe_worker(&call);
    frontend = actual_frontend;
    CHECK(unlink(duplicate) == 0);
    observed("unsafe_worker_mode_hardlink_foreign_owner_and_symlink_deny_before_password_entry");
    start(&call, 0, 2);
    until(&call, "Administrator name: ");
    CHECK(!strstr(call.text, "$ "));
    send(&call, "bad:name", 0);
    until(&call, "Invalid administrator name.");
    until(&call, "Administrator name: ");
    unpublished();
    observed("first_boot_invalid_name_keeps_accounts_unpublished_and_home_absent");
    send(&call, "admin", 0);
    until(&call, "New password: ");
    send(&call, password, 1);
    until(&call, "Confirm password: ");
    send(&call, mismatch, 1);
    until(&call, "Administrator name: ");
    unpublished();
    observed("private_confirmation_mismatch_retries_without_publication_or_home");
    send(&call, "admin", 0);
    until(&call, "New password: ");
    send(&call, password, 1);
    until(&call, "Confirm password: ");
    send(&call, password, 1);
    until(&call, "Administrator created. Please log in.");
    until(&call, "login: ");
    struct account_profile* profile = NULL;
    CHECK(account_auth_password(database, "admin", password, 0, &profile) == ACCOUNT_AUTH_ACCEPTED);
    CHECK(profile->uid == 1000 && profile->gid == 1000);
    account_profile_free(profile);
    CHECK(!strstr(call.text, "$ "));
    observed("first_boot_creates_real_administrator_privately_then_requires_authentication");
    send(&call, "admin", 0);
    until(&call, "Password: ");
    send(&call, mismatch, 1);
    until(&call, "Authentication failed.");
    until(&call, "login: ");
    active(0);
    CHECK(!strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS"));
    observed("wrong_password_retries_without_running_a_session");
    login(&call, argv[5]);
    observed("actual_ordinary_shell_identity_environment_terminal_records_and_logout");
    send(&call, "admin", 0);
    until(&call, "Password: ");
    CHECK(write(call.master, "Console-pri", 11) == 11);
    CHECK(kill(worker(call.pid), SIGKILL) == 0);
    until(&call, "login: ");
    struct termios restored = {0};
    CHECK(tcgetattr(call.master, &restored) == 0 &&
          (restored.c_lflag & (ECHO | ICANON | ISIG)) == (ECHO | ICANON | ISIG));
    login(&call, argv[5]);
    observed("killed_password_worker_restores_echo_and_flushes_partial_secret_before_retry");
    CHECK(kill(call.pid, SIGTERM) == 0);
    finish(&call, 0);
    start(&call, 0, 0);
    until(&call, "login: ");
    CHECK(!strstr(call.text, "Administrator name:") && !strstr(call.text, "first boot"));
    login(&call, argv[5]);
    CHECK(kill(call.pid, SIGTERM) == 0);
    finish(&call, 0);
    observed("restarted_console_preserves_administrator_and_requires_new_login");
    char current[PATH_MAX], missing[PATH_MAX];
    path(current, database, "current");
    path(missing, database, "held-current");
    CHECK(rename(current, missing) == 0);
    start(&call, 0, 0);
    finish(&call, 1);
    CHECK(strstr(call.text, "Accounts unavailable; authentication is blocked.") &&
          !strstr(call.text, "Administrator name:") && !strstr(call.text, "$ "));
    CHECK(rename(missing, current) == 0);
    observed("missing_committed_current_fails_closed_without_reprovisioning_or_root_shell");
    printf("ACCOUNT_CONSOLE_PASS observations=%u\n", observations);
    return 0;
}
