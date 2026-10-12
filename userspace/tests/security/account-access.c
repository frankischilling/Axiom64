// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/auth.h"
#include "../../accounts/database.h"
#include "../../accounts/logbook.h"
#include "../../accounts/password.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
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
            fprintf(stderr, "ACCOUNT_ACCESS_FAIL line=%d errno=%d expression=%s\n", __LINE__,      \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char *frontend, *busybox, *observer;
static const char *password = "Fixture-Access-Password-82", *changed = "Fixture-Access-Changed-93";
static char database[4096], records[4096], home[4096], shell[4096];
static unsigned observations;

struct call {
    pid_t pid;
    int master, slave;
    char text[32768];
    size_t size;
};

static void path(char output[4096], const char* parent, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", parent, name) < 4096);
}

static void observed(const char* name) {
    printf("\nACCOUNT_ACCESS_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void receive(struct call* call) {
    CHECK(call->size + 1 < sizeof(call->text));
    ssize_t size = read(call->master, call->text + call->size, sizeof(call->text) - call->size - 1);
    if (size < 0 && errno == EIO)
        return;
    CHECK(size >= 0);
    call->size += (size_t)size;
    call->text[call->size] = 0;
    CHECK(!strstr(call->text, password) && !strstr(call->text, changed));
}

static void until(struct call* call, const char* marker) {
    while (!strstr(call->text, marker)) {
        struct pollfd pollfd = {call->master, POLLIN, 0};
        CHECK(poll(&pollfd, 1, 10000) == 1 && (pollfd.revents & POLLIN));
        receive(call);
    }
}

static void send(struct call* call, const char* bytes, int secret) {
    if (secret) {
        struct termios attributes;
        CHECK(tcgetattr(call->master, &attributes) == 0);
        CHECK(!(attributes.c_lflag & (ECHO | ECHONL)));
    }
    CHECK(write(call->master, bytes, strlen(bytes)) == (ssize_t)strlen(bytes));
    CHECK(write(call->master, "\n", 1) == 1);
}

static void start(struct call* call, uid_t uid, char* const arguments[], const int redirected[3]) {
    *call = (struct call){0};
    call->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(call->master >= 0 && grantpt(call->master) == 0 && unlockpt(call->master) == 0);
    char name[64];
    CHECK(ptsname_r(call->master, name, sizeof(name)) == 0);
    int slave = open(name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0 && fchown(slave, uid, uid) == 0 && fchmod(slave, 0600) == 0);
    call->slave = slave;
    call->pid = fork();
    CHECK(call->pid >= 0);
    if (!call->pid) {
        close(call->master);
        CHECK(setsid() == getpid() && ioctl(slave, TIOCSCTTY, 0) == 0);
        for (int fd = 0; fd < 3; fd++)
            CHECK(dup2(redirected && redirected[fd] >= 0 ? redirected[fd] : slave, fd) == fd);
        if (slave > 2)
            close(slave);
        CHECK(setenv("TERM", "vt100", 1) == 0 && setenv("ACCESS_FORGED", "inherited", 1) == 0);
        CHECK(setgroups(0, NULL) == 0 && setresgid(uid, uid, uid) == 0 &&
              setresuid(uid, uid, uid) == 0);
        execv(frontend, arguments);
        perror("ACCOUNT_ACCESS_FAIL exec");
        _exit(126);
    }
    // The caller's shell/getty keeps its terminal open while a fully redirected
    // command starts. Preserve that outer endpoint until the frontend exits.
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
    CHECK(!strstr(call->text, "ACCOUNT_ACCESS_FAIL"));
    fputs(call->text, stdout);
    fflush(stdout);
}

static void quiet_password(struct call* call, const char* value) {
    until(call, "Password: ");
    send(call, value, 1);
}

static void confirmation(struct call* call, const char* first, const char* second) {
    until(call, "New password: ");
    send(call, first, 1);
    until(call, "Confirm password: ");
    send(call, second, 1);
}

static void verify(const char* name, const char* secret, int result) {
    struct account_profile* profile = NULL;
    CHECK(account_auth_password(database, name, secret, 0, &profile) == result);
    account_profile_free(profile);
}

int main(int argc, char** argv) {
    CHECK(argc == 5 && !getuid() && !geteuid());
    frontend = argv[2];
    busybox = argv[3];
    observer = argv[4];
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0 && chmod(frontend, 04755) == 0);
    path(database, argv[1], "db");
    path(records, argv[1], "records");
    path(home, argv[1], "admin");
    path(shell, argv[1], "sh");
    CHECK(symlink(busybox, shell) == 0);
    CHECK(mkdir("/root", 0700) == 0 || errno == EEXIST);
    struct call call;
    char* provision[] = {(char*)frontend, "provision", "admin", home, shell, NULL};
    start(&call, 0, provision, NULL);
    confirmation(&call, password, changed);
    finish(&call, 1);
    start(&call, 0, provision, NULL);
    confirmation(&call, password, password);
    finish(&call, 0);
    verify("admin", password, ACCOUNT_AUTH_ACCEPTED);
    verify("root", password, ACCOUNT_AUTH_DENIED);
    start(&call, 0, provision, NULL);
    confirmation(&call, password, password);
    finish(&call, 1);
    verify("admin", password, ACCOUNT_AUTH_ACCEPTED);
    observed("private_confirmed_administrator_provisioning_locked_root_and_mismatch_denial");
    char* login[] = {(char*)frontend, "login", "admin", NULL};
    start(&call, 0, login, NULL);
    quiet_password(&call, changed);
    finish(&call, 1);
    CHECK(strstr(call.text, "Authentication failed."));
    observed("wrong_password_denial_without_shell_secret_echo");
    const char* denied_names[] = {"missing", "root"};
    for (unsigned i = 0; i < 2; i++) {
        char* unavailable[] = {(char*)frontend, "login", (char*)denied_names[i], NULL};
        start(&call, 0, unavailable, NULL);
        quiet_password(&call, password);
        finish(&call, 1);
        CHECK(strstr(call.text, "Authentication failed.") &&
              !strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS"));
    }
    observed("missing_and_locked_accounts_deny_real_login_with_generic_failure");
    start(&call, 0, login, NULL);
    quiet_password(&call, password);
    until(&call, "$ ");
    char command[8192];
    CHECK(snprintf(command, sizeof(command), "%s 1000 %s; exit 7", observer, home) <
          (int)sizeof(command));
    send(&call, command, 0);
    finish(&call, 7);
    CHECK(strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS uid=1000"));
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(records, 0, &book) == 0 && account_logbook_active(book, 1000) == 0);
    account_logbook_close(book);
    observed("actual_authenticated_login_shell_complete_identity_environment_terminal_logout");
    CHECK(snprintf(command, sizeof(command), "%s 1000 %s", observer, home) < (int)sizeof(command));
    char* su[] = {(char*)frontend, "su", "admin", "-c", command, NULL};
    start(&call, 0, su, NULL);
    finish(&call, 0);
    CHECK(strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS uid=1000"));
    observed("real_root_su_selects_existing_ordinary_identity_and_records_session");
    char* ordinary_override[] = {(char*)frontend, "--database", database, "login", "admin", NULL};
    start(&call, 1000, ordinary_override, NULL);
    finish(&call, 2);
    observed("setuid_frontend_denies_ordinary_database_override");
    char* elevated[] = {(char*)frontend, "sudo", (char*)observer, "0", "/root", NULL};
    start(&call, 1000, elevated, NULL);
    quiet_password(&call, password);
    finish(&call, 0);
    CHECK(strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS uid=0"));
    observed("actual_setuid_sudo_requires_admin_password_and_executes_full_root_identity");
    struct account_database* db = NULL;
    int published;
    CHECK(account_database_begin(database, 0, &db) == 0);
    CHECK(account_database_member(db, "sudo", "admin", 0) == 0);
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    start(&call, 1000, elevated, NULL);
    quiet_password(&call, password);
    finish(&call, 1);
    CHECK(strstr(call.text, "Authentication failed.") &&
          !strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS"));
    CHECK(account_database_begin(database, 0, &db) == 0);
    CHECK(account_database_member(db, "sudo", "admin", 1) == 0);
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    observed("removed_sudo_membership_denies_actual_setuid_elevation_before_exec");
    char input_path[4096], output_path[4096], error_path[4096];
    path(input_path, argv[1], "input");
    path(output_path, argv[1], "output");
    path(error_path, argv[1], "error");
    int redirected[] = {open(input_path, O_RDWR | O_CREAT | O_EXCL, 0600),
                        open(output_path, O_RDWR | O_CREAT | O_EXCL, 0600),
                        open(error_path, O_RDWR | O_CREAT | O_EXCL, 0600)};
    CHECK(redirected[0] >= 0 && redirected[1] >= 0 && redirected[2] >= 0);
    CHECK(write(redirected[0], "redirect-data", 13) == 13 &&
          lseek(redirected[0], 0, SEEK_SET) == 0);
    char* sudo[] = {(char*)frontend, "sudo", "-u",       "admin", (char*)observer,
                    "1000",          home,   "redirect", NULL};
    start(&call, 1000, sudo, redirected);
    quiet_password(&call, password);
    finish(&call, 0);
    CHECK(!strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS"));
    char output[512] = {0};
    CHECK(lseek(redirected[1], 0, SEEK_SET) == 0 &&
          read(redirected[1], output, sizeof(output) - 1) > 0);
    CHECK(strstr(output, "ACCOUNT_ACCESS_EXEC_PASS uid=1000"));
    memset(output, 0, sizeof(output));
    CHECK(lseek(redirected[2], 0, SEEK_SET) == 0 &&
          read(redirected[2], output, sizeof(output) - 1) > 0);
    CHECK(!strcmp(output, "REDIRECT_STDERR\n"));
    for (int fd = 0; fd < 3; fd++)
        close(redirected[fd]);
    observed("actual_setuid_sudo_password_membership_private_tty_and_three_redirected_streams");
    char* passwd[] = {(char*)frontend, "passwd", NULL};
    start(&call, 1000, passwd, NULL);
    quiet_password(&call, password);
    confirmation(&call, changed, changed);
    finish(&call, 0);
    verify("admin", password, ACCOUNT_AUTH_DENIED);
    verify("admin", changed, ACCOUNT_AUTH_ACCEPTED);
    observed("ordinary_passwd_private_old_password_confirmation_atomic_change");
    CHECK(account_database_begin(database, 0, &db) == 0);
    struct account_user user = *account_database_user(db, "admin");
    user.age[1] = 1;
    CHECK(account_database_put_user(db, "admin", &user) == 0);
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    start(&call, 1000, passwd, NULL);
    quiet_password(&call, changed);
    confirmation(&call, password, password);
    finish(&call, 1);
    verify("admin", changed, ACCOUNT_AUTH_ACCEPTED);
    verify("admin", password, ACCOUNT_AUTH_DENIED);
    observed("ordinary_minimum_password_age_denies_update_and_preserves_previous_hash");
    CHECK(account_database_begin(database, 0, &db) == 0);
    user = *account_database_user(db, "admin");
    user.age[0] = 0;
    CHECK(account_database_put_user(db, "admin", &user) == 0);
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    start(&call, 0, login, NULL);
    quiet_password(&call, changed);
    until(&call, "A password change is required.");
    confirmation(&call, password, password);
    until(&call, "$ ");
    send(&call, "exit 0", 0);
    finish(&call, 0);
    verify("admin", password, ACCOUNT_AUTH_ACCEPTED);
    observed("forced_private_password_change_reauthenticates_before_login_shell");
    char aliases[4096], names[4][4096];
    path(aliases, argv[1], "aliases");
    CHECK(mkdir(aliases, 0755) == 0 && chmod(aliases, 0755) == 0);
    const char* modes[] = {"login", "su", "sudo", "passwd"};
    const char* actual = frontend;
    for (unsigned i = 0; i < 4; i++) {
        path(names[i], aliases, modes[i]);
        CHECK(symlink(actual, names[i]) == 0);
    }
    frontend = names[0];
    char* alias_login[] = {names[0], "admin", NULL};
    start(&call, 0, alias_login, NULL);
    quiet_password(&call, password);
    until(&call, "$ ");
    send(&call, "exit 0", 0);
    finish(&call, 0);
    observed("installed_login_alias_authenticates_before_starting_the_shell");
    frontend = names[1];
    CHECK(snprintf(command, sizeof(command), "%s 1000 %s", observer, home) < (int)sizeof(command));
    char* alias_su[] = {names[1], "-", "admin", "-c", command, NULL};
    start(&call, 0, alias_su, NULL);
    finish(&call, 0);
    CHECK(strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS uid=1000"));
    observed("installed_su_alias_accepts_login_flag_and_installs_complete_target_identity");
    frontend = names[2];
    char* alias_sudo[] = {names[2], (char*)observer, "0", "/root", NULL};
    start(&call, 1000, alias_sudo, NULL);
    quiet_password(&call, password);
    finish(&call, 0);
    CHECK(strstr(call.text, "ACCOUNT_ACCESS_EXEC_PASS uid=0"));
    observed("installed_sudo_alias_uses_actual_setuid_password_and_membership_policy");
    CHECK(account_database_begin(database, 0, &db) == 0);
    user = *account_database_user(db, "admin");
    user.age[1] = 0;
    CHECK(account_database_put_user(db, "admin", &user) == 0 &&
          account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    frontend = names[3];
    char* alias_passwd[] = {names[3], NULL};
    start(&call, 1000, alias_passwd, NULL);
    quiet_password(&call, password);
    confirmation(&call, changed, changed);
    finish(&call, 0);
    verify("admin", password, ACCOUNT_AUTH_DENIED);
    verify("admin", changed, ACCOUNT_AUTH_ACCEPTED);
    observed("installed_passwd_alias_privately_authenticates_confirms_and_publishes_own_password");
    frontend = actual;
    printf("ACCOUNT_ACCESS_PASS observations=%u\n", observations);
    return 0;
}
