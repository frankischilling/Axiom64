// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/database.h"
#include "../../accounts/logbook.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_NORMAL_FAIL line=%d errno=%d expression=%s\n", __LINE__,      \
                    errno, #expression);                                                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int identity(void) {
    uid_t real, effective, saved;
    gid_t gr, ge, gs;
    CHECK(getresuid(&real, &effective, &saved) == 0 && real == 1000 && effective == 1000 &&
          saved == 1000 && (uid_t)setfsuid(-1) == 1000);
    CHECK(getresgid(&gr, &ge, &gs) == 0 && gr == 1000 && ge == 1000 && gs == 1000 &&
          (gid_t)setfsgid(-1) == 1000);
    gid_t groups[8];
    int count = getgroups(8, groups), primary = 0, sudo = 0;
    CHECK(count == 2);
    for (int i = 0; i < count; i++) {
        primary |= groups[i] == 1000;
        sudo |= groups[i] == 27;
    }
    CHECK(primary && sudo);
    char cwd[4096];
    CHECK(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/home/admin"));
    CHECK(getenv("HOME") && !strcmp(getenv("HOME"), cwd));
    CHECK(getenv("USER") && !strcmp(getenv("USER"), "admin"));
    CHECK(getenv("LOGNAME") && !strcmp(getenv("LOGNAME"), "admin"));
    CHECK(getenv("SHELL") && !strcmp(getenv("SHELL"), "/bin/bash"));
    CHECK(!getenv("LD_PRELOAD") && !getenv("LD_LIBRARY_PATH"));
    struct passwd* user = getpwnam("admin");
    CHECK(user && user->pw_uid == 1000 && user->pw_gid == 1000 && !strcmp(user->pw_dir, cwd) &&
          !strcmp(user->pw_shell, "/bin/bash"));
    struct group* group = getgrnam("sudo");
    CHECK(group && group->gr_gid == 27 && group->gr_mem && group->gr_mem[0] &&
          !strcmp(group->gr_mem[0], "admin"));
    errno = 0;
    CHECK(!getspnam("admin") && errno == EACCES);
    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && tcgetsid(tty) == getsid(0) && tcgetpgrp(tty) == getpgrp());
    struct stat value;
    // /dev/tty has its own alias inode; standard input is the owned PTY slave.
    CHECK(fstat(0, &value) == 0 && value.st_uid == 1000 && value.st_gid == 1000 &&
          (value.st_mode & 07777) == 0600);
    close(tty);

    struct {
        uint32_t version;
        int32_t pid;
    } header = {0x20080522, 0};

    struct {
        uint32_t effective, permitted, inheritable;
    } caps[2] = {{0}, {0}};

    CHECK(syscall(SYS_capget, &header, caps) == 0 && !caps[0].effective && !caps[0].permitted &&
          !caps[0].inheritable && !caps[1].effective && !caps[1].permitted && !caps[1].inheritable);
    CHECK(setuid(0) == -1 && errno == EPERM);
    int file = open("persisted-account", O_RDWR | O_CREAT, 0666);
    CHECK(file >= 0 && fstat(file, &value) == 0 && value.st_uid == 1000 && value.st_gid == 1000 &&
          (value.st_mode & 07777) == 0600);
    const char bytes[] = "Axiom64 authenticated persistent file\n";
    if (!value.st_size)
        CHECK(write(file, bytes, sizeof(bytes) - 1) == (ssize_t)(sizeof(bytes) - 1) &&
              fsync(file) == 0);
    CHECK(lseek(file, 0, SEEK_SET) == 0);
    char content[sizeof(bytes)] = {0};
    CHECK(read(file, content, sizeof(content)) == (ssize_t)(sizeof(bytes) - 1) &&
          !strcmp(content, bytes));
    close(file);
    puts("ACCOUNT_NORMAL_IDENTITY_PASS uid=1000 gid=1000 groups=2 private_tty=1 lookup=1 "
         "shadow_denied=1 persisted=1");
    return 0;
}

static int protected_state(void) {
    CHECK(!getuid() && !geteuid() && !getegid());
    struct account_database* db = NULL;
    CHECK(account_database_begin("/etc/axiom64/accounts", 0, &db) == 0 &&
          !account_database_fresh(db));
    const struct account_user* admin = account_database_user(db, "admin");
    CHECK(admin && admin->uid == 1000 && admin->gid == 1000 &&
          !strcmp(admin->home, "/home/admin") && !strcmp(admin->shell, "/bin/bash"));
    const struct account_user* root = account_database_user(db, "root");
    CHECK(root && root->uid == 0 && root->password[0] == '!');
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open("/var/log/axiom64/login", 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 1 && account_logbook_active(book, 0) == 1);
    account_logbook_close(book);
    account_database_end(db);
    struct stat value;
    CHECK(stat("/etc/shadow", &value) == 0 && value.st_uid == 0 && value.st_gid == 0 &&
          (value.st_mode & 07777) == 0600 && value.st_nlink == 1);
    CHECK(stat("/var/run/utmp", &value) == 0 && value.st_uid == 0 &&
          (value.st_mode & 07777) == 0644 && value.st_size >= 384);
    CHECK(stat("/home/admin", &value) == 0 && value.st_uid == 1000 && value.st_gid == 1000 &&
          (value.st_mode & 07777) == 0700);
    puts("ACCOUNT_NORMAL_PROTECTED_PASS root_locked=1 shadow=600 home=700 live_admin=1 live_root=1 "
         "utmp=1");
    return 0;
}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "identity"))
        return identity();
    if (!strcmp(argv[1], "protected"))
        return protected_state();
    if (!strcmp(argv[1], "poweroff")) {
        CHECK(protected_state() == 0);
        fflush(stdout);
        CHECK(syscall(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc, NULL) == 0);
    }
    return 1;
}
