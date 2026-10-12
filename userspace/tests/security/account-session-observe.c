// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
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
            fprintf(stderr, "ACCOUNT_SESSION_FAIL observer_line=%d errno=%d expression=%s\n",      \
                    __LINE__, errno, #expression);                                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    CHECK(argc == 8);
    uid_t uid = (uid_t)strtoul(argv[1], NULL, 10);
    gid_t gid = (gid_t)strtoul(argv[2], NULL, 10);
    pid_t sid = (pid_t)strtol(argv[4], NULL, 10);
    pid_t other = (pid_t)strtol(argv[6], NULL, 10);
    uid_t real, effective, saved;
    gid_t gr, ge, gs;
    CHECK(getresuid(&real, &effective, &saved) == 0);
    CHECK(real == uid && effective == uid && saved == uid && (uid_t)setfsuid(-1) == uid);
    CHECK(getresgid(&gr, &ge, &gs) == 0);
    CHECK(gr == gid && ge == gid && gs == gid && (gid_t)setfsgid(-1) == gid);
    gid_t groups[8];
    int count = getgroups(8, groups), primary = 0, shared = 0;
    CHECK(count == 2);
    for (int i = 0; i < count; i++) {
        primary |= groups[i] == gid;
        shared |= groups[i] == 1002;
    }
    CHECK(primary && shared);
    CHECK(getsid(0) == sid && tcgetsid(0) == sid && tcgetpgrp(0) == getpgrp());
    for (int fd = 0; fd < 3; fd++) {
        struct stat value;
        CHECK(isatty(fd) && fstat(fd, &value) == 0);
        CHECK(S_ISCHR(value.st_mode) && value.st_uid == uid && value.st_gid == gid);
        CHECK((value.st_mode & 0777) == 0600);
    }
    char cwd[4096];
    CHECK(getcwd(cwd, sizeof(cwd)) && strcmp(cwd, argv[3]) == 0);
    CHECK(getenv("HOME") && strcmp(getenv("HOME"), argv[3]) == 0);
    CHECK(getenv("USER") && strcmp(getenv("USER"), argv[7]) == 0);
    CHECK(getenv("LOGNAME") && strcmp(getenv("LOGNAME"), argv[7]) == 0);
    CHECK(getenv("TERM") && strcmp(getenv("TERM"), "vt100") == 0);
    CHECK(!getenv("LD_PRELOAD") && !getenv("LD_LIBRARY_PATH") && !getenv("SESSION_FORGED"));
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);

    struct {
        uint32_t version;
        int32_t pid;
    } header = {0x20080522, 0};

    struct {
        uint32_t effective, permitted, inheritable;
    } capabilities[2] = {{0}, {0}};

    CHECK(syscall(SYS_capget, &header, capabilities) == 0);
    CHECK(!capabilities[0].effective && !capabilities[0].permitted &&
          !capabilities[0].inheritable && !capabilities[1].effective &&
          !capabilities[1].permitted && !capabilities[1].inheritable);
    CHECK(open(argv[5], O_RDONLY) == -1 && errno == EACCES);
    CHECK(kill(other, 0) == -1 && errno == EPERM);
    CHECK(setuid(0) == -1 && errno == EPERM);
    int file = open("session-created", O_WRONLY | O_CREAT | O_EXCL, 0666);
    CHECK(file >= 0 && write(file, "session", 7) == 7);
    struct stat value;
    CHECK(fstat(file, &value) == 0 && value.st_uid == uid && value.st_gid == gid);
    CHECK((value.st_mode & 0777) == 0600);
    close(file);
    printf("ACCOUNT_SHELL_SESSION_PASS user=%s uid=%u gid=%u sid=%d foreground=1 private_tty=1 "
           "cross_user_denied=1\n",
           argv[7], (unsigned)uid, (unsigned)gid, (int)sid);
    return 0;
}
