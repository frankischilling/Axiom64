// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

int main(void) {
    uid_t uid, effective, saved;
    gid_t gid, group_effective, group_saved;
    struct stat terminal;
    if (getresuid(&uid, &effective, &saved) < 0 || !uid || effective != uid || saved != uid ||
        getresgid(&gid, &group_effective, &group_saved) < 0 || group_effective != gid ||
        group_saved != gid || !isatty(0) || fstat(0, &terminal) < 0 || !S_ISCHR(terminal.st_mode) ||
        terminal.st_uid != uid || terminal.st_gid != gid || terminal.st_nlink != 1 ||
        tcgetsid(0) != getsid(0) || tcgetpgrp(0) != getpgrp()) {
        fputs("desktop-terminal: an owned ordinary-user foreground terminal is required\n", stderr);
        return 1;
    }
    // Use the retained slave descriptor. A tty pathname or /dev/tty alias does
    // not necessarily identify this PTY's ownership inode.
    if (fchmod(0, 0600) < 0 || fstat(0, &terminal) < 0 || (terminal.st_mode & 07777) != 0600) {
        perror("desktop-terminal: private terminal permissions");
        return 1;
    }
    const char* shell = getenv("SHELL");
    const char* user = getenv("USER");
    if (!shell || shell[0] != '/' || !user || !*user) {
        fputs("desktop-terminal: authenticated shell environment is missing\n", stderr);
        return 1;
    }
    umask(077);
    printf("\033[2J\033[HAxiom64\n\nSigned in as %.32s.\n\n", user);
    fflush(stdout);
    execl(shell, shell, "-l", (char*)NULL);
    perror("desktop-terminal: shell exec");
    return 127;
}
