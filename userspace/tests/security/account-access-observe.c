// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv) {
    if (argc < 3)
        return 1;
    uid_t uid = (uid_t)strtoul(argv[1], NULL, 10), real, effective, saved;
    gid_t gr, ge, gs;
    char home[4096];
    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (getresuid(&real, &effective, &saved) < 0 || getresgid(&gr, &ge, &gs) < 0 || real != uid ||
        effective != uid || saved != uid || gr != uid || ge != uid || gs != uid ||
        !getcwd(home, sizeof(home)) || strcmp(home, argv[2]) || !getenv("HOME") ||
        strcmp(getenv("HOME"), argv[2]) || getenv("ACCESS_FORGED") || tty < 0 ||
        tcgetsid(tty) != getsid(0) || tcgetpgrp(tty) != getpgrp())
        return 1;
    close(tty);
    if (argc == 4) {
        char payload[16] = {0};
        if (read(0, payload, sizeof(payload)) != 13 || memcmp(payload, "redirect-data", 13))
            return 1;
        fputs("REDIRECT_STDERR\n", stderr);
    }
    printf("ACCOUNT_ACCESS_EXEC_PASS uid=%u home=%s\n", (unsigned)uid, home);
    return 0;
}
