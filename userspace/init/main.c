// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t console(void) {
    pid_t child = fork();
    if (!child) {
        if (setsid() < 0 || ioctl(0, TIOCSCTTY, 0) < 0) {
            perror("init: console session");
            _exit(1);
        }
        execl("/bin/busybox", "busybox", "sh", "-i", (char*)0);
        perror("init: console exec");
        _exit(1);
    }
    return child;
}

int main(void) {
    const char* test = getenv("AXIOM64_TEST");
    const char* suite = getenv("AXIOM64_SUITE");
    if (test && *test == '1') {
        const char* script = suite && !strcmp(suite, "storage")   ? "/etc/storage-test.sh"
                             : suite && !strcmp(suite, "ext2")    ? "/etc/ext2-test.sh"
                             : suite && !strcmp(suite, "threads") ? "/etc/thread-test.sh"
                             : suite && !strcmp(suite, "desktop") ? "/etc/desktop-test.sh"
                                                                  : "/etc/boot-test.sh";
        execl("/bin/busybox", "busybox", "sh", script, (char*)0);
    } else {
        puts("Axiom64. Starting Xorg, twm, and Bash; ash is available on the serial console.");
        pid_t desktop = fork();
        if (!desktop) {
            int input = open("/dev/null", O_RDONLY);
            if (input >= 0) {
                dup2(input, 0);
                close(input);
            }
            execl("/bin/busybox", "busybox", "sh", "/usr/bin/startx", (char*)0);
            perror("init: desktop exec");
            _exit(1);
        }
        if (desktop < 0) {
            perror("init: desktop fork");
            return 1;
        }
        pid_t shell = console();
        if (shell < 0) {
            perror("init: console fork");
            return 1;
        }
        for (;;) {
            int status;
            pid_t child = waitpid(-1, &status, 0);
            if (child < 0) {
                if (errno == EINTR)
                    continue;
                perror("init: wait");
                return 1;
            }
            if (child == shell) {
                puts("Console shell exited; starting a new ash session.");
                shell = console();
                if (shell < 0)
                    return 1;
            } else if (child == desktop) {
                puts("Desktop session ended. Run startx from the console to open it again.");
            }
        }
    }
    perror("init: exec");
    return 1;
}
