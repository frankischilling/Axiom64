// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/random/generation_exec.c
 * @brief   Random generation execution probe.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reports random subsystem behavior across a process execution boundary.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "GENERATION_EXEC_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

int main(void) {
    setbuf(stdout, NULL);
    struct termios terminal;
    require(tcgetattr(0, &terminal) == 0, "serial state");
    cfmakeraw(&terminal);
    require(tcsetattr(0, TCSANOW, &terminal) == 0, "raw serial barriers");
    unsigned char sample[16], before[16];
    unsigned char* original = (unsigned char*)getauxval(AT_RANDOM);
    require(original != NULL, "original auxiliary random bytes");
    memcpy(before, original, sizeof(before));
    require(getrandom(sample, sizeof(sample), GRND_NONBLOCK) == sizeof(sample),
            "initial ready source");
    puts("GENERATION_EXEC_READY");
    unsigned char barrier;
    require(read(0, &barrier, 1) == 1 && barrier == 'F', "failure barrier");
    errno = 0;
    require(getrandom(sample, sizeof(sample), GRND_INSECURE) == -1 && errno == EIO,
            "actual generation source read failure");
    puts("GENERATION_EXEC_SOURCE_ERROR error=5");
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        pid_t child = fork();
        require(child >= 0, "failed exec child");
        if (!child) {
            errno = 0;
            execl("/bin/busybox", "busybox", "echo", "GENERATION_UNEXPECTED_EXEC", (char*)0);
            require(errno == EIO, "exec source error propagation");
            require((unsigned char*)getauxval(AT_RANDOM) == original &&
                        !memcmp(original, before, sizeof(before)),
                    "failed exec preserves original memory and auxiliary vector");
            _exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0,
                "failed exec result");
    }
    errno = 0;
    require(getrandom(sample, sizeof(sample), GRND_INSECURE) == -1 && errno == EIO,
            "source error remains active through failed execs");
    puts("GENERATION_EXEC_DENIED errors=16 memory=preserved");
    require(read(0, &barrier, 1) == 1 && barrier == 'R', "recovery barrier");
    require(getrandom(sample, sizeof(sample), GRND_NONBLOCK) == sizeof(sample), "source recovery");
    pid_t child = fork();
    require(child >= 0, "recovered exec child");
    if (!child) {
        execl("/bin/busybox", "busybox", "echo", "GENERATION_RECOVERED_EXEC", (char*)0);
        _exit(127);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "recovered exec result");
    puts("GENERATION_EXEC_PASS denied=16 recovered=1");
    return 0;
}
