// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_INIT_CONSOLE_H
#define AXIOM64_INIT_CONSOLE_H
#include <sys/types.h>
#include <termios.h>
#include <time.h>

struct init_console {
    pid_t pid;
    int flags;
    struct termios original;
    struct timespec retry;
};

// Capture init's physical terminal once. The child claims a new controlling
// session and runs only the authenticated console. Failure never starts a shell.
int init_console_initialize(struct init_console*, const struct timespec*);
// Consume matching reaps, retire remaining physical-console workers, restore
// flags/settings/input, and retry fork/exec failure after a real second.
int init_console_update(struct init_console*, pid_t reaped, int status, const struct timespec*);

#endif
