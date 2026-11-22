// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/init/console.h
 * @brief   Init console interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares terminal setup, logging, and console supervision helpers used by
 * init.
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
#ifndef AXIOM64_INIT_CONSOLE_H
#define AXIOM64_INIT_CONSOLE_H
#include <sys/types.h>
#include <termios.h>
#include <time.h>

struct init_console {
    pid_t pid;
    int flags;
    int graphical;
    const char* services;
    struct termios original;
    struct timespec retry;
};

// Capture init's physical terminal once. The child claims a new controlling
// session and runs only the authenticated console. Failure never starts a shell.
int init_console_initialize(struct init_console*, const struct timespec*, int graphical,
                            const char* services);
// Consume matching reaps, retire remaining physical-console workers, restore
// flags/settings/input, and retry fork/exec failure after a real second.
int init_console_update(struct init_console*, pid_t reaped, int status, const struct timespec*);

#endif
