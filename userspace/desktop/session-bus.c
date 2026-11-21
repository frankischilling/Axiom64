// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/desktop/session-bus.c
 * @brief   Start the seat's private D-Bus daemon.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Binds the daemon's lifetime to dbus-run-session and selects a fresh address.
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // A console crash can kill the session leader before it can stop the
    // upstream daemon. Keep the kernel responsible for closing its socket.
    pid_t parent = getppid();
    if (parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 || getppid() != parent) {
        fputs("session bus: could not attach to session leader\n", stderr);
        return 1;
    }

    unsigned char random[16];
    if (getentropy(random, sizeof(random)) < 0) {
        perror("session bus: address entropy");
        return 1;
    }
    static const char prefix[] = "--address=unix:abstract=axiom64-session-";
    static const char hex[] = "0123456789abcdef";
    char address[sizeof(prefix) + 2 * sizeof(random)];
    memcpy(address, prefix, sizeof(prefix) - 1);
    char* digits = address + sizeof(prefix) - 1;
    for (size_t i = 0; i < sizeof(random); i++) {
        digits[2 * i] = hex[random[i] >> 4];
        digits[2 * i + 1] = hex[random[i] & 15];
    }
    digits[2 * sizeof(random)] = '\0';

    char** arguments = calloc((size_t)argc + 2, sizeof(*arguments));
    if (!arguments) {
        perror("session bus: daemon arguments");
        return 1;
    }
    arguments[0] = "/usr/bin/dbus-daemon";
    memcpy(arguments + 1, argv + 1, ((size_t)argc - 1) * sizeof(*argv));
    arguments[argc] = address;
    execv(arguments[0], arguments);
    perror("session bus: exec dbus-daemon");
    free(arguments);
    return 127;
}
