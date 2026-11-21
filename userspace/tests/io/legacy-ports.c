// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/io/legacy-ports.c
 * @brief   Exercise the guest UART and parallel printer nodes.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks device metadata, absent mappings, access control, and binary writes.
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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int device(const char* path, int present, unsigned id, unsigned minor_id) {
    struct stat st;
    if (!present)
        return stat(path, &st) == -1 && errno == ENOENT ? 0 : -1;
    if (stat(path, &st) || !S_ISCHR(st.st_mode) || (st.st_mode & 0777) != 0600 || st.st_uid ||
        st.st_gid || major(st.st_rdev) != id || minor(st.st_rdev) != minor_id)
        return -1;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (!pid) {
        if (setgid(1000) || setuid(1000))
            _exit(1);
        int fd = open(path, O_WRONLY | O_NOCTTY);
        _exit(fd < 0 && errno == EACCES ? 0 : 1);
    }
    int status;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0
                                                                                            : -1;
}

static int emit(const char* path, const void* data, size_t length, int printer) {
    int fd = open(path, O_RDWR | O_NOCTTY);
    char byte;
    if (fd < 0 || (printer && (read(fd, &byte, 1) != -1 || errno != EINVAL)) ||
        write(fd, data, 0) != 0 || write(fd, data, length) != (ssize_t)length || close(fd))
        return -1;
    return 0;
}

static int receive(void) {
    static const char expected[] = "legacy-port-input\n";
    int fd = open("/dev/ttyS0", O_RDONLY | O_NOCTTY);
    if (fd < 0)
        return -1;
    puts("LEGACY_UART_READY");
    fflush(stdout);
    char input[sizeof(expected)];
    ssize_t bytes = read(fd, input, sizeof(input));
    return close(fd) || bytes != sizeof(expected) - 1 || memcmp(input, expected, bytes) ? -1 : 0;
}

int main(void) {
    char flags[2];
    int fd = open("/legacy-ports", O_RDONLY);
    if (fd < 0 || read(fd, flags, sizeof(flags)) != sizeof(flags) || close(fd))
        return 1;
    int uart = flags[0] == '1';
    int printer = flags[1] == '1';
    if (device("/dev/console", 1, 5, 1) || device("/dev/ttyS0", uart, 4, 64) ||
        device("/dev/lp0", printer, 6, 0))
        return 1;
    static const char message[] = "LEGACY_UART_PAYLOAD\n";
    if (uart && (emit("/dev/ttyS0", message, sizeof(message) - 1, 0) || receive()))
        return 1;
    static const uint8_t payload[] = {0x41, 0, 0xff, '\n', '\r', 0x7f, 0x42};
    if (printer && emit("/dev/lp0", payload, sizeof(payload), 1))
        return 1;
    printf("LEGACY_PORTS_PASS uart=%d printer=%d\n", uart, printer);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
