// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/boot-media.c
 * @brief   Read the boot module from the first userspace process.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Reports a token read from the initramfs, then shuts down the guest.
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
#include <fcntl.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char token[33] = {0};
    int fd = open("/boot-proof", O_RDONLY);
    if (argc != 1 || getpid() != 1 || fd < 0 ||
        read(fd, token, sizeof(token)) != sizeof(token) - 1 || close(fd))
        return 1;
    printf("BOOT_MEDIA_PASS %s %s\n", argv[0], token);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
