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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <unistd.h>

static int check_framebuffer(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    volatile uint8_t* pixels = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pixels == MAP_FAILED)
        return -1;
    uint8_t original = pixels[0];
    uint8_t color = original ^ 0xff;
    pixels[0] = color;
    int ok = pixels[0] == color;
    pixels[0] = original;
    if (munmap((void*)pixels, page) || close(fd) || !ok)
        return -1;
    puts("BOOT_MEDIA_FRAMEBUFFER_PASS");
    return 0;
}

int main(int argc, char** argv) {
    char token[33] = {0};
    int fd = open("/boot-proof", O_RDONLY);
    if (argc != 1 || getpid() != 1 || fd < 0 ||
        read(fd, token, sizeof(token)) != sizeof(token) - 1 || close(fd) || check_framebuffer())
        return 1;
    printf("BOOT_MEDIA_PASS %s %s\n", argv[0], token);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
