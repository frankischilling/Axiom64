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
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <unistd.h>

static int check_usb_input(void) {
    enum { key_a = 30, key_b = 48, button_left = 272 };

    struct input_event {
        int64_t seconds, microseconds;
        uint16_t type, code;
        int32_t value;
    } event;
    struct pollfd devices[] = {{open("/dev/input/event0", O_RDONLY), POLLIN, 0},
                               {open("/dev/input/event1", O_RDONLY), POLLIN, 0}};
    if (devices[0].fd < 0 || devices[1].fd < 0)
        return -1;
    unsigned keys[2] = {0}, button = 0;
    int dx = 0, dy = 0;
    puts("BOOT_USB_INPUT_READY");
    fflush(stdout);
    for (unsigned i = 0; i < 32; ++i) {
        if (poll(devices, 2, 8000) <= 0)
            return -1;
        for (unsigned j = 0; j < 2; ++j) {
            if (!(devices[j].revents & POLLIN))
                continue;
            if (read(devices[j].fd, &event, sizeof(event)) != sizeof(event))
                return -1;
            if (!j && event.type == 1 && (event.code == key_a || event.code == key_b)) {
                unsigned* state = &keys[event.code == key_b];
                if (*state > 1 || event.value != (int)(1 - *state))
                    return -1;
                ++*state;
            }
            if (j && event.type == 2 && event.code == 0)
                dx += event.value;
            if (j && event.type == 2 && event.code == 1)
                dy += event.value;
            if (j && event.type == 1 && event.code == button_left) {
                if (button > 1 || event.value != (int)(1 - button))
                    return -1;
                if (++button == 1) {
                    puts("BOOT_USB_MOUSE_PRESSED");
                    fflush(stdout);
                }
            }
        }
        if (keys[0] == 2 && keys[1] == 2 && button == 2 && dx == 31 && dy == -19) {
            puts("BOOT_USB_INPUT_PASS");
            return close(devices[0].fd) || close(devices[1].fd) ? -1 : 0;
        }
    }
    return -1;
}

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
        read(fd, token, sizeof(token)) != sizeof(token) - 1 || close(fd) || check_framebuffer() ||
        (!access("/boot-usb-input", F_OK) && check_usb_input()))
        return 1;
    printf("BOOT_MEDIA_PASS %s %s\n", argv[0], token);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
