// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/desktop/virtio-gpu.c
 * @brief   Draws through the guest framebuffer.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Validates framebuffer geometry and draws two frames for host capture.
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
#include <linux/fb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "VIRTIO_GPU_FAIL line=%d errno=%d: %s\n", __LINE__, errno,             \
                    #expression);                                                                  \
            reboot(RB_POWER_OFF);                                                                  \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void paint(volatile uint32_t* pixels, const struct fb_var_screeninfo* var, unsigned stride,
                  unsigned frame) {
    static const uint32_t colors[4] = {0xff0000, 0x00ff00, 0x0000ff, 0xffffff};
    for (unsigned y = 0; y < var->yres; ++y) {
        for (unsigned x = 0; x < var->xres; ++x) {
            unsigned quadrant = (y >= var->yres / 2) * 2 + (x >= var->xres / 2);
            pixels[y * stride + x] = colors[(quadrant + frame) % 4];
        }
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int fd = open("/dev/fb0", O_RDWR);
    CHECK(fd >= 0);
    struct fb_fix_screeninfo fix;
    struct fb_var_screeninfo var;
    CHECK(ioctl(fd, FBIOGET_FSCREENINFO, &fix) == 0);
    CHECK(ioctl(fd, FBIOGET_VSCREENINFO, &var) == 0);
    if (access("/gpu-fallback", F_OK) == 0) {
        CHECK(!strcmp(fix.id, "Axiom64 fb"));
        puts("VIRTIO_GPU_FIRMWARE_FALLBACK");
        reboot(RB_POWER_OFF);
        return 1;
    }

    CHECK(!strcmp(fix.id, "Axiom64 virtio"));
    CHECK(var.xres == 800 && var.yres == 600);
    CHECK(var.xres == var.xres_virtual && var.yres == var.yres_virtual);
    CHECK(var.bits_per_pixel == 32 && fix.line_length == 4 * var.xres);
    CHECK(fix.smem_len == fix.line_length * var.yres);
    CHECK(var.red.offset == 16 && var.green.offset == 8 && var.blue.offset == 0);
    size_t size = fix.smem_len;
    off_t outside = (size + 4095) & ~4095ul;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, outside) == MAP_FAILED && errno == EINVAL);
    volatile uint32_t* pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(pixels != MAP_FAILED);
    CHECK(ioctl(fd, FBIOPAN_DISPLAY, NULL) == -1 && errno == EFAULT);
    var.xoffset = 1;
    CHECK(ioctl(fd, FBIOPAN_DISPLAY, &var) == -1 && errno == EINVAL);
    var.xoffset = 0;

    paint(pixels, &var, fix.line_length / sizeof(uint32_t), 0);
    CHECK(ioctl(fd, FBIOPAN_DISPLAY, &var) == 0);
    puts("VIRTIO_GPU_FRAME_ONE");
    CHECK(getchar() == '\n');
    // The second frame must appear without a presentation ioctl.
    paint(pixels, &var, fix.line_length / sizeof(uint32_t), 1);
    puts("VIRTIO_GPU_FRAME_TWO");
    CHECK(getchar() == '\n');
    CHECK(munmap((void*)pixels, size) == 0);
    CHECK(close(fd) == 0);
    puts("VIRTIO_GPU_GUEST_PASS");
    reboot(RB_POWER_OFF);
    return 1;
}
