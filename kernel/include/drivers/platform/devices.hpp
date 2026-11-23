// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/devices.hpp
 * @brief   Platform device discovery interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the platform routines that initialize and enumerate devices.
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
#pragma once
#include "fs/vfs.hpp"

namespace ax {
struct Task;
enum class Device {
    none,
    serial,
    tty,
    null,
    zero,
    random,
    framebuffer,
    keyboard,
    mouse,
    ptmx,
    pty_slave,
    vt,
    block,
    full,
    parallel,
    dsp,
    alsa_control,
    alsa_playback,
    drm_scanout
};

struct Terminal {
    uint32_t input, output, control, local;
    uint8_t line, cc[19];
};

static_assert(sizeof(Terminal) == 36);

struct ByteQueue {
    uint8_t bytes[16384];
    size_t head, size;
};

struct Pty {
    bool used, locked, io_error;
    unsigned id, masters, slaves;
    Node* slave;
    Terminal terminal;
    int pgid, sid;
    ByteQueue input, output;
    uint16_t rows, columns;
};

void devices_init(bool display_console, bool virtio_graphics, bool drm);

uint64_t device_number(Node*);

constexpr uint32_t device_major(uint64_t device) {
    return ((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000);
}

constexpr uint32_t device_minor(uint64_t device) {
    return (device & 0xff) | ((device >> 12) & 0xffffff00);
}

int device_open(Handle*);

void device_close(Handle*);

bool device_has_poll(const Handle&);
bool device_ready(Handle*, bool);

bool memory_device(const Handle&);
bool device_ignores_buffer(Handle*, bool write);

int64_t device_read(Handle*, void*, size_t);

int64_t device_write(Handle*, const void*, size_t);

int64_t device_ioctl(Handle*, uint64_t, uint64_t);

int64_t framebuffer_map(AddressSpace&, uint64_t, size_t, int, uint64_t);

void devices_poll();
void usb_keyboard_event(unsigned code, bool pressed);
void usb_mouse_event(int dx, int dy, uint8_t buttons, int wheel);

void terminal_exit(Task*);
} // namespace ax
