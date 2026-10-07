// SPDX-License-Identifier: GPL-3.0-or-later
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
    block
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
    bool used;
    unsigned id, masters, slaves;
    Terminal terminal;
    int pgid, sid;
    ByteQueue input, output;
    uint16_t rows, columns;
};

void devices_init();

uint64_t device_number(Node*);

bool device_open(Handle*);

void device_close(Handle*);

bool device_ready(Handle*, bool);

int64_t device_read(Handle*, void*, size_t);

int64_t device_write(Handle*, const void*, size_t);

int64_t device_ioctl(Handle*, uint64_t, uint64_t);

int64_t framebuffer_map(AddressSpace&, uint64_t, size_t, int, uint64_t);

void devices_poll();

void terminal_exit(Task*);
} // namespace ax
