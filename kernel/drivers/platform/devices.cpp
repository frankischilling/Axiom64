// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/devices.cpp
 * @brief   Built-in device nodes.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Connects console, terminal, input, and other built-in devices to the kernel's
 * file interfaces.
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
#include "drivers/platform/devices.hpp"
#include "drivers/platform/virtual_console.hpp"
#include "drivers/graphics/virtio_gpu.hpp"
#include "drivers/platform/legacy_io.hpp"
#include "drivers/block/block.hpp"
#include "drivers/block/floppy.hpp"
#include "drivers/block/nvme.hpp"
#include "drivers/platform/fb_console.hpp"
#include "drivers/usb/xhci.hpp"
#include "drivers/audio/alsa_pcm.hpp"
#include "drivers/audio/pcm.hpp"
#include "boot/boot.hpp"
#include "process/signals.hpp"
#include "process/task.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"

namespace ax {
static const BootFramebuffer* framebuffer;
static bool virtio_framebuffer;
static Pty ptys[32];
static constexpr Terminal default_terminal{0x500,  5, 0xbf,
                                           0x8a3b, 0, {3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26}};
static Terminal console_terminal = default_terminal;
static ByteQueue console_input;
static int console_pgid = 1, console_sid = 1, vt_mode = 0, keyboard_mode = 1;

struct InputEvent {
    int64_t sec, usec;
    uint16_t type, code;
    int32_t value;
};

struct InputQueue {
    InputEvent events[256];
    uint64_t sequence;
};

static InputQueue keyboard_events, mouse_events;
static uint8_t keys[96], ps2_keys[96], usb_keys[96];
static bool extended, console_keyboard, console_caps_lock;
static uint8_t mouse_packet[3], mouse_offset, ps2_mouse_buttons, usb_mouse_buttons;
static bool ps2_present;
static bool mouse_ack_pending;

static bool console_output(char character) {
    fb_console_put(character);
    return !serial_present() || serial_put(character);
}

static bool key_down(unsigned code) {
    return (keys[code / 8] & (1u << (code % 8))) != 0;
}

static unsigned char console_key(unsigned code) {
    // The i8042 driver publishes translated set-1 positions to evdev and the console.
    static constexpr char plain[] =
        "\0\033"
        "1234567890-=\177\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
    static constexpr char shifted[] =
        "\0\033"
        "!@#$%^&*()_+\177\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";
    static_assert(sizeof(plain) == sizeof(shifted) && sizeof(plain) == 59);
    if (code == 96) // Keypad Enter.
        return '\n';
    if (code >= sizeof(plain) || key_down(56) || key_down(100))
        return 0;
    const auto letter = plain[code] >= 'a' && plain[code] <= 'z';
    if (letter && (key_down(29) || key_down(97)))
        return plain[code] - 'a' + 1;
    const bool shift = key_down(42) || key_down(54);
    return shift != (letter && console_caps_lock) ? shifted[code] : plain[code];
}

static void terminal_signal(int pgid, int signal) {
    if (pgid <= 0)
        return;
    for (auto& task : tasks)
        if (task.state != State::empty && task.process->leader == &task &&
            task.process->pgid == pgid)
            queue_process_signal(task.process, signal);
}

static void detach_pty(Pty* p, bool hangup = true) {
    if (hangup) {
        terminal_signal(p->pgid, 1);
        terminal_signal(p->pgid, 18);
    }
    for (auto& task : tasks)
        if (task.state != State::empty && task.process->controlling_pty == p)
            task.process->controlling_pty = nullptr;
    p->sid = p->pgid = 0;
}

static void detach_console(bool hangup) {
    if (hangup) {
        terminal_signal(console_pgid, 1);
        terminal_signal(console_pgid, 18);
    }
    for (auto& task : tasks)
        if (task.state != State::empty)
            task.process->controlling_console = false;
    console_sid = console_pgid = 0;
}

static int64_t attach_console(Handle* h, bool force) {
    auto process = current_task()->process;
    if (process->pid == process->sid && process->controlling_console && process->sid == console_sid)
        return 0;
    if (process->pid != process->sid || process->controlling_pty || process->controlling_console)
        return -1;
    if (console_sid && console_sid != process->sid) {
        if (!force || !capable(current_task()->credentials, Capability::sys_admin))
            return -1;
        detach_console(false);
    }
    if ((h->flags & 3) == 1 && !capable(current_task()->credentials, Capability::sys_admin))
        return -1;
    console_sid = process->sid;
    console_pgid = process->pgid;
    process->controlling_console = true;
    return 0;
}

void terminal_exit(Task* task) {
    if (task->process->controlling_pty && task->process->pid == task->process->sid)
        detach_pty(task->process->controlling_pty);
    if (task->process->controlling_console && task->process->pid == task->process->sid &&
        task->process->sid == console_sid)
        detach_console(true);
    task->process->controlling_pty = nullptr;
    task->process->controlling_console = false;
}

static int64_t attach_pty(Handle* h, bool force) {
    auto p = h->pty;
    if (current_task()->process->pid == current_task()->process->sid &&
        current_task()->process->controlling_pty == p)
        return 0;
    if (current_task()->process->pid != current_task()->process->sid ||
        current_task()->process->controlling_pty || current_task()->process->controlling_console)
        return -1;
    if (p->sid && p->sid != current_task()->process->sid) {
        if (!force || !capable(current_task()->credentials, Capability::sys_admin))
            return -1;
        detach_pty(p, false);
    }
    if ((h->flags & 3) == 1 && !capable(current_task()->credentials, Capability::sys_admin))
        return -1;
    p->sid = current_task()->process->sid;
    p->pgid = current_task()->process->pgid;
    current_task()->process->controlling_pty = p;
    return 0;
}

static void queue_put(ByteQueue& q, uint8_t value) {
    if (q.size < sizeof(q.bytes)) {
        q.bytes[(q.head + q.size) % sizeof(q.bytes)] = value;
        q.size++;
    }
}

static size_t queue_read(ByteQueue& q, void* data, size_t len) {
    len = min(len, q.size);
    auto output = (uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        output[i] = q.bytes[q.head];
        q.head = (q.head + 1) % sizeof(q.bytes);
    }
    q.size -= len;
    return len;
}

static bool canonical_ready(const ByteQueue& q, const Terminal& term) {
    if (!(term.local & 2))
        return q.size;
    for (size_t i = 0; i < q.size; i++) {
        auto c = q.bytes[(q.head + i) % sizeof(q.bytes)];
        if (c == '\n' || c == term.cc[4])
            return true;
    }
    return false;
}

static int64_t terminal_read(ByteQueue& q, const Terminal& term, void* data, size_t len) {
    if (!len)
        return 0;
    if (!canonical_ready(q, term))
        return -11;
    if (!(term.local & 2))
        return queue_read(q, data, len);
    size_t count = 0;
    auto output = (uint8_t*)data;
    while (count < len && q.size) {
        uint8_t c;
        queue_read(q, &c, 1);
        if (c == term.cc[4])
            break;
        output[count++] = c;
        if (c == '\n')
            break;
    }
    return count;
}

static void terminal_input(ByteQueue& input, ByteQueue* echo, const Terminal& term, int pgid,
                           uint8_t c) {
    if ((term.local & 1) && c && (c == term.cc[0] || c == term.cc[1] || c == term.cc[10])) {
        terminal_signal(pgid, c == term.cc[0] ? 2 : c == term.cc[1] ? 3 : 20);
        if (!(term.local & 0x80)) {
            input.head = input.size = 0;
            if (echo)
                echo->head = echo->size = 0;
        }
        return;
    }
    if ((term.input & 0x100) && c == '\r')
        c = '\n';
    if ((term.local & 2) && (c == term.cc[2] || c == 8)) {
        if (input.size)
            input.size--;
        if (term.local & 8) {
            if (echo) {
                queue_put(*echo, 8);
                queue_put(*echo, ' ');
                queue_put(*echo, 8);
            } else {
                console_output('\b');
                console_output(' ');
                console_output('\b');
            }
        }
        return;
    }
    queue_put(input, c);
    if (term.local & 8) {
        if (echo)
            queue_put(*echo, c);
        else
            console_output(c);
    }
}

static void tag(const char* path, Device type, unsigned id = 0) {
    Node* n = lookup(path);
    if (!n)
        n = make_node(path, character | 0666);
    if (!n)
        panic("device creation");
    n->device = type;
    n->device_id = id;
    if (type == Device::serial || type == Device::vt || type == Device::keyboard ||
        type == Device::mouse || type == Device::framebuffer || type == Device::parallel) {
        n->mode = character | 0600;
        n->uid = n->gid = 0;
    }
}

static void tag_audio(const char* path, Device type) {
    tag(path, type);
    auto* node = lookup(path);
    node->mode = character | 0660;
    node->uid = 0;
    node->gid = 29; // audio
}

static void number_path(char* out, const char* prefix, unsigned number) {
    size_t length = strlen(prefix);
    memcpy(out, prefix, length);
    char digits[16];
    size_t count = 0;
    do {
        digits[count++] = '0' + number % 10;
        number /= 10;
    } while (number);
    while (count)
        out[length++] = digits[--count];
    out[length] = 0;
}

static bool inventory_directory(const char* path) {
    if (auto node = lookup(path, false))
        return (node->mode & 0170000) == directory;
    return make_node(path, directory | 0755);
}

static bool inventory_attribute(const char* parent, const char* name, const char* value) {
    char path[64];
    const size_t prefix = strlen(parent), suffix = strlen(name);
    if (prefix + suffix + 2 > sizeof(path))
        return false;
    memcpy(path, parent, prefix);
    path[prefix] = '/';
    memcpy(path + prefix + 1, name, suffix + 1);
    const size_t length = strlen(value);
    auto bytes = static_cast<uint8_t*>(alloc(length + 1));
    if (!bytes)
        return false;
    auto node = make_node(path, regular_file | 0444);
    if (!node) {
        release(bytes);
        return false;
    }
    memcpy(bytes, value, length);
    bytes[length] = '\n';
    node->data = bytes;
    node->size = node->capacity = length + 1;
    node->owned = true;
    return true;
}

static void publish_nvme_inventory() {
    constexpr const char* parents[] = {"/sys", "/sys/class", "/sys/class/nvme"};
    bool parent_ready = false;
    for (unsigned controller = 0; controller < nvme_controller_slots; ++controller) {
        NvmeIdentity identity;
        if (!nvme_identity(controller, identity))
            continue;
        if (!parent_ready) {
            for (const auto path : parents)
                if (!inventory_directory(path))
                    return;
            parent_ready = true;
        }
        char path[64];
        number_path(path, "/sys/class/nvme/nvme", controller);
        if (!inventory_directory(path) || !inventory_attribute(path, "model", identity.model) ||
            !inventory_attribute(path, "serial", identity.serial) ||
            !inventory_attribute(path, "firmware_rev", identity.firmware))
            log("nvme: could not publish identity for controller=%u\n", uint64_t(controller));
    }
}

static bool controller_wait(bool output) {
    for (unsigned i = 0; i < 100000; i++) {
        uint8_t status = in8(0x64);
        if (output ? status & 1 : !(status & 2))
            return true;
    }
    return false;
}

void devices_init(bool display_console, bool virtio_graphics) {
    framebuffer = virtio_graphics ? virtio_gpu_scanout_init() : nullptr;
    virtio_framebuffer = framebuffer != nullptr;
    if (!framebuffer && boot_info.framebuffer.address)
        framebuffer = &boot_info.framebuffer;
    if (framebuffer) {
        tag("/dev/fb0", Device::framebuffer);
        // Expose the firmware framebuffer through the platform device interface.
        const char* paths[] = {"/sys",
                               "/sys/class",
                               "/sys/class/graphics",
                               "/sys/class/graphics/fb0",
                               "/sys/class/graphics/fb0/device",
                               "/sys/bus",
                               "/sys/bus/platform"};
        for (auto path : paths)
            if (!lookup(path) && !make_node(path, directory | 0755))
                panic("framebuffer metadata");
        Node* subsystem = make_node("/sys/class/graphics/fb0/device/subsystem", symlink | 0777);
        const char* target = "/sys/bus/platform";
        if (!subsystem || !(subsystem->data = (uint8_t*)alloc(strlen(target) + 1)))
            panic("framebuffer subsystem");
        memcpy(subsystem->data, target, strlen(target) + 1);
        subsystem->size = strlen(target);
        subsystem->capacity = subsystem->size + 1;
        subsystem->owned = true;
        log("Framebuffer: %ux%u pitch=%u bpp=%u\n", framebuffer->width, framebuffer->height,
            framebuffer->pitch, uint64_t(framebuffer->bpp));
        if (display_console)
            console_keyboard = fb_console_init(*framebuffer);
    }
    legacy_pnp_init();
    tag("/dev/console", Device::serial, 0x501);
    tag("/dev/tty", Device::tty);
    if (serial_present())
        tag("/dev/ttyS0", Device::serial, 0x440);
    if (parallel_present())
        tag("/dev/lp0", Device::parallel);
    tag("/dev/null", Device::null);
    tag("/dev/zero", Device::zero);
    tag("/dev/full", Device::full);
    tag("/dev/random", Device::random, 8);
    tag("/dev/urandom", Device::random, 9);
    if (Pcm::initialize()) {
        tag_audio("/dev/dsp", Device::dsp);
        if (Pcm::output_available()) {
            if (!lookup("/dev/snd") && !make_node("/dev/snd", directory | 0755))
                panic("sound device directory");
            tag_audio("/dev/snd/controlC0", Device::alsa_control);
            tag_audio("/dev/snd/pcmC0D0p", Device::alsa_playback);
        }
    }
    tag("/dev/tty0", Device::vt);
    tag("/dev/tty1", Device::vt, foreground_vt);
    publish_foreground_console();
    tag("/dev/ptmx", Device::ptmx);
    for (unsigned i = 0; i < block_device_limit(); i++) {
        auto info = block_info(i);
        if (!info)
            continue;
        char path[block_name_size];
        block_device_name(i, path);
        auto node = make_node(path, block_device | 0600);
        if (!node)
            panic("block device node");
        node->device = Device::block;
        node->device_id = i;
        node->size = info->sectors * sector_size;
    }
    publish_nvme_inventory();
    if (!lookup("/dev/pts"))
        make_node("/dev/pts", directory | 0755);
    if (!lookup("/dev/input"))
        make_node("/dev/input", directory | 0755);
    tag("/dev/input/event0", Device::keyboard);
    tag("/dev/input/event1", Device::mouse);
    for (unsigned i = 0; i < 256; i++) {
        uint8_t status = in8(0x64);
        if (status == 0xff)
            return;
        if (!(status & 1)) {
            ps2_present = true;
            break;
        }
        in8(0x60);
    }
    if (!ps2_present)
        return;
    if (controller_wait(false))
        out8(0x64, 0xa8);
    if (controller_wait(false))
        out8(0x64, 0x20);
    if (controller_wait(true)) {
        uint8_t config = in8(0x60);
        config = (config & ~0x33) | 0x40;
        if (controller_wait(false))
            out8(0x64, 0x60);
        if (controller_wait(false))
            out8(0x60, config);
    }
    if (controller_wait(false))
        out8(0x64, 0xd4);
    if (controller_wait(false))
        out8(0x60, 0xf4);
    mouse_ack_pending = true;
    if (controller_wait(false))
        out8(0x60, 0xf4);
}

uint64_t device_number(Node* node) {
    switch (node->device) {
    case Device::block:
        return block_device_number(node->device_id);
    case Device::serial:
        return node->device_id;
    case Device::parallel:
        return 0x600;
    case Device::dsp:
        return 0xe03;
    case Device::alsa_control:
        return 0x7400;
    case Device::alsa_playback:
        return 0x7410;
    case Device::tty:
        return 0x500;
    case Device::vt:
        return 0x400 | node->device_id;
    case Device::framebuffer:
        return 0x1d00;
    case Device::keyboard:
        return 0x0d40;
    case Device::mouse:
        return 0x0d41;
    case Device::null:
        return 0x103;
    case Device::zero:
        return 0x105;
    case Device::full:
        return 0x107;
    case Device::random:
        return 0x100 | node->device_id;
    case Device::ptmx:
        return 0x502;
    case Device::pty_slave:
        return 0x8800 | node->device_id;
    default:
        return 0;
    }
}

int device_open(Handle* h) {
    if (!h->node)
        return 0;
    auto kind = h->node->device;
    if (kind == Device::block && (h->flags & 0200)) // O_EXCL
        return block_claim(h->node->device_id, h);
    if (kind == Device::dsp)
        return Pcm::open(*h);
    if (kind == Device::alsa_playback)
        return (h->flags & 3) == 0 || (h->flags & 3) == 3 ? -22 : Alsa::open();
    if (kind == Device::tty) {
        if (!current_task() || (!current_task()->process->controlling_pty &&
                                !current_task()->process->controlling_console))
            return -6;
        if (current_task()->process->controlling_pty) {
            h->pty = current_task()->process->controlling_pty;
            h->pty->slaves++;
        }
        return 0;
    }
    if (kind == Device::keyboard || kind == Device::mouse)
        h->offset = (kind == Device::keyboard ? keyboard_events : mouse_events).sequence;
    if ((kind == Device::serial || kind == Device::vt) && current_task() && !(h->flags & 0400) &&
        (h->flags & 3) != 1 && !console_sid && !current_task()->process->controlling_pty &&
        !current_task()->process->controlling_console &&
        current_task()->process->pid == current_task()->process->sid)
        attach_console(h, false);
    if (kind == Device::ptmx) {
        for (auto& p : ptys)
            if (!p.used) {
                p = {};
                p.used = true;
                p.id = &p - ptys;
                p.locked = true;
                p.terminal = default_terminal;
                p.rows = 24;
                p.columns = 80;
                char name[16];
                number_path(name, "", p.id);
                auto parent = lookup("/dev/pts");
                if (!parent || (parent->mode & 0170000) != directory) {
                    p.used = false;
                    return -2;
                }
                if (node_readonly(parent)) {
                    p.used = false;
                    return -30;
                }
                Node* existing = nullptr;
                int error = parent->mount->ops->lookup(parent, name, existing);
                if (error != -2) {
                    p.used = false;
                    return error ? error : -17;
                }
                error =
                    parent->mount->ops->create(parent, name, character | 0600, nullptr, p.slave);
                if (error) {
                    p.used = false;
                    return error;
                }
                p.slave->uid = current_task() ? current_task()->credentials.user.filesystem : 0;
                p.slave->gid = current_task() ? current_task()->credentials.group.filesystem : 0;
                p.slave->device = Device::pty_slave;
                p.slave->device_id = p.id;
                p.masters = 1;
                h->pty = &p;
                h->writer = true;
                return 0;
            }
        return -28;
    }
    if (kind == Device::pty_slave) {
        auto id = h->node->device_id;
        if (id >= 32 || !ptys[id].used || ptys[id].slave != h->node || !ptys[id].masters)
            return -5;
        if (ptys[id].locked) {
            ptys[id].io_error = true;
            return -5;
        }
        ptys[id].io_error = false;
        h->pty = &ptys[id];
        h->pty->slaves++;
        h->writer = false;
        if (current_task() && !(h->flags & 0400) && !current_task()->process->controlling_pty &&
            !current_task()->process->controlling_console &&
            current_task()->process->pid == current_task()->process->sid && !h->pty->sid)
            attach_pty(h, false);
    }
    return 0;
}

void device_close(Handle* h) {
    if (h->node && h->node->device == Device::block) {
        block_unclaim(h->node->device_id, h);
        return;
    }
    if (h->node && h->node->device == Device::dsp) {
        Pcm::close(*h);
        return;
    }
    if (h->node && h->node->device == Device::alsa_playback) {
        Alsa::close();
        return;
    }
    if (!h->pty)
        return;
    auto p = h->pty;
    if (h->writer) {
        if (!--p->masters) {
            detach_pty(p);
            if (p->slave && !p->slave->removed)
                p->slave->mount->ops->remove(p->slave);
            p->input = p->output = {};
        }
    } else
        p->slaves--;
    if (!p->masters && !p->slaves) {
        ramfs_reclaim_device(p->slave);
        p->used = false;
    }
}

bool device_has_poll(const Handle& handle) {
    if (handle.pty)
        return true;
    switch (handle.node->device) {
    case Device::serial:
    case Device::tty:
    case Device::vt:
    case Device::keyboard:
    case Device::mouse:
    case Device::dsp:
    case Device::alsa_control:
    case Device::alsa_playback:
        return true;
    case Device::random:
        return handle.node->device_id == 8;
    default:
        return false;
    }
}

bool device_ready(Handle* h, bool write) {
    if (h->node->device == Device::dsp)
        return Pcm::ready(*h, write);
    if (h->node->device == Device::alsa_playback)
        return write && Alsa::ready();
    if (h->node->device == Device::alsa_control)
        return false;
    if (h->pty) {
        auto p = h->pty;
        if (!h->writer && p->io_error)
            return true;
        if (write)
            return (h->writer ? p->input : p->output).size < sizeof(ByteQueue::bytes);
        return h->writer ? p->output.size || !p->slaves
                         : canonical_ready(p->input, p->terminal) || !p->masters;
    }
    auto kind = h->node->device;
    if (kind == Device::keyboard || kind == Device::mouse)
        return write ||
               h->offset < (kind == Device::keyboard ? keyboard_events : mouse_events).sequence;
    if (kind == Device::serial || kind == Device::tty || kind == Device::vt)
        return write || canonical_ready(console_input, console_terminal);
    if (kind == Device::random && h->node->device_id == 8)
        return write ? !random_ready() : random_ready();
    return true;
}

static int64_t block_bytes(Handle* h, void* data, size_t len, bool write) {
    const auto info = block_info(h->node->device_id);
    if (!info)
        return -19;
    if (write && info->readonly)
        return -30;
    uint64_t capacity = info->sectors * sector_size;
    if (h->offset >= capacity)
        return write ? -28 : 0;
    len = min(len, size_t(capacity - h->offset));
    auto bytes = (uint8_t*)data;
    size_t done = 0;
    uint8_t partial[sector_size];
    const bool synchronous = write && (h->flags & 010000); // O_SYNC includes O_DSYNC.
    const size_t burst = synchronous ? 1 : block_direct_sectors(h->node->device_id);
    while (done < len) {
        uint64_t position = h->offset;
        size_t within = position % sector_size;
        size_t count = min(len - done, sector_size - within);
        int result;
        if (!within && len - done >= sector_size) {
            // A failed submission leaves the offset at the last completed command.
            const size_t sectors = min(burst, (len - done) / sector_size);
            count = sectors * sector_size;
            result = write ? block_write(h->node->device_id, position / sector_size, bytes + done,
                                         sectors, h)
                           : block_read(h->node->device_id, position / sector_size, bytes + done,
                                        sectors);
        } else {
            result = block_read(h->node->device_id, position / sector_size, partial, 1);
            if (!result) {
                if (write) {
                    memcpy(partial + within, bytes + done, count);
                    result = block_write(h->node->device_id, position / sector_size, partial, 1, h);
                } else {
                    memcpy(bytes + done, partial + within, count);
                }
            }
        }
        if (!result && synchronous)
            result = block_flush(h->node->device_id);
        if (result)
            return done ? int64_t(done) : result;
        h->offset += count;
        done += count;
    }
    return done;
}

bool memory_device(const Handle& handle) {
    auto node = handle.node;
    return node && (node->mode & 0170000) == character && !handle.pty &&
           (node->device == Device::null || node->device == Device::zero ||
            node->device == Device::full || node->device == Device::random);
}

bool device_ignores_buffer(Handle* handle, bool write) {
    if (!memory_device(*handle))
        return false;
    auto kind = handle->node->device;
    return kind == Device::null || (write && (kind == Device::zero || kind == Device::full));
}

int64_t device_read(Handle* h, void* data, size_t len) {
    if (h->node->device == Device::dsp)
        return Pcm::read(data, len);
    if (h->node->device == Device::block)
        return block_bytes(h, data, len, false);
    if (h->pty) {
        auto p = h->pty;
        if (h->writer)
            return p->output.size ? int64_t(queue_read(p->output, data, len))
                   : p->slaves    ? -11
                                  : -5;
        if (!p->masters)
            return 0;
        if (p->io_error)
            return -5;
        return terminal_read(p->input, p->terminal, data, len);
    }
    switch (h->node->device) {
    case Device::null:
        return 0;
    case Device::zero:
    case Device::full:
        memset(data, 0, len);
        return len;
    case Device::random: {
        size_t count = min(len, size_t(256));
        int error = random_read(data, count, h->node->device_id == 9);
        return error ? int64_t(error) : int64_t(count);
    }
    case Device::keyboard:
    case Device::mouse: {
        if (len < sizeof(InputEvent))
            return -22;
        auto& q = h->node->device == Device::keyboard ? keyboard_events : mouse_events;
        if (h->offset == q.sequence)
            return -11;
        if (q.sequence - h->offset > 256)
            h->offset = q.sequence - 256;
        size_t count = min(len / sizeof(InputEvent), size_t(q.sequence - h->offset));
        auto out = (InputEvent*)data;
        for (size_t i = 0; i < count; i++) {
            out[i] = q.events[h->offset++ % 256];
        }
        return count * sizeof(InputEvent);
    }
    case Device::serial:
    case Device::tty:
    case Device::vt:
        return terminal_read(console_input, console_terminal, data, len);
    case Device::parallel:
        return -22;
    default:
        return -19;
    }
}

int64_t device_write(Handle* h, const void* data, size_t len) {
    if (h->node->device == Device::dsp)
        return Pcm::write(data, len);
    if (h->node->device == Device::alsa_playback)
        return Alsa::write(data, len);
    if (h->node->device == Device::block)
        return block_bytes(h, const_cast<void*>(data), len, true);
    if (h->node->device == Device::parallel)
        return parallel_write(data, len);
    auto bytes = (const uint8_t*)data;
    if (h->pty) {
        auto p = h->pty;
        auto& queue = h->writer ? p->input : p->output;
        if (!h->writer && (!p->masters || p->io_error))
            return -5;
        size_t n = min(len, sizeof(queue.bytes) - queue.size);
        if (!n && len)
            return -11;
        for (size_t i = 0; i < n; i++) {
            if (h->writer) {
                terminal_input(p->input, &p->output, p->terminal, p->pgid, bytes[i]);
            } else {
                if (bytes[i] == '\n' && (p->terminal.output & 5) == 5)
                    queue_put(p->output, '\r');
                queue_put(p->output, bytes[i]);
            }
        }
        return n;
    }
    if (h->node->device == Device::null || h->node->device == Device::zero)
        return len;
    if (h->node->device == Device::full)
        return -28;
    if (h->node->device == Device::random) {
        random_mix(data, len);
        return len;
    }
    if (h->node->device == Device::serial || h->node->device == Device::tty ||
        h->node->device == Device::vt) {
        for (size_t i = 0; i < len; i++)
            if (!console_output(bytes[i]))
                return i ? int64_t(i) : -5;
        return len;
    }
    return -19;
}

struct Bitfield {
    uint32_t offset, length, msb_right;
};

struct FbVar {
    uint32_t xres, yres, xres_virtual, yres_virtual, xoffset, yoffset, bpp, grayscale;
    Bitfield red, green, blue, transparency;
    uint32_t nonstd, activate, height, width, accel_flags, pixclock, left_margin, right_margin,
        upper_margin, lower_margin, hsync_len, vsync_len, sync, vmode, rotate, colorspace,
        reserved[4];
};

struct FbFix {
    char id[16];
    uint64_t smem_start;
    uint32_t smem_len, type, type_aux, visual;
    uint16_t xpanstep, ypanstep, ywrapstep;
    uint32_t line_length;
    uint64_t mmio_start;
    uint32_t mmio_len, accel;
    uint16_t capabilities, reserved[2];
};

static_assert(sizeof(FbVar) == 160 && sizeof(FbFix) == 80);

static int64_t output(uint64_t dst, const void* data, size_t len) {
    return current_task()->memory->space.copy_out(dst, data, len) ? 0 : -14;
}

int64_t device_ioctl(Handle* h, uint64_t request, uint64_t arg) {
    auto kind = h->node->device;
    if (kind == Device::dsp)
        return Pcm::ioctl(*h, request, arg);
    if (kind == Device::alsa_control)
        return Alsa::control_ioctl(request, arg);
    if (kind == Device::alsa_playback)
        return Alsa::playback_ioctl(*current_task(), request, arg);
    if (kind == Device::random) {
        if (request == 0x80045200) { // RNDGETENTCNT reports partial initialization credit.
            int count = random_entropy_count();
            return output(arg, &count, sizeof(count));
        }
        switch (request) {
        case 0x40045201: // RNDADDTOENTCNT
        case 0x40085203: // RNDADDENTROPY
        case 0x5204:     // RNDZAPENTCNT
        case 0x5206:     // RNDCLEARPOOL
        case 0x5207:     // RNDRESEEDCRNG
            if (!capable(current_task()->credentials, Capability::sys_admin))
                return -1;
            break;
        default:
            return -22;
        }
        // Current Linux keeps initialization monotonic; these historical commands are no-ops.
        if (request == 0x5204 || request == 0x5206)
            return 0;
        if (request == 0x5207)
            return random_reseed();
        int count;
        if (!current_task()->memory->space.copy_in(&count, arg, sizeof(count)))
            return -14;
        if (count < 0)
            return -22;
        if (request == 0x40085203) {
            int length;
            if (!current_task()->memory->space.copy_in(&length, arg + 4, sizeof(length)))
                return -14;
            // import_ubuf clamps MAX_RW_COUNT, then the ioctl requires the full signed length.
            size_t size = min(size_t(int64_t(length)), size_t(0x7ffff000));
            uint64_t address = arg + 8;
            if (address >= user_limit || size > user_limit - address)
                return -14;
            uint8_t buffer[256];
            size_t done = 0;
            while (done < size) {
                size_t amount = min(sizeof(buffer), size - done);
                amount = min(amount, page_size - (address + done) % page_size);
                if (!current_task()->memory->space.copy_in(buffer, address + done, amount)) {
                    random::erase(buffer, sizeof(buffer));
                    return -14;
                }
                random_mix(buffer, amount); // Failed later copies leave this prefix uncredited.
                random::erase(buffer, sizeof(buffer));
                done += amount;
            }
            if (int64_t(done) != length)
                return -14;
        }
        random_credit(unsigned(count));
        return 0;
    }
    if (kind == Device::block) {
        const auto info = block_info(h->node->device_id);
        if (!info)
            return -19;
        uint64_t capacity = info->sectors * sector_size;
        int value;
        switch (request) {
        case 0x80081272: // BLKGETSIZE64
            return output(arg, &capacity, sizeof(capacity));
        case 0x1260: // BLKGETSIZE: unsigned long sector count on x86-64
            return output(arg, &info->sectors, sizeof(info->sectors));
        case 0x1268: // BLKSSZGET
            value = sector_size;
            return output(arg, &value, sizeof(value));
        case 0x125e: // BLKROGET
            value = info->readonly;
            return output(arg, &value, sizeof(value));
        case 0x1261: // BLKFLSBUF: no kernel block cache yet
            return block_flush(h->node->device_id);
        default:
            return -25;
        }
    }
    if (kind == Device::framebuffer && framebuffer) {
        auto fb = framebuffer;
        if (request == 0x4600) {
            FbVar var{};
            var.xres = var.xres_virtual = fb->width;
            var.yres = var.yres_virtual = fb->height;
            var.bpp = fb->bpp;
            var.red = {fb->red_mask_shift, fb->red_mask_size, 0};
            var.green = {fb->green_mask_shift, fb->green_mask_size, 0};
            var.blue = {fb->blue_mask_shift, fb->blue_mask_size, 0};
            var.height = var.width = UINT32_MAX;
            return output(arg, &var, sizeof(var));
        }
        if (request == 0x4602) {
            FbFix fix{};
            const char* name = virtio_framebuffer ? "Axiom64 virtio" : "Axiom64 fb";
            memcpy(fix.id, name, strlen(name));
            fix.smem_start = uint64_t(fb->address) - direct_map;
            fix.smem_len = fb->pitch * fb->height;
            fix.visual = 2;
            fix.line_length = fb->pitch;
            return output(arg, &fix, sizeof(fix));
        }
        if (request == 0x4601) {
            FbVar var;
            if (!current_task()->memory->space.copy_in(&var, arg, sizeof(var)))
                return -14;
            return var.xres == fb->width && var.yres == fb->height && var.bpp == fb->bpp ? 0 : -22;
        }
        if (request == 0x4606 && virtio_framebuffer) { // FBIOPAN_DISPLAY
            FbVar var;
            if (!current_task()->memory->space.copy_in(&var, arg, sizeof(var)))
                return -14;
            if (var.xoffset || var.yoffset)
                return -22;
            return virtio_gpu_request_refresh() ? 0 : -5;
        }
        if (request == 0x4606 || request == 0x4611)
            return 0;
        return -25;
    }
    if (kind == Device::keyboard || kind == Device::mouse) {
        unsigned number = request & 255, size = (request >> 16) & 0x3fff;
        if (((request >> 8) & 255) != 0x45 || size > 1024)
            return -25;
        uint8_t buffer[1024]{};
        if (number == 1) {
            uint32_t version = 0x10001;
            memcpy(buffer, &version, 4);
        } else if (number == 2) {
            uint16_t id[] = {0x11, 1, uint16_t(kind == Device::keyboard ? 1 : 2), 1};
            memcpy(buffer, id, 8);
        } else if (number == 6 || number == 7) {
            const char* name = number == 7                ? "isa0060/serio0/input0"
                               : kind == Device::keyboard ? "Axiom64 PS/2 keyboard"
                                                          : "Axiom64 PS/2 mouse";
            memcpy(buffer, name, min(strlen(name) + 1, size_t(size)));
        } else if (number == 0x20) {
            buffer[0] = (1 << 0) | (1 << 1) | (kind == Device::mouse ? 1 << 2 : 0);
        } else if (number == 0x21) {
            if (kind == Device::keyboard)
                for (unsigned key = 1; key < 128; key++)
                    buffer[key / 8] |= 1 << (key % 8);
            else
                for (unsigned key = 272; key < 275; key++)
                    buffer[key / 8] |= 1 << (key % 8);
        } else if (number == 0x22) {
            if (kind == Device::mouse) {
                buffer[0] = 3; // REL_X and REL_Y.
                buffer[1] = 1; // REL_WHEEL.
            }
        } else if (number == 0x18)
            memcpy(buffer, keys, min(sizeof(keys), size_t(size)));
        else if (number == 0x90)
            return 0;
        else if (number >= 0x40 && number < 0x80)
            return -22;
        return output(arg, buffer, size) ? -14 : int64_t(size);
    }
    if (!h->pty && kind != Device::serial && kind != Device::tty && kind != Device::vt)
        return -25;
    Terminal* term = h->pty ? &h->pty->terminal : &console_terminal;
    int* group = h->pty ? &h->pty->pgid : &console_pgid;
    switch (request) {
    case 0x5401:
        return output(arg, term, sizeof(*term));
    case 0x5402:
    case 0x5403:
    case 0x5404: {
        Terminal next{};
        if (!current_task()->memory->space.copy_in(&next, arg, sizeof(next)))
            return -14;
        if (request == 0x5404) {
            // Termios on either PTY endpoint configures the slave. Discard
            // its received input only after the complete new state is valid.
            auto& input = h->pty ? h->pty->input : console_input;
            memset(input.bytes, 0, sizeof(input.bytes));
            input.head = input.size = 0;
        }
        *term = next;
        return 0;
    }
    case 0x540b: {
        if (arg > 2)
            return -22;
        if (arg != 1) {
            auto& input = h->pty ? (h->writer ? h->pty->output : h->pty->input) : console_input;
            memset(input.bytes, 0, sizeof(input.bytes));
            input.head = input.size = 0;
        }
        // Writes deliver directly to the peer's received queue or UART.
        // There is no separate unsent driver buffer to discard for TCOFLUSH.
        return 0;
    }
    case 0x540f:
        if (!h->writer && (h->pty ? current_task()->process->controlling_pty != h->pty
                                  : !current_task()->process->controlling_console))
            return -25;
        return output(arg, group, 4);
    case 0x5410: {
        if (h->pty ? (current_task()->process->controlling_pty != h->pty ||
                      current_task()->process->sid != h->pty->sid)
                   : (!current_task()->process->controlling_console ||
                      current_task()->process->sid != console_sid))
            return -25;
        int next_group;
        if (!current_task()->memory->space.copy_in(&next_group, arg, 4))
            return -14;
        if (next_group <= 0)
            return -22;
        bool member = false;
        for (auto& task : tasks)
            if (task.state != State::empty && task.process->pgid == next_group &&
                task.process->sid == current_task()->process->sid)
                member = true;
        if (!member)
            return -1;
        *group = next_group;
        return 0;
    }
    case 0x540e:
        if (h->pty)
            return attach_pty(h, arg == 1);
        return attach_console(h, arg == 1);
    case 0x5422:
        if (h->pty && current_task()->process->controlling_pty != h->pty)
            return -25;
        if (h->pty && current_task()->process->controlling_pty == h->pty) {
            if (current_task()->process->pid == current_task()->process->sid)
                detach_pty(h->pty);
            current_task()->process->controlling_pty = nullptr;
        } else if (current_task()->process->controlling_console &&
                   current_task()->process->sid == console_sid) {
            if (current_task()->process->pid == current_task()->process->sid)
                detach_console(true);
            current_task()->process->controlling_console = false;
        } else
            return -25;
        return 0;
    case 0x5429: {
        if (!h->writer && (h->pty ? current_task()->process->controlling_pty != h->pty
                                  : !current_task()->process->controlling_console))
            return -25;
        int sid = h->pty ? h->pty->sid : console_sid;
        if (!sid)
            return -25;
        return output(arg, &sid, sizeof(sid));
    }
    case 0x5413: {
        uint16_t size[] = {h->pty ? h->pty->rows : uint16_t(24),
                           h->pty ? h->pty->columns : uint16_t(80), 0, 0};
        return output(arg, size, sizeof(size));
    }
    case 0x5414: {
        uint16_t size[4];
        if (!current_task()->memory->space.copy_in(size, arg, sizeof(size)))
            return -14;
        if (h->pty) {
            bool changed = h->pty->rows != size[0] || h->pty->columns != size[1];
            h->pty->rows = size[0];
            h->pty->columns = size[1];
            if (changed)
                terminal_signal(h->pty->pgid, 28);
        }
        return 0;
    }
    case 0x541b: {
        int available =
            h->pty ? (h->writer ? h->pty->output.size : h->pty->input.size) : console_input.size;
        return output(arg, &available, 4);
    }
    case 0x80045430:
        if (!h->pty || !h->writer)
            return -25;
        return output(arg, &h->pty->id, 4);
    case 0x40045431:
        if (!h->pty || !h->writer)
            return -25;
        {
            int locked;
            if (!current_task()->memory->space.copy_in(&locked, arg, sizeof(locked)))
                return -14;
            h->pty->locked = locked != 0;
            return 0;
        }
    case 0x80045439: {
        if (!h->pty || !h->writer)
            return -25;
        int locked = h->pty->locked;
        return output(arg, &locked, sizeof(locked));
    }
    case 0x5600: {
        int free_vt = 1;
        return output(arg, &free_vt, 4);
    }
    case 0x5601: {
        uint8_t mode[8]{};
        return output(arg, mode, sizeof(mode));
    }
    case 0x5602:
        return current_task()->memory->space.valid(arg, 8) ? 0 : -14;
    case 0x5603: {
        uint16_t state[] = {foreground_vt, 0, 1u | (1u << foreground_vt)};
        return output(arg, state, sizeof(state));
    }
    case 0x5605:
        return 0;
    case 0x5606:
    case 0x5607:
        return arg == foreground_vt ? 0 : -6;
    case 0x4b3b:
        return output(arg, &vt_mode, 4);
    case 0x4b3a:
        if (arg > 1)
            return -22;
        vt_mode = arg;
        if (!h->pty)
            fb_console_graphics(arg != 0);
        return 0;
    case 0x4b44:
        return output(arg, &keyboard_mode, 4);
    case 0x4b45:
        keyboard_mode = arg;
        return 0;
    default:
        return -25;
    }
}

int64_t framebuffer_map(AddressSpace& memory, uint64_t va, size_t length, int prot,
                        uint64_t offset) {
    if (!framebuffer || offset > framebuffer->pitch * framebuffer->height ||
        length > align_up(framebuffer->pitch * framebuffer->height) - offset)
        return -22;
    uint64_t address = uint64_t(framebuffer->address) - direct_map + offset;
    if (address % page_size)
        return -22;
    return memory.map_physical(va, address, length, prot, !virtio_framebuffer) ? int64_t(va) : -12;
}

static void event(InputQueue& q, uint16_t type, uint16_t code, int32_t value) {
    q.events[q.sequence++ % 256] = {int64_t(ticks / 100), int64_t(ticks % 100) * 10000, type, code,
                                    value};
}

static void keyboard_event(uint8_t* source, unsigned code, bool pressed) {
    if (code >= sizeof(keys) * 8)
        return;
    const unsigned offset = code / 8, mask = 1u << (code % 8);
    const bool before = key_down(code), repeat = pressed && (source[offset] & mask);
    if (pressed)
        source[offset] |= mask;
    else
        source[offset] &= ~mask;
    keys[offset] = ps2_keys[offset] | usb_keys[offset];
    const bool down = key_down(code);
    if (!repeat && before == down)
        return;
    event(keyboard_events, 1, code, down ? 1 : 0);
    event(keyboard_events, 0, 0, 0);
    if (console_keyboard && !vt_mode && down) {
        if (code == 58 && !before)
            console_caps_lock = !console_caps_lock;
        if (auto character = console_key(code))
            terminal_input(console_input, nullptr, console_terminal, console_pgid, character);
    }
}

void usb_keyboard_event(unsigned code, bool pressed) {
    keyboard_event(usb_keys, code, pressed);
}

static void mouse_event(uint8_t& source, int dx, int dy, uint8_t buttons, int wheel) {
    const auto before = ps2_mouse_buttons | usb_mouse_buttons;
    source = buttons & 7;
    const auto after = ps2_mouse_buttons | usb_mouse_buttons;
    if (dx)
        event(mouse_events, 2, 0, dx);
    if (dy)
        event(mouse_events, 2, 1, dy);
    if (wheel)
        event(mouse_events, 2, 8, wheel);
    for (unsigned k = 0; k < 3; ++k)
        if ((before ^ after) & (1 << k))
            event(mouse_events, 1, 272 + k, (after >> k) & 1);
    event(mouse_events, 0, 0, 0);
}

void usb_mouse_event(int dx, int dy, uint8_t buttons, int wheel) {
    mouse_event(usb_mouse_buttons, dx, dy, buttons, wheel);
}

void devices_poll() {
    if (virtio_framebuffer)
        virtio_gpu_poll(ticks);
    floppy_poll();
    Pcm::poll();
    xhci_keyboard_poll();
    for (unsigned i = 0; i < 64; i++) {
        int c = serial_read();
        if (c < 0)
            break;
        terminal_input(console_input, nullptr, console_terminal, console_pgid, c);
    }
    if (!ps2_present)
        return;
    for (unsigned i = 0; i < 32 && (in8(0x64) & 1); i++) {
        uint8_t status = in8(0x64), byte = in8(0x60);
        if (status & 0x20) {
            if (mouse_ack_pending) {
                mouse_ack_pending = false;
                if (byte == 0xfa)
                    continue;
            }
            if (!mouse_offset && !(byte & 8))
                continue;
            mouse_packet[mouse_offset++] = byte;
            if (mouse_offset < 3)
                continue;
            mouse_offset = 0;
            uint8_t buttons = mouse_packet[0] & 7;
            int dx = mouse_packet[1] - (mouse_packet[0] & 0x10 ? 256 : 0),
                dy = mouse_packet[2] - (mouse_packet[0] & 0x20 ? 256 : 0);
            mouse_event(ps2_mouse_buttons, dx, -dy, buttons, 0);
        } else {
            if (byte == 0xfa)
                continue;
            if (byte == 0xe0) {
                extended = true;
                continue;
            }
            unsigned code = byte & 127;
            if (extended) {
                switch (code) {
                case 28:
                    code = 96;
                    break;
                case 29:
                    code = 97;
                    break;
                case 56:
                    code = 100;
                    break;
                case 71:
                    code = 102;
                    break;
                case 72:
                    code = 103;
                    break;
                case 73:
                    code = 104;
                    break;
                case 75:
                    code = 105;
                    break;
                case 77:
                    code = 106;
                    break;
                case 79:
                    code = 107;
                    break;
                case 80:
                    code = 108;
                    break;
                case 81:
                    code = 109;
                    break;
                case 82:
                    code = 110;
                    break;
                case 83:
                    code = 111;
                    break;
                }
                extended = false;
            }
            keyboard_event(ps2_keys, code, !(byte & 128));
        }
    }
}
} // namespace ax
