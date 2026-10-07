// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/platform/devices.hpp"
#include "drivers/block/block.hpp"
#include "boot/boot.hpp"
#include "process/signals.hpp"
#include "process/task.hpp"

namespace ax {
static limine_framebuffer* framebuffer;
static Pty ptys[32];
static Terminal console_terminal{0x500,  5, 0xbf,
                                 0x8a3b, 0, {3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26}};
static ByteQueue console_input;
static int console_pgid = 1, vt_mode = 0, keyboard_mode = 1;
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
static uint8_t keys[96];
static bool extended;
static uint8_t mouse_packet[3], mouse_offset, mouse_buttons;
static bool mouse_ack_pending;
static void terminal_signal(int pgid, int signal) {
    if (pgid <= 0)
        return;
    for (auto& task : tasks)
        if (task.state != State::empty && task.process->leader == &task &&
            task.process->pgid == pgid)
            queue_process_signal(task.process, signal);
}
static void detach_pty(Pty* p) {
    terminal_signal(p->pgid, 1);
    terminal_signal(p->pgid, 18);
    for (auto& task : tasks)
        if (task.state != State::empty && task.process->controlling_pty == p)
            task.process->controlling_pty = nullptr;
    p->sid = p->pgid = 0;
}
void terminal_exit(Task* task) {
    if (task->process->controlling_pty && task->process->pid == task->process->sid)
        detach_pty(task->process->controlling_pty);
    task->process->controlling_pty = nullptr;
    task->process->controlling_console = false;
}
static int64_t attach_pty(Pty* p, bool force) {
    if (current->process->controlling_pty == p)
        return 0;
    if (current->process->pid != current->process->sid || current->process->controlling_pty ||
        current->process->controlling_console)
        return -1;
    if (p->sid && p->sid != current->process->sid) {
        if (!force)
            return -1;
        detach_pty(p);
    }
    p->sid = current->process->sid;
    p->pgid = current->process->pgid;
    current->process->controlling_pty = p;
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
            } else
                log("\b \b");
        }
        return;
    }
    queue_put(input, c);
    if (term.local & 8) {
        if (echo)
            queue_put(*echo, c);
        else
            putchar(c);
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
static bool controller_wait(bool output) {
    for (unsigned i = 0; i < 100000; i++) {
        uint8_t status = in8(0x64);
        if (output ? status & 1 : !(status & 2))
            return true;
    }
    return false;
}
void devices_init() {
    auto response = framebuffer_request.response;
    if (response && response->framebuffer_count)
        framebuffer = response->framebuffers[0];
    if (framebuffer) {
        tag("/dev/fb0", Device::framebuffer);
        // Limine's boot framebuffer is exposed by our platform framebuffer driver.
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
    }
    tag("/dev/console", Device::serial, 0x501);
    tag("/dev/tty", Device::tty);
    tag("/dev/ttyS0", Device::serial, 0x440);
    tag("/dev/null", Device::null);
    tag("/dev/zero", Device::zero);
    tag("/dev/random", Device::random, 8);
    tag("/dev/urandom", Device::random, 9);
    tag("/dev/tty0", Device::vt);
    tag("/dev/tty1", Device::vt, 1);
    tag("/dev/ptmx", Device::ptmx);
    for (unsigned i = 0; block_info(i); i++) {
        char path[] = "/dev/vda";
        path[7] += i;
        auto node = make_node(path, block_device | 0600);
        if (!node)
            panic("block device node");
        node->device = Device::block;
        node->device_id = i;
        node->size = block_info(i)->sectors * sector_size;
    }
    if (!lookup("/dev/pts"))
        make_node("/dev/pts", directory | 0755);
    if (!lookup("/dev/input"))
        make_node("/dev/input", directory | 0755);
    tag("/dev/input/event0", Device::keyboard);
    tag("/dev/input/event1", Device::mouse);
    while (in8(0x64) & 1)
        in8(0x60);
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
        return 0xfc00 | (node->device_id * 16);
    case Device::serial:
        return node->device_id;
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
bool device_open(Handle* h) {
    if (!h->node)
        return true;
    auto kind = h->node->device;
    if (kind == Device::tty) {
        if (!current ||
            (!current->process->controlling_pty && !current->process->controlling_console))
            return false;
        if (current->process->controlling_pty) {
            h->pty = current->process->controlling_pty;
            h->pty->slaves++;
        }
        return true;
    }
    if (kind == Device::keyboard || kind == Device::mouse)
        h->offset = (kind == Device::keyboard ? keyboard_events : mouse_events).sequence;
    if (kind == Device::ptmx) {
        for (auto& p : ptys)
            if (!p.used) {
                p = {};
                p.used = true;
                p.id = &p - ptys;
                p.terminal = console_terminal;
                p.rows = 24;
                p.columns = 80;
                p.masters = 1;
                char path[32];
                number_path(path, "/dev/pts/", p.id);
                tag(path, Device::pty_slave, p.id);
                h->pty = &p;
                h->writer = true;
                return true;
            }
        return false;
    }
    if (kind == Device::pty_slave) {
        auto id = h->node->device_id;
        if (id >= 32 || !ptys[id].used)
            return false;
        h->pty = &ptys[id];
        h->pty->slaves++;
        h->writer = false;
        if (current && !(h->flags & 0400) && !current->process->controlling_pty &&
            !current->process->controlling_console &&
            current->process->pid == current->process->sid && !h->pty->sid)
            attach_pty(h->pty, false);
    }
    return true;
}
void device_close(Handle* h) {
    if (!h->pty)
        return;
    auto p = h->pty;
    if (h->writer) {
        if (!--p->masters)
            detach_pty(p);
    } else
        p->slaves--;
    if (!p->masters && !p->slaves)
        p->used = false;
}
bool device_ready(Handle* h, bool write) {
    if (h->pty) {
        auto p = h->pty;
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
    while (done < len) {
        uint64_t position = h->offset;
        size_t within = position % sector_size;
        size_t count = min(len - done, sector_size - within);
        int result;
        if (!within && len - done >= sector_size) {
            // Keep error reporting precise: advance the handle only for completed sectors.
            count = sector_size;
            result = write
                         ? block_write(h->node->device_id, position / sector_size, bytes + done, 1)
                         : block_read(h->node->device_id, position / sector_size, bytes + done, 1);
        } else {
            result = block_read(h->node->device_id, position / sector_size, partial, 1);
            if (!result) {
                if (write) {
                    memcpy(partial + within, bytes + done, count);
                    result = block_write(h->node->device_id, position / sector_size, partial, 1);
                } else {
                    memcpy(bytes + done, partial + within, count);
                }
            }
        }
        if (!result && write && (h->flags & 010000)) // O_DSYNC; O_SYNC includes this bit.
            result = block_flush(h->node->device_id);
        if (result)
            return done ? int64_t(done) : result;
        h->offset += count;
        done += count;
    }
    return done;
}
int64_t device_read(Handle* h, void* data, size_t len) {
    if (h->node->device == Device::block)
        return block_bytes(h, data, len, false);
    if (h->pty) {
        auto p = h->pty;
        if (h->writer)
            return p->output.size ? int64_t(queue_read(p->output, data, len))
                   : p->slaves    ? -11
                                  : -5;
        if (!p->masters && !p->input.size)
            return 0;
        return terminal_read(p->input, p->terminal, data, len);
    }
    switch (h->node->device) {
    case Device::null:
        return 0;
    case Device::zero:
        memset(data, 0, len);
        return len;
    case Device::random: {
        static uint64_t state = 0x4158494f4d3634;
        auto bytes = (uint8_t*)data;
        for (size_t i = 0; i < len; i++) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes[i] = state;
        }
        return len;
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
    default:
        return -19;
    }
}
int64_t device_write(Handle* h, const void* data, size_t len) {
    if (h->node->device == Device::block)
        return block_bytes(h, const_cast<void*>(data), len, true);
    auto bytes = (const uint8_t*)data;
    if (h->pty) {
        auto p = h->pty;
        auto& queue = h->writer ? p->input : p->output;
        if (!h->writer && !p->masters)
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
    if (h->node->device == Device::serial || h->node->device == Device::tty ||
        h->node->device == Device::vt) {
        for (size_t i = 0; i < len; i++)
            putchar(bytes[i]);
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
    return current->memory->space.copy_out(dst, data, len) ? 0 : -14;
}
int64_t device_ioctl(Handle* h, uint64_t request, uint64_t arg) {
    auto kind = h->node->device;
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
            memcpy(fix.id, "Axiom64 fb", 10);
            fix.smem_start = uint64_t(fb->address) - direct_map;
            fix.smem_len = fb->pitch * fb->height;
            fix.visual = 2;
            fix.line_length = fb->pitch;
            return output(arg, &fix, sizeof(fix));
        }
        if (request == 0x4601) {
            FbVar var;
            if (!current->memory->space.copy_in(&var, arg, sizeof(var)))
                return -14;
            return var.xres == fb->width && var.yres == fb->height && var.bpp == fb->bpp ? 0 : -22;
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
            if (kind == Device::mouse)
                buffer[0] = 3;
        } else if (number == 0x18)
            memcpy(buffer, keys, min(sizeof(keys), size_t(size)));
        else if (number == 0x90)
            return 0;
        else if (number >= 0x40 && number < 0x80)
            return -22;
        return output(arg, buffer, size) ? -14 : int64_t(size);
    }
    Terminal* term = h->pty ? &h->pty->terminal : &console_terminal;
    int* group = h->pty ? &h->pty->pgid : &console_pgid;
    switch (request) {
    case 0x5401:
        return output(arg, term, sizeof(*term));
    case 0x5402:
    case 0x5403:
    case 0x5404:
        return current->memory->space.copy_in(term, arg, sizeof(*term)) ? 0 : -14;
    case 0x540f:
        return output(arg, group, 4);
    case 0x5410: {
        int next_group;
        if (!current->memory->space.copy_in(&next_group, arg, 4))
            return -14;
        if (next_group <= 0)
            return -22;
        bool member = false;
        for (auto& task : tasks)
            if (task.state != State::empty && task.process->pgid == next_group &&
                task.process->sid == current->process->sid)
                member = true;
        if (!member)
            return -1;
        *group = next_group;
        return 0;
    }
    case 0x540e:
        if (h->pty)
            return attach_pty(h->pty, arg != 0);
        current->process->controlling_console = true;
        console_pgid = current->process->pgid;
        return 0;
    case 0x5422:
        if (h->pty && current->process->controlling_pty == h->pty) {
            if (current->process->pid == current->process->sid)
                detach_pty(h->pty);
            current->process->controlling_pty = nullptr;
        } else
            current->process->controlling_console = false;
        return 0;
    case 0x5429: {
        int sid = h->pty ? h->pty->sid : current->process->sid;
        return output(arg, &sid, sizeof(sid));
    }
    case 0x5413: {
        uint16_t size[] = {h->pty ? h->pty->rows : uint16_t(24),
                           h->pty ? h->pty->columns : uint16_t(80), 0, 0};
        return output(arg, size, sizeof(size));
    }
    case 0x5414: {
        uint16_t size[4];
        if (!current->memory->space.copy_in(size, arg, sizeof(size)))
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
        return current->memory->space.valid(arg, 4) ? 0 : -14;
    case 0x5600: {
        int free_vt = 1;
        return output(arg, &free_vt, 4);
    }
    case 0x5601: {
        uint8_t mode[8]{};
        return output(arg, mode, sizeof(mode));
    }
    case 0x5602:
        return current->memory->space.valid(arg, 8) ? 0 : -14;
    case 0x5603: {
        uint16_t state[] = {1, 0, 2};
        return output(arg, state, sizeof(state));
    }
    case 0x5605:
    case 0x5606:
    case 0x5607:
        return 0;
    case 0x4b3b:
        return output(arg, &vt_mode, 4);
    case 0x4b3a:
        if (arg > 1)
            return -22;
        vt_mode = arg;
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
    return memory.map_physical(va, address, length, prot, true) ? int64_t(va) : -12;
}
static void event(InputQueue& q, uint16_t type, uint16_t code, int32_t value) {
    q.events[q.sequence++ % 256] = {int64_t(ticks / 100), int64_t(ticks % 100) * 10000, type, code,
                                    value};
}
void devices_poll() {
    for (unsigned i = 0; i < 64; i++) {
        int c = serial_read();
        if (c < 0)
            break;
        terminal_input(console_input, nullptr, console_terminal, console_pgid, c);
    }
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
            if (dx)
                event(mouse_events, 2, 0, dx);
            if (dy)
                event(mouse_events, 2, 1, -dy);
            for (unsigned k = 0; k < 3; k++)
                if ((buttons ^ mouse_buttons) & (1 << k))
                    event(mouse_events, 1, 272 + k, (buttons >> k) & 1);
            mouse_buttons = buttons;
            event(mouse_events, 0, 0, 0);
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
            if (code < sizeof(keys) * 8) {
                if (byte & 128)
                    keys[code / 8] &= ~(1 << (code % 8));
                else
                    keys[code / 8] |= 1 << (code % 8);
            }
            event(keyboard_events, 1, code, (byte & 128) ? 0 : 1);
            event(keyboard_events, 0, 0, 0);
        }
    }
}
} // namespace ax
