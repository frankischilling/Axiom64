// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/input/uevent.cpp
 * @brief   Publishes evdev additions and handles input coldplug requests.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Sends device additions on the kernel uevent multicast group after the
 * input node and its discovery attributes are available.
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
#include "net/netlink.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
uint64_t sequence;

struct Message {
    char data[256];
    size_t size = 0;

    void text(const char* value) {
        const auto length = strlen(value);
        memcpy(data + size, value, length);
        size += length;
    }

    void number(uint64_t value) {
        char digits[20];
        unsigned length = 0;
        do {
            digits[length++] = '0' + value % 10;
            value /= 10;
        } while (value);
        while (length)
            data[size++] = digits[--length];
    }

    void field(const char* value) {
        text(value);
        end();
    }

    void end() {
        data[size++] = 0;
    }

    void path(unsigned index) {
        text("/devices/virtual/input/input");
        number(index);
        text("/event");
        number(index);
        end();
    }
};

int access(Node* node, unsigned mask, bool real) {
    const Credentials boot{};
    return credential_access(current_task() ? current_task()->credentials : boot, node->uid,
                             node->gid, node->mode, mask, real);
}

int64_t read(Handle* handle, void* output, size_t length) {
    const auto* node = handle->node;
    const auto offset = min(uint64_t(node->size), handle->offset);
    const auto copied = min(length, node->size - offset);
    memcpy(output, node->data + offset, copied);
    handle->offset += copied;
    return copied;
}

int64_t write(Handle* handle, const void* data, size_t length) {
    if (!((length == 3 && !memcmp(data, "add", 3)) || (length == 4 && !memcmp(data, "add\n", 4))))
        return -22;
    input_device_added(handle->node->device_id, true);
    return length;
}

int truncate(Node*, size_t length) {
    return length ? -22 : 0;
}

constexpr ControlFileOps control{access, read, write, truncate};
} // namespace

void input_device_added(unsigned index, bool synthetic) {
    // All fields are fixed apart from the evdev index and the 64-bit sequence.
    if (index >= 3)
        return;
    Message event;
    event.text("add@");
    event.path(index);
    event.field("ACTION=add");
    event.text("DEVPATH=");
    event.path(index);
    event.field("SUBSYSTEM=input");
    event.field("MAJOR=13");
    event.text("MINOR=");
    event.number(64 + index);
    event.end();
    event.text("DEVNAME=input/event");
    event.number(index);
    event.end();
    if (synthetic)
        event.field("SYNTH_UUID=0");
    event.text("SEQNUM=");
    event.number(++sequence);
    event.end();
    netlink_broadcast_uevent(event.data, event.size);
}

const ControlFileOps* input_uevent_control(Node* node) {
    return node->device == Device::input_uevent ? &control : nullptr;
}
} // namespace ax
