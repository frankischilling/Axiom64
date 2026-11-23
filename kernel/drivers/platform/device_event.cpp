// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/device_event.cpp
 * @brief   Publish kernel device events and replay existing device inventory.
 * @author  frankischilling
 * @date    2026-11-23
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
#include "drivers/platform/device_event.hpp"
#include "fs/vfs.hpp"
#include "net/netlink.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
uint64_t sequence;
constexpr const char* actions[] = {"add",    "remove",  "change", "move",
                                   "online", "offline", "bind",   "unbind"};

struct Payload {
    char bytes[2048];
    size_t used = 0;

    bool append(const char* part, size_t length) {
        if (length > sizeof(bytes) - used)
            return false;
        memcpy(bytes + used, part, length);
        used += length;
        return true;
    }

    bool text(const char* part) {
        return append(part, strlen(part));
    }

    bool end() {
        return append("", 1);
    }
};

int access(Node* node, unsigned mask, bool) {
    auto task = current_task();
    if ((mask & 1) || ((mask & 4) && !(node->mode & 0444)) ||
        ((mask & 2) &&
         (!(node->mode & 0200) || (task && !capable(task->credentials, Capability::sys_admin)))))
        return -13;
    return 0;
}

int64_t read(Handle* handle, void* output, size_t capacity) {
    const Node& node = *handle->node;
    if (handle->offset >= node.size)
        return 0;
    const size_t count = min(capacity, node.size - handle->offset);
    memcpy(output, node.data + handle->offset, count);
    handle->offset += count;
    return count;
}

int emit_device_event(Node*, const char* action, bool synthetic);

int64_t write(Handle* handle, const void* data, size_t count) {
    if (!count)
        return 0;
    const auto input = static_cast<const char*>(data);
    const size_t length = count - (input[count - 1] == '\n');
    for (const char* action : actions)
        if (strlen(action) == length && !memcmp(input, action, length)) {
            int error = emit_device_event(handle->node, action, true);
            return error ? error : int64_t(count);
        }
    return -22;
}

int emit_device_event(Node* source, const char* action, bool synthetic) {
    if (!source->parent || source->removed)
        return -19;
    char path[sizeof(Path::text)];
    node_path(source->parent, path, sizeof(path), false, root_node);
    constexpr char prefix[] = "/sys/";
    if (strlen(path) < sizeof(prefix) || memcmp(path, prefix, sizeof(prefix) - 1))
        return -19;
    const char* devpath = path + sizeof("/sys") - 1;

    char digits[21]{};
    size_t start = sizeof(digits) - 1;
    for (uint64_t number = sequence + 1;;) {
        digits[--start] = char('0' + number % 10);
        number /= 10;
        if (!number)
            break;
    }
    Payload message;
    if (!message.text(action) || !message.text("@") || !message.text(devpath) || !message.end() ||
        !message.text("ACTION=") || !message.text(action) || !message.end() ||
        !message.text("DEVPATH=") || !message.text(devpath) || !message.end())
        return -7;
    for (size_t start = 0, end = 0; end < source->size; ++end) {
        if (source->data[end] != '\n')
            continue;
        const auto property = reinterpret_cast<const char*>(source->data + start);
        if (!message.append(property, end - start) || !message.end())
            return -7;
        start = end + 1;
    }
    if ((synthetic && !message.append("SYNTH_UUID=0", sizeof("SYNTH_UUID=0"))) ||
        !message.text("SEQNUM=") || !message.text(digits + start) || !message.end())
        return -7;
    ++sequence;
    netlink_device_event(message.bytes, message.used);
    return 0;
}

const ControlFileOps device_event_ops = {access, read, write,
                                         [](Node*, size_t size) { return size ? -22 : 0; }};
} // namespace

int publish_device_event(Node* node) {
    ramfs_set_control(node, &device_event_ops);
    return emit_device_event(node, "add", false);
}
} // namespace ax
