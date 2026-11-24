// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/uevent.cpp
 * @brief   Device inventory add and change events.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Exposes coldplug controls and publishes the device path and properties.
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
    char data[2048];
    size_t size = 0;

    void text(const char* value) {
        size_t length = strlen(value);
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
        data[size++] = 0;
    }

    void properties(const uint8_t* properties, size_t length) {
        for (size_t offset = 0; offset < length; ++offset)
            data[size++] = properties[offset] == '\n' ? 0 : char(properties[offset]);
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

void emit(Node*, const char* action, bool synthetic);

int64_t write(Handle* handle, const void* data, size_t length) {
    const auto* input = static_cast<const char*>(data);
    const auto bytes = length && input[length - 1] == '\n' ? length - 1 : length;
    if (bytes == 3 && !memcmp(input, "add", 3))
        emit(handle->node, "add", true);
    else if (handle->node->device == Device::power_supply_uevent && bytes == 6 &&
             !memcmp(input, "change", 6))
        emit(handle->node, "change", true);
    else
        return -22;
    return length;
}

int truncate(Node*, size_t length) {
    return length ? -22 : 0;
}

constexpr ControlFileOps control{access, read, write, truncate};

void emit(Node* node, const char* action, bool synthetic) {
    char path[256]{};
    node_path(node, path, sizeof(path), false, root_node);
    size_t length = strlen(path);
    constexpr char endpoint[] = "/uevent";
    if (length <= sizeof(endpoint) + 4 || memcmp(path, "/sys/devices/", 13) ||
        strcmp(path + length - (sizeof(endpoint) - 1), endpoint))
        return;
    path[length - (sizeof(endpoint) - 1)] = 0;
    const char* relative = path + 4;
    Message event;
    // Reserve space for two terminated paths, the properties and fixed fields.
    size_t prefix_bytes = 2 * strlen(relative) + 100;
    if (prefix_bytes > sizeof(event.data) || node->size > sizeof(event.data) - prefix_bytes)
        return;
    event.text(action);
    event.text("@");
    event.field(relative);
    event.text("ACTION=");
    event.field(action);
    event.text("DEVPATH=");
    event.field(relative);
    const char* subsystem = node->device == Device::network_uevent        ? "SUBSYSTEM=net"
                            : node->device == Device::power_supply_uevent ? "SUBSYSTEM=power_supply"
                                                                          : "SUBSYSTEM=input";
    event.field(subsystem);
    event.properties(node->data, node->size);
    if (synthetic)
        event.field("SYNTH_UUID=0");
    event.text("SEQNUM=");
    event.number(++sequence);
    event.field("");
    netlink_broadcast_uevent(event.data, event.size);
}
} // namespace

void inventory_device_added(Node* node, bool synthetic) {
    emit(node, "add", synthetic);
}

void inventory_device_changed(Node* node) {
    emit(node, "change", false);
}

const ControlFileOps* inventory_uevent_control(Node* node) {
    return node->device == Device::input_uevent || node->device == Device::network_uevent ||
                   node->device == Device::power_supply_uevent
               ? &control
               : nullptr;
}
} // namespace ax
