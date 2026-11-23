// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/inventory.cpp
 * @brief   Device inventory files.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Creates directories, read-only attributes, and links for discovered devices.
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
#include "drivers/platform/inventory.hpp"

namespace ax::DeviceInventory {
void number_path(char* out, const char* prefix, unsigned number) {
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

bool inventory_directory(const char* path) {
    if (auto node = lookup(path, false))
        return (node->mode & 0170000) == directory;
    return make_node(path, directory | 0755);
}

Node* inventory_attribute(const char* parent, const char* name, const char* value) {
    char path[256];
    if (!inventory_path(path, parent, name))
        return nullptr;
    const size_t length = strlen(value);
    auto bytes = static_cast<uint8_t*>(alloc(length + 1));
    if (!bytes)
        return nullptr;
    auto node = make_node(path, regular_file | 0444);
    if (!node) {
        release(bytes);
        return nullptr;
    }
    memcpy(bytes, value, length);
    bytes[length] = '\n';
    node->data = bytes;
    node->size = node->capacity = length + 1;
    node->owned = true;
    return node;
}

bool inventory_link(const char* parent, const char* name, const char* target) {
    char text[256];
    if (!inventory_path(text, parent, name))
        return false;
    Path path;
    path.base = root_node;
    memcpy(path.text, text, strlen(text) + 1);
    Node* link = nullptr;
    return !create_node(path, symlink | 0777, link, target);
}
} // namespace ax::DeviceInventory
