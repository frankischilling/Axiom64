// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/inventory.hpp
 * @brief   Device inventory file creation.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Declares helpers for exposing kernel device objects to userspace.
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
struct NetInfo;
struct PciFunction;

namespace DeviceInventory {
void number_path(char*, const char*, unsigned);

bool inventory_directory(const char*);
bool inventory_directories(char* path);

Node* inventory_attribute(const char*, const char*, const char*);

bool inventory_link(const char*, const char*, const char*);

template <size_t Capacity>
bool inventory_path(char (&out)[Capacity], const char* parent, const char* name) {
    const size_t prefix = strlen(parent), length = strlen(name);
    if (prefix + length + 2 > Capacity)
        return false;
    memcpy(out, parent, prefix);
    out[prefix] = '/';
    memcpy(out + prefix + 1, name, length + 1);
    return true;
}

void network_inventory_init();

void publish_ethernet(const NetInfo&, const PciFunction*);
} // namespace DeviceInventory
} // namespace ax
