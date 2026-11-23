// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/virtual_console.cpp
 * @brief   Expose the foreground virtual console to session managers.
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
#include "drivers/platform/virtual_console.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
int access(Node* node, unsigned mask, bool) {
    return (mask & 3) || ((mask & 4) && !(node->mode & 0444)) ? -13 : 0;
}

int64_t read(Handle* handle, void* data, size_t size) {
    static_assert(foreground_vt < 10);
    constexpr char line[] = {'t', 't', 'y', char('0' + foreground_vt), '\n'};
    const size_t offset = min(handle->offset, sizeof(line));
    const size_t count = min(size, sizeof(line) - offset);
    memcpy(data, line + offset, count);
    handle->offset += count;
    return count;
}

const ControlFileOps active_console = {
    .access = access,
    .read = read,
    .write = [](Handle*, const void*, size_t) -> int64_t { return -13; },
    .truncate = [](Node*, size_t) { return -13; },
    .poll_events = [](const Handle&) -> uint32_t {
        // A fixed foreground VT has ordinary sysfs readiness and no switch events.
        return 1 | 4 | 0x40 | 0x100;
    },
};
} // namespace

void publish_foreground_console() {
    constexpr const char* directories[] = {"/sys", "/sys/class", "/sys/class/tty",
                                           "/sys/class/tty/tty0"};
    for (auto path : directories)
        if (!lookup(path) && !make_node(path, directory | 0755))
            return;
    if (auto node = make_node("/sys/class/tty/tty0/active", regular_file | 0444))
        ramfs_set_control(node, &active_console);
}
} // namespace ax
