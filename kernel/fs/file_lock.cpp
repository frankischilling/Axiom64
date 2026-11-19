// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/file_lock.cpp
 * @brief   Whole-file advisory locks.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages lock owners, compatibility, and wakeups for the kernel's flock
 * operations.
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
#include "fs/file_lock.hpp"

namespace ax {
bool file_lock_operation(uint32_t operation) {
    uint32_t kind = operation & ~uint32_t(4);
    return kind == 1 || kind == 2 || kind == 8;
}

void file_lock_release(Handle* handle) {
    if (!handle || !handle->file_lock)
        return;
    auto node = handle->node;
    if (handle->file_lock == 1)
        --node->lock_readers;
    else
        node->lock_writer = nullptr;
    handle->file_lock = 0;
}

int file_lock_try(Handle* handle, uint32_t operation) {
    if (!file_lock_operation(operation))
        return -22;
    if (!handle || (handle->flags & 010000000)) // O_PATH does not allow flock.
        return -9;
    auto node = handle->node;
    if (!node)
        return -95;
    unsigned kind = operation & ~uint32_t(4);
    if (kind == handle->file_lock)
        return 0;
    // Linux conversions release the previous mode even if acquisition fails.
    file_lock_release(handle);
    if (kind == 8)
        return 0;
    if (node->lock_writer || (kind == 2 && node->lock_readers))
        return -11;
    if (kind == 1)
        ++node->lock_readers;
    else
        node->lock_writer = handle;
    handle->file_lock = kind;
    return 0;
}
} // namespace ax
