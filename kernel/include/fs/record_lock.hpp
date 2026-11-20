// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/record_lock.hpp
 * @brief   POSIX record lock interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines range-lock ownership and declares operations for testing, installing,
 * and releasing locks.
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
struct Task;
struct FileTable;

struct RecordFlock {
    int16_t type, whence;
    uint32_t padding;
    int64_t start, length;
    int32_t pid;
    uint32_t padding2;
};

static_assert(sizeof(RecordFlock) == 32);

bool record_lock_command(uint64_t);
int record_lock_prepare(Handle*, unsigned command, RecordFlock&);
// Preparation captures an absolute range. Queries preserve unmodified caller
// fields when no conflict exists. Blocking setters retain a per-task wait and
// detect cycles among process-associated owners.
int record_lock_try(Task&, Handle*, unsigned command, RecordFlock&);
void record_lock_discard(Task&);
void record_lock_close(FileTable&, Node*);
void record_lock_release(FileTable&);
void record_lock_release(Handle&);
} // namespace ax
