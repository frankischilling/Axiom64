// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/descriptor.hpp
 * @brief   File descriptor and open description types.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines file and socket descriptor state and declares operations for holding,
 * cloning, and closing it.
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

namespace ax {
struct FileTable;
struct Handle;
struct Task;

// A reservation owns a table slot without exposing a file. Install exactly once,
// or discard on failure/interruption. The owning task keeps the table alive.
int reserve_fd(Task&, int start = 0, bool cloexec = false);
void install_reserved_fd(FileTable&, int, Handle*);
void discard_reserved_fd(FileTable&, int);
// Closing or replacing a visible descriptor releases that table's POSIX locks
// on the inode, independently of description references retained elsewhere.
void close_descriptor(FileTable&, int);
} // namespace ax
