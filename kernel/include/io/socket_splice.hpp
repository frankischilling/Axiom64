// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/io/socket_splice.hpp
 * @brief   Socket and pipe transfer interfaces.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the data path for moving bytes between pipe slots and sockets.
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
#include "core/base.hpp"

namespace ax {
struct Handle;
struct Pipe;
struct Task;

bool splice_socket(const Handle&);
int64_t splice_socket_to_pipe(Handle&, Pipe&, size_t length);
int64_t splice_pipe_to_socket(Task&, Pipe&, Handle&, size_t length, bool more);
} // namespace ax
