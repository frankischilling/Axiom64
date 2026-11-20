// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/io/io.hpp
 * @brief   Kernel I/O request interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares descriptor operations and the lifecycle of retained I/O across
 * blocking and restart.
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
#include "process/task.hpp"

namespace ax {
int64_t io_syscall(Task&, const Frame&);

bool io_resume(Task&);
bool io_resume_signal_descriptor(Task&);

void io_discard(Task&);
// A finite socket timeout or completed stream bytes prevent automatic restart.
bool io_restartable(const Task&);

// Finalize completed bytes and receive metadata before discarding the request.
int64_t io_interrupted_result(Task&);
} // namespace ax
