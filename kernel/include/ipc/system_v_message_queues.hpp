// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/system_v_message_queues.hpp
 * @brief   System V message queue interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares queue creation, send and receive, administration, and retained wait
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
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t message_queue_syscall(Frame*);
void message_queue_discard(Task&);
void message_queue_resume(Task&);
} // namespace ax
