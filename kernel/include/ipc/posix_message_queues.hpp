// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/posix_message_queues.hpp
 * @brief   POSIX message queue interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares priority queue I/O, attributes, notifications, and saved wait
 * handling.
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
const FilesystemOps& posix_queue_filesystem();
void posix_queue_mount(Node*);
bool posix_queue_mounted();
bool posix_queue_ready(const Node*, bool write);
void posix_queue_reap(Node*);
void posix_queue_descriptor_closed(Handle*);
void posix_queue_process_exit(const Process&);
void posix_queue_discard(Task&);
void posix_queue_resume(Task&);
bool posix_queue_expire(Task&);
int64_t posix_queue_syscall(Frame*);
} // namespace ax
