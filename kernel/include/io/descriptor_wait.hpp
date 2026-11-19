// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/io/descriptor_wait.hpp
 * @brief   Descriptor readiness and wait interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares readiness sampling, saved waits, and notifications for poll, select,
 * and epoll.
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
#include <stdint.h>

namespace ax {
struct Frame;
struct Task;

int64_t descriptor_wait_syscall(Task&, const Frame&);
bool descriptor_wait_resume(Task&);
bool descriptor_wait_interrupt(Task&);
void descriptor_wait_stop(Task&);
void descriptor_wait_discard(Task&);
void descriptor_wait_notify(const void* source, uint32_t events);
} // namespace ax
