// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/eventfd.hpp
 * @brief   Event counter descriptor interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares eventfd counter reads, writes, readiness, and cleanup.
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
struct Eventfd;
struct Handle;

struct EventfdInfo {
    uint64_t count;
    bool semaphore;
};

Handle* open_eventfd(uint32_t initial, bool semaphore, bool nonblocking, int& error);
void close_eventfd(Eventfd*);
bool eventfd_ready(const Eventfd*, bool write);
int64_t eventfd_read(Eventfd*, void*, size_t);
int64_t eventfd_write(Eventfd*, const void*, size_t);
EventfdInfo eventfd_info(const Eventfd&);
} // namespace ax
