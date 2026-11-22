// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/eventfd.cpp
 * @brief   Linux eventfd ABI.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Validates eventfd flags and installs an event counter in the process
 * descriptor table.
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
#include "abi/linux/eventfd.hpp"
#include "fs/descriptor.hpp"
#include "ipc/eventfd.hpp"
#include "process/task.hpp"

namespace ax {
int64_t eventfd_syscall(const Frame& frame) {
    uint32_t flags = frame.rax == 290 ? uint32_t(frame.rsi) : 0;
    if (flags & ~uint32_t(1 | 04000 | 02000000))
        return -22;
    int fd = reserve_fd(*current_task(), 0, flags & 02000000);
    if (fd < 0)
        return fd;
    int error;
    auto handle = open_eventfd(uint32_t(frame.rdi), flags & 1, flags & 04000, error);
    if (!handle) {
        discard_reserved_fd(*current_task()->files, fd);
        return error;
    }
    install_reserved_fd(*current_task()->files, fd, handle);
    return fd;
}
} // namespace ax
