// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/socket_control.hpp
 * @brief   Socket ancillary data interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines control message state and declares the helpers that marshal socket
 * metadata.
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
struct Task;

// A receive-control copy owns its cursor, commits only successful stores, and
// leaves alignment padding untouched. Failed copies consume no capacity.
class SocketControlWriter {
  public:
    SocketControlWriter(Task& owner, uint32_t protocol_level, uint64_t pointer, uint64_t limit,
                        uint32_t& result)
        : task(owner), level(protocol_level), address(pointer), capacity(limit), flags(result) {
    }

    void append(uint32_t type, const void* bytes, size_t size);

    uint64_t used = 0;

  private:
    Task& task;
    uint32_t level;
    uint64_t address, capacity;
    uint32_t& flags;
};
} // namespace ax
