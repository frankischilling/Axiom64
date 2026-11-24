// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/unix_credentials.hpp
 * @brief   Unix socket credential interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines credential records and declares validation and conversion operations.
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
#include <cstddef>
#include <cstdint>

namespace ax {
struct Task;
class UnixRights;

// A queued message keeps its captured identity after the sender exits. An
// uncaptured message reports the anonymous identity if PASSCRED is enabled later.
class UnixMessageCredentials {
    int32_t pid = 0;
    uint32_t uid = 65534, gid = 65534;
    bool captured = false;
    friend int unix_read_control(Task&, uint64_t, size_t, UnixMessageCredentials&, UnixRights*&);

  public:
    void capture(const Task&);
    bool operator==(const UnixMessageCredentials&) const = default;
    size_t write(Task&, uint64_t pointer, size_t capacity, uint32_t& flags) const;
};
} // namespace ax
