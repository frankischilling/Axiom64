// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/unix_rights.hpp
 * @brief   Unix descriptor passing interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the retained descriptor set used to transfer rights over Unix
 * sockets.
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
struct Handle;
struct Socket;
struct Task;

// A send captures descriptions, not descriptor numbers. A pending send owns the
// same references while waiting; enqueue makes them part of the receiver graph.
class UnixRights {
    static UnixRights* all;
    static unsigned queued_sockets;
    UnixRights *next = nullptr, *previous = nullptr, *collect_next = nullptr;
    Handle* files[253]{};
    unsigned count = 0, sockets = 0;
    uint32_t uid = 0;
    Socket* receiver = nullptr;
    friend void unix_collect_rights();

  public:
    static constexpr unsigned maximum = 253;
    static UnixRights* create(uint32_t uid);
    void append(Handle*);
    int admission(uint64_t limit, bool privileged) const;
    void enqueue(Socket*);
    void dequeue();
    void drop();
    size_t write(Task&, uint64_t pointer, size_t capacity, bool cloexec, uint32_t& flags) const;

    unsigned size() const {
        return count;
    }
};

// Called after an outermost description release, when all nested close callbacks
// have finished. References held by pending sends and ordinary descriptors root
// the graph; only unreachable receive queues are cleared.
void unix_collect_rights();
} // namespace ax
