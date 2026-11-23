// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/socket_control.cpp
 * @brief   Socket control dispatch.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Handles network socket control operations and routes protocol-specific
 * requests.
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
#include "net/socket_control.hpp"
#include "net/socket_filter.hpp"
#include "process/task.hpp"

namespace ax {
int SocketFilter::attach(Task& task, uint64_t pointer, size_t length) {
    struct Program {
        uint16_t count;
        uint64_t code;
    } program;

    static_assert(sizeof(Program) == 16 && offsetof(Program, code) == 8);
    if (length != sizeof(program))
        return -22;
    if (!task.memory->space.copy_in(&program, pointer, sizeof(program)))
        return -14;
    if (!program.count || program.count > max_socket_filter_instructions)
        return -22;
    const size_t bytes = size_t(program.count) * sizeof(FilterInstruction);
    const size_t mask_bytes = size_t(program.count) * sizeof(uint16_t);
    auto candidate = static_cast<FilterInstruction*>(alloc(bytes + mask_bytes));
    if (!candidate)
        return -12;
    if (!task.memory->space.copy_in(candidate, program.code, bytes)) {
        release(candidate);
        return -14;
    }
    auto masks = reinterpret_cast<uint16_t*>(candidate + program.count);
    if (!validate_socket_filter(candidate, program.count, masks)) {
        release(candidate);
        return -22;
    }
    release(code);
    code = candidate;
    count = program.count;
    return 0;
}

int SocketFilter::detach() {
    if (!code)
        return -2;
    release(code);
    *this = {};
    return 0;
}

void SocketControlWriter::append(uint32_t type, const void* bytes, size_t size) {
    if (!address || capacity < 16) {
        flags |= 8;
        return;
    }
    uint64_t length = min(capacity, uint64_t(16 + size));
    if (length < 16 + size)
        flags |= 8;
    if (address >= user_limit || length > user_limit - address)
        return;
    // A failed control copy leaves its written prefix visible. It consumes
    // no capacity, so later enabled controls still try the same position.
    if (!task.memory->space.copy_out(address, &length, 8) ||
        !task.memory->space.copy_out(address + 8, &level, 4) ||
        !task.memory->space.copy_out(address + 12, &type, 4))
        return;
    auto source = static_cast<const uint8_t*>(bytes);
    size_t remaining = length - 16;
    uint64_t at = address + 16;
    while (remaining) {
        // Linux x86-64 control copies commit complete 8/4/2/1-byte stores.
        size_t copied = remaining >= 8 ? 8 : remaining >= 4 ? 4 : remaining >= 2 ? 2 : 1;
        if (!task.memory->space.copy_out(at, source, copied))
            return;
        at += copied;
        source += copied;
        remaining -= copied;
    }
    // Account for alignment without writing padding bytes.
    uint64_t consumed = min(capacity, uint64_t((16 + size + 7) & ~size_t(7)));
    used += consumed;
    address += consumed;
    capacity -= consumed;
}
} // namespace ax
