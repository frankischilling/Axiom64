// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/socket_filter.cpp
 * @brief   Validate and evaluate classic BPF over socket payloads.
 * @author  frankischilling
 * @date    2026-11-23
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
#include "net/socket_filter.hpp"
#include "process/task.hpp"

namespace ax {
struct SocketFilterInstruction {
    uint16_t code;
    uint8_t yes, no;
    uint32_t operand;
};

namespace {
struct FilterProgram {
    uint16_t length;
    uint64_t instructions;
};

static_assert(sizeof(FilterProgram) == 16 && sizeof(SocketFilterInstruction) == 8);

constexpr unsigned load_word = 0x20, and_constant = 0x54, jump_equal = 0x15, return_constant = 0x06;
constexpr unsigned instruction_limit = 4096;

bool valid(const SocketFilterInstruction* program, unsigned count) {
    if (program[count - 1].code != return_constant)
        return false;
    for (unsigned i = 0; i < count; ++i) {
        const auto& instruction = program[i];
        switch (instruction.code) {
        case load_word:
            if (instruction.operand > INT32_MAX)
                return false; // Ancillary loads use negative offsets.
            break;
        case and_constant:
        case return_constant:
            break;
        case jump_equal:
            if (i + 1 + max(instruction.yes, instruction.no) >= count)
                return false;
            break;
        default:
            return false;
        }
    }
    return true;
}
} // namespace

int SocketFilter::install(Task& task, uint64_t address, size_t size) {
    FilterProgram source;
    if (size != sizeof(source))
        return -22;
    if (!task.memory->space.copy_in(&source, address, sizeof(source)))
        return -14;
    if (!source.length || source.length > instruction_limit)
        return -22;
    const size_t bytes = source.length * sizeof(SocketFilterInstruction);
    auto program = static_cast<SocketFilterInstruction*>(alloc(bytes));
    if (!program)
        return -12;
    if (!task.memory->space.copy_in(program, source.instructions, bytes)) {
        release(program);
        return -14;
    }
    if (!valid(program, source.length)) {
        release(program);
        return -22;
    }
    clear();
    instructions = program;
    length = source.length;
    return 0;
}

size_t SocketFilter::accept(const void* payload, size_t size) const {
    if (!instructions)
        return size;
    const auto bytes = static_cast<const uint8_t*>(payload);
    uint32_t accumulator = 0;
    for (unsigned i = 0; i < length; ++i) {
        const auto& instruction = instructions[i];
        switch (instruction.code) {
        case load_word: {
            const size_t offset = instruction.operand;
            if (offset > size || size - offset < 4)
                return 0;
            accumulator = (uint32_t(bytes[offset]) << 24) | (uint32_t(bytes[offset + 1]) << 16) |
                          (uint32_t(bytes[offset + 2]) << 8) | bytes[offset + 3];
            break;
        }
        case and_constant:
            accumulator &= instruction.operand;
            break;
        case jump_equal:
            i += accumulator == instruction.operand ? instruction.yes : instruction.no;
            break;
        case return_constant:
            return min(size, size_t(instruction.operand));
        }
    }
    return 0;
}

void SocketFilter::clear() {
    release(instructions);
    *this = {};
}
} // namespace ax
