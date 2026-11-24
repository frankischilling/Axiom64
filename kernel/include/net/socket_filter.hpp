// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/socket_filter.hpp
 * @brief   Classic socket filter programs.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Defines the Linux instruction layout and the input to a socket filter.
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

struct FilterInstruction {
    uint16_t code;
    uint8_t jump_true, jump_false;
    uint32_t value;
};

static_assert(sizeof(FilterInstruction) == 8);
constexpr unsigned max_socket_filter_instructions = 4096;

struct FilterInput {
    const uint8_t* data;
    size_t length;
    uint32_t protocol = 0, type = 0, interface = 0;
};

// The caller supplies one mask per instruction for forward scratch validation.
bool validate_socket_filter(const FilterInstruction*, unsigned count, uint16_t* masks);

uint32_t run_socket_filter(const FilterInstruction*, unsigned count, const FilterInput&);

struct SocketFilter {
    FilterInstruction* code = nullptr;
    unsigned count = 0;

    int attach(Task&, uint64_t pointer, size_t length);

    int detach();

    size_t snapshot(const FilterInput& input) const {
        return code ? min(input.length, size_t(run_socket_filter(code, count, input)))
                    : input.length;
    }
};
} // namespace ax
