// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/core/classic_filter.cpp
 * @brief   Classic BPF validation and execution.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Validates forward-only filter programs and reads their input within bounds.
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
#include "core/classic_filter.hpp"

namespace ax {
namespace {
constexpr uint32_t ancillary = 0xfffff000;
constexpr unsigned slots = 16;
constexpr uint16_t ld = 0, ldx = 1, st = 2, stx = 3, alu = 4, jmp = 5, ret = 6, misc = 7;
constexpr uint16_t half = 8, byte = 16, immediate = 0, absolute = 0x20, indirect = 0x40,
                   memory = 0x60, length = 0x80, header_shift = 0xa0, from_x = 8;
constexpr uint16_t add = 0, subtract = 0x10, multiply = 0x20, divide = 0x30, bit_or = 0x40,
                   bit_and = 0x50, left_shift = 0x60, right_shift = 0x70, negate = 0x80,
                   modulo = 0x90, bit_xor = 0xa0;
constexpr uint16_t always = 0, equal = 0x10, greater = 0x20, at_least = 0x30, bit_set = 0x40;
constexpr uint16_t result_a = 0x10, x_to_a = 0x80;

bool ancillary_value(uint32_t offset, const FilterInput& input, uint32_t& value) {
    switch (offset) {
    case ancillary:
        value = input.protocol;
        return true;
    case ancillary + 4:
        value = input.type;
        return true;
    case ancillary + 8:
        value = input.interface;
        return true;
    default:
        return false;
    }
}

bool supported_load(const FilterInstruction& item, FilterContext context, size_t input_size) {
    const auto mode = item.code & 0xe0, width = item.code & 0x18;
    bool to_x = item.code & 1;
    if (mode == immediate || mode == length || mode == memory)
        return width == 0 && (mode != memory || item.value < slots);
    if (context == FilterContext::syscall)
        return item.code == absolute && !(item.value & 3) && item.value <= input_size &&
               sizeof(uint32_t) <= input_size - item.value;
    if (mode == header_shift)
        return to_x && width == byte;
    if (to_x || (mode != absolute && mode != indirect) || width == 0x18)
        return false;
    if (mode == absolute && item.value >= ancillary) {
        uint32_t value;
        // Linux decodes these extensions by offset for all three load widths.
        return ancillary_value(item.value, {}, value);
    }
    return true;
}

bool load(const FilterInstruction& item, const FilterInput& input, uint32_t x,
          const uint32_t (&scratch)[slots], uint32_t& result, FilterContext context) {
    const auto mode = item.code & 0xe0;
    if (mode == immediate)
        result = item.value;
    else if (mode == memory)
        result = scratch[item.value];
    else if (mode == length)
        result = input.length;
    else if (context == FilterContext::syscall) {
        if (item.value > input.length || sizeof(result) > input.length - item.value)
            return false;
        memcpy(&result, input.data + item.value, sizeof(result));
    } else if (mode == absolute && item.value >= ancillary)
        return ancillary_value(item.value, input, result);
    else {
        const uint64_t offset = uint64_t(item.value) + (mode == indirect ? x : 0);
        const auto width = item.code & 0x18;
        const size_t size = (width == byte ? 1 : width == half ? 2 : 4);
        if (offset > input.length || size > input.length - offset)
            return false;
        result = 0;
        for (size_t index = 0; index < size; ++index)
            result = (result << 8) | input.data[offset + index];
        if (mode == header_shift)
            result = (result & 15) * 4;
    }
    return true;
}

bool calculate(uint16_t operation, uint32_t& a, uint32_t value) {
    switch (operation) {
    case add:
        a += value;
        break;
    case subtract:
        a -= value;
        break;
    case multiply:
        a *= value;
        break;
    case divide:
        if (!value)
            return false;
        a /= value;
        break;
    case bit_or:
        a |= value;
        break;
    case bit_and:
        a &= value;
        break;
    case left_shift:
        a <<= value & 31;
        break;
    case right_shift:
        a >>= value & 31;
        break;
    case negate:
        a = 0 - a;
        break;
    case modulo:
        if (!value)
            return false;
        a %= value;
        break;
    case bit_xor:
        a ^= value;
        break;
    default:
        return false;
    }
    return true;
}

bool branch(uint16_t operation, uint32_t a, uint32_t value) {
    switch (operation) {
    case equal:
        return a == value;
    case greater:
        return a > value;
    case at_least:
        return a >= value;
    case bit_set:
        return (a & value) != 0;
    default:
        return false;
    }
}
} // namespace

bool validate_classic_filter(const FilterInstruction* code, unsigned count, uint16_t* masks,
                             FilterContext context, size_t input_size) {
    if (!count || count > max_classic_filter_instructions || (code[count - 1].code & 7) != ret)
        return false;
    memset(masks, 0xff, count * sizeof(*masks));
    masks[0] = 0;
    for (unsigned index = 0; index < count; ++index) {
        const auto& item = code[index];
        if (item.code > 0xff)
            return false;
        const auto operation = item.code & 0xf0;
        uint16_t initialized = masks[index];
        const unsigned remaining = count - index - 1;
        switch (item.code & 7) {
        case ld:
        case ldx:
            if (!supported_load(item, context, input_size) ||
                ((item.code & 0xe0) == memory && !(initialized & (1u << item.value))))
                return false;
            break;
        case st:
        case stx:
            if (item.code > stx || item.value >= slots)
                return false;
            initialized |= 1u << item.value;
            break;
        case alu:
            if (operation > bit_xor || (context == FilterContext::syscall && operation == modulo) ||
                (operation == negate && (item.code & from_x)) ||
                (!(item.code & from_x) &&
                 (((operation == divide || operation == modulo) && !item.value) ||
                  ((operation == left_shift || operation == right_shift) && item.value >= 32))))
                return false;
            break;
        case jmp:
            if (operation == always) {
                if ((item.code & from_x) || item.value >= remaining)
                    return false;
                masks[index + 1 + item.value] &= initialized;
            } else {
                if (operation > bit_set || item.jump_true >= remaining ||
                    item.jump_false >= remaining)
                    return false;
                masks[index + 1 + item.jump_true] &= initialized;
                masks[index + 1 + item.jump_false] &= initialized;
            }
            continue;
        case ret:
            if (item.code != ret && item.code != (ret | result_a))
                return false;
            continue;
        case misc:
            if (item.code != misc && item.code != (misc | x_to_a))
                return false;
            break;
        }
        if (!remaining)
            return false;
        masks[index + 1] &= initialized;
    }
    return true;
}

uint32_t run_classic_filter(const FilterInstruction* code, unsigned count, const FilterInput& input,
                            FilterContext context) {
    uint32_t a = 0, x = 0, scratch[slots]{};
    for (unsigned index = 0; index < count; ++index) {
        const auto& item = code[index];
        const auto operation = item.code & 0xf0;
        const uint32_t operand = item.code & from_x ? x : item.value;
        switch (item.code & 7) {
        case ld:
        case ldx:
            if (!load(item, input, x, scratch, item.code & 1 ? x : a, context))
                return 0;
            break;
        case st:
            scratch[item.value] = a;
            break;
        case stx:
            scratch[item.value] = x;
            break;
        case alu:
            if (!calculate(operation, a, operand))
                return 0;
            break;
        case jmp:
            index += operation == always             ? item.value
                     : branch(operation, a, operand) ? item.jump_true
                                                     : item.jump_false;
            break;
        case ret:
            return item.code & result_a ? a : item.value;
        case misc:
            if (item.code & x_to_a)
                a = x;
            else
                x = a;
            break;
        }
    }
    return 0;
}
} // namespace ax
