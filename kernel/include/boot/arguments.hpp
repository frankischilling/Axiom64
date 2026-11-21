// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/boot/arguments.hpp
 * @brief   Parse bounded kernel command-line arguments.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Reads exact boot flags and rejects ambiguous keyed values.
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
class BootArguments {
    const char* line;

    static bool space(char value) {
        return value == ' ' || value == '\t';
    }

    static bool next(const char*& cursor, const char*& begin, size_t& length) {
        while (space(*cursor))
            ++cursor;
        begin = cursor;
        while (*cursor && !space(*cursor))
            ++cursor;
        length = cursor - begin;
        return length != 0;
    }

  public:
    explicit BootArguments(const char* command_line) : line(command_line ? command_line : "") {
    }

    bool has(const char* word) const {
        size_t length, size = strlen(word);
        const char* cursor = line;
        const char* begin;
        while (next(cursor, begin, length))
            if (length == size && !memcmp(begin, word, size))
                return true;
        return false;
    }

    // A key includes the trailing '='. Duplicate, empty and oversized values are invalid.
    int read(const char* key, char* value, size_t capacity) const {
        size_t length, size = strlen(key);
        const char* cursor = line;
        const char* begin;
        bool found = false;
        while (next(cursor, begin, length)) {
            if (length < size || memcmp(begin, key, size))
                continue;
            size_t count = length - size;
            if (found || !count || count >= capacity)
                return -22;
            memcpy(value, begin + size, count);
            value[count] = 0;
            found = true;
        }
        return found ? 1 : 0;
    }
};
} // namespace ax
