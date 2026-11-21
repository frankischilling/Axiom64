// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/crc.hpp
 * @brief   CRC accumulators for filesystem metadata and journal records.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Updates caller-supplied CRC states without implicit initial or final XORs.
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

#include <stddef.h>
#include <stdint.h>

namespace ax {
namespace crc_detail {
template <bool reflected, uint32_t polynomial> struct Table {
    uint32_t rows[256]{};

    constexpr Table() {
        for (unsigned i = 0; i < 256; i++) {
            uint32_t row = reflected ? i : uint32_t(i) << 24;
            for (unsigned j = 0; j < 8; j++) {
                if constexpr (reflected)
                    row = (row >> 1) ^ ((row & 1) ? polynomial : 0);
                else
                    row = (row << 1) ^ ((row >> 31) ? polynomial : 0);
            }
            rows[i] = row;
        }
    }

    uint32_t update(uint32_t crc, const uint8_t* data, size_t length) const {
        for (size_t i = 0; i < length; i++) {
            if constexpr (reflected)
                crc = (crc >> 8) ^ rows[(crc ^ data[i]) & 0xff];
            else
                crc = (crc << 8) ^ rows[(crc >> 24) ^ data[i]];
        }
        return crc;
    }
};

inline constexpr Table<true, 0x82f63b78> castagnoli;
inline constexpr Table<false, 0x04c11db7> ieee_be;
} // namespace crc_detail

inline uint32_t crc32c(uint32_t crc, const uint8_t* bytes, size_t length) {
    return crc_detail::castagnoli.update(crc, bytes, length);
}

inline uint32_t crc32_be(uint32_t crc, const uint8_t* bytes, size_t length) {
    return crc_detail::ieee_be.update(crc, bytes, length);
}
} // namespace ax
