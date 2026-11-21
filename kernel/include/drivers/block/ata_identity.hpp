// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/ata_identity.hpp
 * @brief   ATA disk identity geometry and flush support.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Decodes the IDENTIFY DEVICE fields shared by ATA and SATA disks.
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
#include "drivers/block/block.hpp"

namespace ax {
inline constexpr uint64_t lba28_limit = 1ull << 28;
inline constexpr uint64_t lba48_limit = 1ull << 48;

struct AtaIdentity {
    uint64_t sectors;
    uint8_t flush_command;
    bool extended;
};

inline bool ata_identity(const uint16_t* words, AtaIdentity& identity) {
    if ((words[0] & 0x8000) || !(words[49] & 0x200))
        return false;
    if ((words[106] & 0xd000) == 0x5000 && (words[117] != sector_size / 2 || words[118] != 0))
        return false;
    const bool commands_valid = (words[83] & 0xc000) == 0x4000;
    const bool extended = commands_valid && (words[83] & 0x0400);
    uint64_t capacity = uint32_t(words[61]) << 16 | words[60];
    if (extended) {
        capacity = 0;
        for (unsigned i = 0; i < 4; ++i)
            capacity |= uint64_t(words[100 + i]) << (16 * i);
    }
    if (!capacity || capacity > (extended ? lba48_limit : lba28_limit))
        return false;
    const uint8_t flush = commands_valid && extended && (words[83] & 0x2000) ? 0xea
                          : commands_valid && (words[83] & 0x1000)           ? 0xe7
                                                                             : 0;
    identity = {capacity, flush, extended};
    return true;
}
} // namespace ax
