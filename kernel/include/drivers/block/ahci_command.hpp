// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/ahci_command.hpp
 * @brief   AHCI command and DMA memory layout.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Builds register FISes and a single-entry physical region descriptor.
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

namespace ax::Ahci {
struct CommandTable {
    uint8_t frame[128]; // Register FIS, ATAPI command area, and reserved bytes.
    uint32_t data[4];   // One PRD spans the contiguous bounce buffer.
};

struct CommandMemory {
    uint32_t list[256];
    uint8_t received[256];
    CommandTable table;
};

static_assert(offsetof(CommandMemory, received) == 0x400);
static_assert(offsetof(CommandMemory, table) == 0x500);
static_assert(offsetof(CommandTable, data) == 0x80);
static_assert(sizeof(CommandMemory) <= page_size);

inline void prepare(CommandMemory& memory, uint64_t dma, uint8_t opcode, uint64_t sector,
                    uint16_t count, uint32_t bytes, bool extended, bool write) {
    auto& table = memory.table;
    table = {};
    const uint64_t table_address = dma + offsetof(CommandMemory, table);
    memory.list[0] = 5 | (write ? 1u << 6 : 0) | (bytes ? 1u << 16 : 0);
    memory.list[1] = 0;
    memory.list[2] = uint32_t(table_address);
    memory.list[3] = table_address >> 32;
    auto& frame = table.frame;
    frame[0] = 0x27; // Host-to-device register FIS.
    frame[1] = 0x80; // Update the command register.
    frame[2] = opcode;
    for (unsigned i = 0; i < 3; ++i)
        frame[4 + i] = sector >> (8 * i);
    frame[7] = opcode == 0xec ? 0 : 0xe0 | (extended ? 0 : (sector >> 24) & 15);
    if (extended) {
        for (unsigned i = 0; i < 3; ++i)
            frame[8 + i] = sector >> (24 + 8 * i);
        frame[13] = count >> 8;
    }
    frame[12] = count;
    if (bytes) {
        const uint64_t data_address = dma + page_size;
        table.data[0] = uint32_t(data_address);
        table.data[1] = data_address >> 32;
        table.data[3] = bytes - 1;
    }
}
} // namespace ax::Ahci
