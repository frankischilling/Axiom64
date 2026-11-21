// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/block/ahci.cpp
 * @brief   Checks ATA identify parsing and the AHCI DMA command layout.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercises address widths, transfer descriptors, and empty flush payloads.
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
#include <cassert>
#include <cstdio>
#include "drivers/block/ahci_command.hpp"
#include "drivers/block/ata_identity.hpp"

namespace {
using namespace ax;

void identity() {
    uint16_t words[256]{};
    AtaIdentity decoded{};
    assert(!ata_identity(words, decoded));
    words[49] = 0x300;
    words[60] = 8192;
    words[83] = 0x5000;
    assert(ata_identity(words, decoded) && decoded.sectors == 8192 && !decoded.extended);
    assert(decoded.flush_command == 0xe7);
    words[83] = 0x7400;
    words[101] = 16;
    words[102] = 1;
    assert(ata_identity(words, decoded) && decoded.extended && decoded.sectors == 0x100100000ull);
    assert(decoded.flush_command == 0xea);
    words[106] = 0x5000;
    words[117] = 2048;
    assert(!ata_identity(words, decoded));
    words[117] = 256;
    assert(ata_identity(words, decoded));
    words[103] = 2;
    assert(!ata_identity(words, decoded));
    words[103] = 0;
    words[83] = 0xa000;
    assert(ata_identity(words, decoded) && decoded.sectors == 8192 && !decoded.flush_command);
    words[0] = 0x8000;
    assert(!ata_identity(words, decoded));
}

void commands() {
    Ahci::CommandMemory memory{};
    constexpr uint64_t dma = 0x12345000;
    Ahci::prepare(memory, dma, 0x35, 0x123456789abc, 32, 16384, true, true);
    const auto& list = memory.list;
    const auto& frame = memory.table.frame;
    const auto& prd = memory.table.data;
    assert(list[0] == 0x10045 && list[1] == 0 && list[2] == dma + 0x500 && list[3] == 0);
    const uint8_t expected[]{0x27, 0x80, 0x35, 0, 0xbc, 0x9a, 0x78, 0xe0, 0x56, 0x34,
                             0x12, 0,    32,   0, 0,    0,    0,    0,    0,    0};
    assert(!memcmp(frame, expected, sizeof(expected)));
    assert(prd[0] == dma + page_size && prd[1] == 0 && prd[2] == 0 && prd[3] == 16383);
    memory.list[1] = 16384;
    Ahci::prepare(memory, dma, 0xc8, 0x0fedcba9, 1, 512, false, false);
    assert(list[0] == 0x10005 && list[1] == 0 && frame[2] == 0xc8 && frame[7] == 0xef);
    assert(frame[4] == 0xa9 && frame[5] == 0xcb && frame[6] == 0xed && !frame[8]);
    assert(frame[12] == 1 && frame[13] == 0 && prd[3] == 511);
    Ahci::prepare(memory, dma, 0xea, 0, 0, 0, true, false);
    assert(list[0] == 5 && frame[2] == 0xea && !prd[0] && !prd[3]);
    Ahci::prepare(memory, dma, 0xec, 0, 0, 512, false, false);
    assert(list[0] == 0x10005 && frame[2] == 0xec && !frame[7] && prd[3] == 511);
}
} // namespace

int main() {
    identity();
    commands();
    std::puts("AHCI_COMMAND_PASS identify lba28 lba48 aligned_dma single_prd flush identify_fis");
}
