// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/block/nvme.cpp
 * @brief   Tests NVMe namespace parsing, transfer limits, and DMA pages.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks PRP boundaries, metadata rejection, and namespace descriptor framing.
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
#include "drivers/block/nvme_command.hpp"

namespace {
using namespace ax;

void geometry() {
    uint8_t data[page_size]{};
    BlockInfo info{};
    assert(!Nvme::namespace_info(data, info));
    const uint64_t sectors = 8192;
    memcpy(data, &sectors, sizeof(sectors));
    memcpy(data + 8, &sectors, sizeof(sectors));
    data[128 + 2] = 9;
    assert(Nvme::namespace_info(data, info) && info.sectors == sectors && !info.readonly &&
           info.flush_supported);
    data[99] = 1;
    assert(Nvme::namespace_info(data, info) && info.readonly);
    data[128] = 8;
    assert(!Nvme::namespace_info(data, info));
    data[128] = 0;
    data[128 + 2] = 12;
    assert(!Nvme::namespace_info(data, info));
    data[25] = 16;
    data[26] = 0x20;
    data[128 + 16 * 4 + 2] = 9;
    assert(Nvme::namespace_info(data, info));
    data[29] = 1;
    assert(!Nvme::namespace_info(data, info));
}

void descriptors() {
    uint8_t data[page_size]{}, uuid[16]{};
    data[0] = 3;
    data[1] = 16;
    data[4] = 0xa4;
    data[20] = 4;
    data[21] = 1;
    assert(Nvme::namespace_descriptors(data, uuid) && uuid[0] == 0xa4 && uuid[1] == 0);
    data[24] = 2;
    assert(!Nvme::namespace_descriptors(data, uuid));
    data[24] = 0;
    data[25] = 4;
    data[26] = 1;
    assert(!Nvme::namespace_descriptors(data, uuid));
    data[1] = 255;
    assert(!Nvme::namespace_descriptors(data, uuid));
}

void page_pointers() {
    Nvme::Command command{};
    uint64_t entries[3]{};
    const uint64_t data = 0x12345000, list = 0x12349000;
    assert(Nvme::data_pages(command, data, list, entries, page_size));
    assert(command.prp1 == data && command.prp2 == 0);
    assert(Nvme::data_pages(command, data, list, entries, 2 * page_size));
    assert(command.prp2 == data + page_size && entries[0] == 0);
    assert(Nvme::data_pages(command, data, list, entries, 2 * page_size + sector_size));
    assert(command.prp2 == list && entries[0] == data + page_size &&
           entries[1] == data + 2 * page_size && entries[2] == 0);
    assert(Nvme::data_pages(command, data, list, entries, 4 * page_size));
    assert(entries[2] == data + 3 * page_size);
    assert(!Nvme::data_pages(command, data, list, entries, 4 * page_size + 1));
    assert(!Nvme::data_pages(command, data + 1, list, entries, page_size));
    assert(!Nvme::data_pages(command, data, list + 1, entries, 4 * page_size));
    assert(Nvme::transfer_sectors(0) == 32 && Nvme::transfer_sectors(1) == 16 &&
           Nvme::transfer_sectors(2) == 32 && Nvme::transfer_sectors(255) == 32);
}
} // namespace

int main() {
    geometry();
    descriptors();
    page_pointers();
    std::puts("NVME_COMMAND_PASS namespace_format descriptors mdts prp1 prp2 prp_list");
}
