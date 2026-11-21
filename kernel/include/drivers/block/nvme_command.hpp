// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/nvme_command.hpp
 * @brief   NVMe command, completion, and DMA transfer encoding.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks namespace format and builds the PRPs for contiguous bounce buffers.
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

namespace ax::Nvme {
struct Command {
    uint16_t opcode;
    uint16_t cid;
    uint32_t nsid;
    uint64_t reserved, metadata;
    uint64_t prp1, prp2;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
};

struct Completion {
    uint32_t result, reserved;
    uint16_t head, queue, cid, status;
};

static_assert(sizeof(Command) == 64 && offsetof(Command, cdw10) == 40);
static_assert(sizeof(Completion) == 16 && offsetof(Completion, status) == 14);

constexpr unsigned bounce_pages = 4;
constexpr size_t bounce_bytes = bounce_pages * page_size;

inline bool data_pages(Command& command, uint64_t data, uint64_t list, uint64_t* entries,
                       size_t bytes) {
    if (!bytes || bytes > bounce_bytes || !data || data % page_size ||
        bytes - 1 > UINT64_MAX - data ||
        (bytes > 2 * page_size && (!list || list % page_size || !entries)))
        return false;
    command.prp1 = data;
    command.prp2 = 0;
    if (bytes > 2 * page_size) {
        command.prp2 = list;
        for (size_t page = 1; page * page_size < bytes; ++page)
            entries[page - 1] = data + page * page_size;
    } else if (bytes > page_size) {
        command.prp2 = data + page_size;
    }
    return true;
}

inline unsigned transfer_sectors(unsigned mdts) {
    constexpr unsigned maximum = bounce_bytes / sector_size;
    if (!mdts || mdts >= 2)
        return maximum;
    return (page_size / sector_size) << mdts;
}

inline bool namespace_info(const uint8_t* data, BlockInfo& info) {
    uint64_t size, capacity;
    memcpy(&size, data, sizeof(size));
    memcpy(&capacity, data + 8, sizeof(capacity));
    const unsigned format = (data[26] & 15) | ((data[26] & 0x60) >> 1);
    if (!capacity || capacity > size || size > uint64_t(INT64_MAX) / sector_size ||
        format > data[25] || (data[29] & 7))
        return false;
    const auto* lba = data + 128 + 4 * format;
    if (lba[0] || lba[1] || lba[2] != 9)
        return false;
    info = {size, bool(data[99] & 1), true};
    return true;
}

inline bool namespace_descriptors(const uint8_t* data, uint8_t (&uuid)[16]) {
    bool have_uuid = false, have_command_set = false;
    for (size_t offset = 0; offset + 4 <= page_size;) {
        const unsigned type = data[offset], length = data[offset + 1];
        if (!length)
            return !type;
        if (!type || length > page_size - offset - 4)
            return false;
        const auto* value = data + offset + 4;
        if (type == 3) {
            if (have_uuid || length != sizeof(uuid))
                return false;
            memcpy(uuid, value, sizeof(uuid));
            have_uuid = true;
        } else if (type == 4) {
            if (have_command_set || length != 1 || value[0] != 0)
                return false;
            have_command_set = true;
        }
        offset += 4 + length;
    }
    return false;
}
} // namespace ax::Nvme
