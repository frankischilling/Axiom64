// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/orphans.cpp
 * @brief   Validate native ext4 orphan lists and orphan files.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Reads persistent orphan records from the staged journal view and clears
 * them through the same transaction as the validated inode cleanup.
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
#include "volume.hpp"
#include "core/crc.hpp"

namespace ax::ext2_detail {
namespace {
constexpr uint32_t orphan_block_magic = 0x0b10ca04;
constexpr unsigned orphan_block_limit = 512, orphan_tail_bytes = 8;

uint32_t checksum(Volume& v, const Inode& inode, uint32_t block, const uint8_t* data) {
    uint8_t address[8]{};
    set32(address, block);
    return crc32c(crc32c(v.inode_seed(inode), address, sizeof(address)), data,
                  v.block_size - orphan_tail_bytes);
}
} // namespace

bool NativeOrphans::mark(uint32_t number, const uint8_t* allocated, Inode& inode) {
    if (!pending || number < v.first_inode || number > v.inodes || number == v.orphan_inode ||
        !bit(allocated, number) || contains(number) || !v.load_inode(number, inode, false))
        return v.fail();
    unsigned type = u16(inode) & 0170000;
    if (type != regular_file && type != directory && type != symlink &&
        (u16(inode + 26) || (type != fifo && type != 0140000)))
        return v.fail();
    setbit(pending, number, true);
    return true;
}

bool NativeOrphans::check_file(const uint8_t* header, const uint8_t* allocated, bool clear) {
    if (!v.orphan_inode)
        return true;
    Inode inode;
    if (!v.load_inode(v.orphan_inode, inode))
        return false;
    uint64_t length = file_size(inode);
    if ((u16(inode) & 0170000) != regular_file || u16(inode + 26) != 1 || u32(inode + 20) ||
        u32(inode + 104) || length % v.block_size || length / v.block_size > orphan_block_limit)
        return v.fail();
    unsigned tail = v.block_size - orphan_tail_bytes;
    bool present = (u32(header + 100) & orphan_present_feature) != 0;
    for (unsigned index = 0; index < length / v.block_size; index++) {
        uint32_t block;
        uint8_t data[max_block_size];
        if (!v.map_block(inode, index, false, block, 0) || !block || !v.read_block(block, data))
            return v.fail();
        if (u32(data + tail) != orphan_block_magic ||
            (v.checksums() && u32(data + tail + 4) != checksum(v, inode, block, data)))
            return v.fail();
        bool changed = false;
        for (unsigned offset = 0; offset < tail; offset += 4) {
            uint32_t number = u32(data + offset);
            if (!number)
                continue;
            if (!present)
                return v.fail();
            if (clear) {
                set32(data + offset, 0);
                changed = true;
            } else {
                Inode orphan;
                if (!mark(number, allocated, orphan) || u32(orphan + 20))
                    return v.fail();
            }
        }
        if (!changed)
            continue;
        if (v.checksums())
            set32(data + tail + 4, checksum(v, inode, block, data));
        if (!v.write_block(block, data, 4))
            return false;
    }
    return true;
}

bool NativeOrphans::collect(const uint8_t* header, const uint8_t* allocated) {
    if (native_orphans_pending(header)) {
        if (!v.journal)
            return v.fail();
        size_t bytes = (uint64_t(v.inodes) + 8) / 8;
        pending = static_cast<uint8_t*>(alloc(bytes));
        if (!pending)
            return v.fail(-12);
        memset(pending, 0, bytes);
        uint32_t number = u32(header + last_orphan_offset);
        while (number) {
            Inode inode;
            if (!mark(number, allocated, inode))
                return false;
            number = u32(inode + 20);
        }
    }
    return check_file(header, allocated, false);
}

bool NativeOrphans::clear(uint8_t* header) {
    if ((u32(header + 100) & orphan_present_feature) && !check_file(header, nullptr, true))
        return false;
    set32(header + last_orphan_offset, 0);
    set32(header + 100, u32(header + 100) & ~orphan_present_feature);
    return v.save_super(header);
}
} // namespace ax::ext2_detail
