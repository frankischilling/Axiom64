// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/metadata.cpp
 * @brief   Ext4 filesystem metadata checksums and lazy allocation bitmaps.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Validates disk metadata and updates checksums within the volume transaction.
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
constexpr uint8_t zero[4]{};
constexpr int64_t inode_epoch_seconds = int64_t(1) << 32;

uint32_t inode_seed_for(uint32_t seed, uint32_t number, const uint8_t* raw) {
    uint8_t identity[4];
    set32(identity, number);
    return crc32c(crc32c(seed, identity, sizeof(identity)), raw + 100, 4);
}

bool has_inode_checksum_high(unsigned size, const uint8_t* raw) {
    return size > inode_bytes && u16(raw + inode_bytes) >= 4;
}

uint32_t inode_checksum(uint32_t seed, uint32_t number, const uint8_t* raw, unsigned size) {
    uint32_t crc = inode_seed_for(seed, number, raw);
    crc = crc32c(crc32c(crc, raw, 124), zero, 2);
    if (!has_inode_checksum_high(size, raw))
        return crc32c(crc, raw + 126, size - 126);
    crc = crc32c(crc32c(crc, raw + 126, 4), zero, 2);
    return crc32c(crc, raw + 132, size - 132);
}

uint32_t xattr_checksum(Volume& v, uint32_t block, const uint8_t* data) {
    uint8_t identity[8]{};
    set32(identity, block);
    uint32_t crc = crc32c(v.metadata_seed, identity, sizeof(identity));
    crc = crc32c(crc32c(crc, data, 16), zero, sizeof(zero));
    return crc32c(crc, data + 20, v.block_size - 20);
}

unsigned directory_index_offset(const Volume& v, const Inode& inode, uint64_t offset,
                                const uint8_t* data) {
    if (!(u32(inode + 32) & indexed_directory))
        return 0;
    if (offset < v.block_size)
        return 32;
    return !u32(data) && u16(data + 4) == v.block_size && !u16(data + 6) ? 8 : 0;
}

bool index_checksum(Volume& v, const Inode& inode, const uint8_t* data, unsigned entries,
                    uint32_t& checksum) {
    unsigned limit = u16(data + entries), count = u16(data + entries + 2);
    if (limit != (directory_index_bytes(v) - entries) / 8 || !count || count > limit)
        return v.fail();
    const uint8_t* tail = data + entries + limit * 8;
    uint32_t crc = crc32c(v.inode_seed(inode), data, entries + count * 8);
    checksum = crc32c(crc32c(crc, tail, 4), zero, 4);
    return true;
}
} // namespace

Timestamp Inode::time(InodeTimeField field) const {
    Timestamp value{int32_t(u32(bytes + field.seconds)), 0};
    if (fits(field.extra, 4)) {
        uint32_t extra = u32(bytes + field.extra);
        value.sec += (extra & 3) * inode_epoch_seconds;
        value.nsec = extra >> 2;
    }
    return value;
}

bool Inode::can_set_time(InodeTimeField field, Timestamp value) const {
    int64_t last = INT32_MAX + (fits(field.extra, 4) ? 3 * inode_epoch_seconds : 0);
    return value.sec >= INT32_MIN && value.sec <= last && value.nsec < 1000000000;
}

void Inode::set_time(InodeTimeField field, Timestamp value) {
    if (!fits(field.seconds, 4))
        return;
    if (fits(field.extra, 4)) {
        int32_t low = value.sec;
        uint32_t epoch = (value.sec - low) / inode_epoch_seconds;
        set32(bytes + field.seconds, low);
        set32(bytes + field.extra, (value.nsec << 2) | (epoch & 3));
    } else {
        set32(bytes + field.seconds, min<int64_t>(max<int64_t>(value.sec, INT32_MIN), INT32_MAX));
    }
}

bool Volume::configure_checksums(const uint8_t* header, bool stored_seed) {
    if (!checksums())
        return !stored_seed || fail(-95);
    if (header[373] != 1)
        return fail(-95);
    if (!check_super_checksum(header))
        return false;
    metadata_seed = stored_seed ? u32(header + 624) : crc32c(UINT32_MAX, header + 104, 16);
    return true;
}

bool Volume::check_super_checksum(const uint8_t* header) {
    return !checksums() || crc32c(UINT32_MAX, header, 1020) == u32(header + 1020) || fail();
}

void Volume::seal_super(uint8_t* header) const {
    set32(header + 1020, crc32c(UINT32_MAX, header, 1020));
}

uint16_t Volume::descriptor_checksum(unsigned group, const uint8_t* desc) const {
    uint8_t number[4];
    set32(number, group);
    uint32_t crc = crc32c(metadata_seed, number, sizeof(number));
    crc = crc32c(crc32c(crc, desc, 30), zero, 2);
    return crc32c(crc, desc + classic_descriptor_bytes,
                  descriptor_bytes - classic_descriptor_bytes);
}

bool Volume::check_descriptor(unsigned group, const uint8_t* desc) {
    if (descriptor_bytes >= wide_descriptor_bytes &&
        (u32(desc + 32) || u32(desc + 36) || u32(desc + 40) || u32(desc + 44) || u32(desc + 48) ||
         u32(desc + 20) || u32(desc + 52)))
        return fail();
    if (!checksums())
        return true;
    unsigned flags = u16(desc + 18);
    return (u16(desc + 30) == descriptor_checksum(group, desc) &&
            !(flags & ~(inode_uninitialized | block_uninitialized | inode_table_zeroed)) &&
            (group || !(flags & (inode_uninitialized | block_uninitialized))) &&
            u16(desc + 28) <= inodes_per_group) ||
           fail();
}

uint32_t Volume::inode_seed(const Inode& inode) const {
    return inode_seed_for(metadata_seed, inode.number, inode);
}

bool Volume::decode_inode(uint32_t number, const uint8_t* raw, Inode& inode) {
    if (inode_size > inode_bytes) {
        unsigned extra = u16(raw + inode_bytes);
        if (extra > inode_size - inode_bytes || (extra & 3))
            return fail(-95);
        unsigned attributes = inode_bytes + extra;
        if (attributes + 4 <= inode_size && u32(raw + attributes) == 0xea020000) {
            // Native tools can leave an empty in-inode list for external attributes.
            if (attributes + 8 > inode_size || u32(raw + attributes + 4))
                return fail(-95);
        }
    }
    if (checksums() && (number >= first_inode || number == 2 || u16(raw))) {
        uint32_t checksum = inode_checksum(metadata_seed, number, raw, inode_size);
        if (uint16_t(checksum) != u16(raw + 124) ||
            (has_inode_checksum_high(inode_size, raw) && (checksum >> 16) != u16(raw + 130)))
            return fail();
    }
    memcpy(inode.bytes, raw, inode_size);
    if (inode_size == inode_bytes)
        set16(inode.bytes + inode_bytes, 0);
    inode.number = number;
    return true;
}

void Volume::seal_inode(uint32_t number, uint8_t* raw) const {
    uint32_t checksum = inode_checksum(metadata_seed, number, raw, inode_size);
    set16(raw + 124, checksum);
    if (has_inode_checksum_high(inode_size, raw))
        set16(raw + 130, checksum >> 16);
}

bool Volume::read_bitmap(unsigned group, bool inode, uint8_t* data, const uint8_t* desc) {
    const auto& g = groups[group];
    uint32_t block = inode ? g.inode_bitmap : g.block_bitmap;
    if (!checksums())
        return read_block(block, data);
    uint8_t local[max_descriptor_bytes];
    if (!desc) {
        if (!descriptor(group, local))
            return false;
        desc = local;
    }
    if (u16(desc + 18) & (inode ? inode_uninitialized : block_uninitialized)) {
        // Uninitialized on-disk bitmap bytes do not describe any allocation.
        memset(data, 0, block_size);
        unsigned count = inode ? g.inodes : g.blocks;
        for (unsigned i = count; i < block_size * 8; i++)
            setbit(data, i, true);
        if (!inode)
            for (unsigned i = 0; i < count; i++)
                if (metadata(g.first + i))
                    setbit(data, i, true);
        return true;
    }
    if (!read_block(block, data))
        return false;
    unsigned bytes = (inode ? inodes_per_group : blocks_per_group) / 8;
    uint32_t checksum = crc32c(metadata_seed, data, bytes);
    unsigned low = inode ? 26 : 24;
    return (uint16_t(checksum) == u16(desc + low) &&
            (descriptor_bytes < wide_descriptor_bytes || checksum >> 16 == u16(desc + low + 32))) ||
           fail();
}

bool Volume::save_bitmap(unsigned group, bool inode, const uint8_t* data, unsigned used_inode) {
    const auto& g = groups[group];
    if (checksums()) {
        uint8_t desc[max_descriptor_bytes];
        if (!descriptor(group, desc))
            return false;
        unsigned bytes = (inode ? inodes_per_group : blocks_per_group) / 8;
        uint32_t checksum = crc32c(metadata_seed, data, bytes);
        unsigned low = inode ? 26 : 24;
        set16(desc + low, checksum);
        if (descriptor_bytes >= wide_descriptor_bytes)
            set16(desc + low + 32, checksum >> 16);
        unsigned flags = u16(desc + 18);
        set16(desc + 18, flags & ~(inode ? inode_uninitialized : block_uninitialized));
        if (inode && used_inode)
            set16(desc + 28, min<unsigned>(u16(desc + 28), inodes_per_group - used_inode));
        if (!save_descriptor(group, desc))
            return false;
    }
    return write_block(inode ? g.inode_bitmap : g.block_bitmap, data, 4);
}

bool Volume::read_xattr_block(uint32_t block, uint8_t* data) {
    if (!read_block(block, data))
        return false;
    if (checksums()) {
        if (u32(data + 16) != xattr_checksum(*this, block, data))
            return fail();
        set32(data + 16, 0);
    }
    return true;
}

bool Volume::write_xattr_block(uint32_t block, uint8_t* data, unsigned rank) {
    if (checksums())
        set32(data + 16, xattr_checksum(*this, block, data));
    return write_block(block, data, rank);
}

unsigned directory_record_end(const Volume& v, const Inode& inode, uint64_t offset,
                              const uint8_t* data) {
    return directory_index_offset(v, inode, offset, data) ? v.block_size : directory_leaf_bytes(v);
}

bool check_directory_block(Volume& v, const Inode& inode, uint64_t offset, const uint8_t* data) {
    if (!v.checksums())
        return true;
    unsigned entries = directory_index_offset(v, inode, offset, data);
    if (entries) {
        uint32_t checksum;
        return index_checksum(v, inode, data, entries, checksum) &&
               (checksum == u32(data + v.block_size - 4) || v.fail());
    }
    unsigned end = directory_leaf_bytes(v);
    const uint8_t* tail = data + end;
    return (!u32(tail) && u16(tail + 4) == 12 && !tail[6] && tail[7] == 0xde &&
            u32(tail + 8) == crc32c(v.inode_seed(inode), data, end)) ||
           v.fail();
}

bool save_directory_leaf(Volume& v, const Inode& inode, uint32_t block, uint8_t* data) {
    if (v.checksums()) {
        unsigned end = directory_leaf_bytes(v);
        uint8_t* tail = data + end;
        set32(tail, 0);
        set16(tail + 4, 12);
        tail[6] = 0;
        tail[7] = 0xde;
        set32(tail + 8, crc32c(v.inode_seed(inode), data, end));
    }
    return v.write_block(block, data, 3);
}

bool save_directory_index(Volume& v, const Inode& inode, uint32_t block, uint8_t* data,
                          unsigned entries) {
    if (v.checksums()) {
        uint32_t checksum;
        set32(data + v.block_size - 8, 0);
        if (!index_checksum(v, inode, data, entries, checksum))
            return false;
        set32(data + v.block_size - 4, checksum);
    }
    return v.write_block(block, data, 3);
}

bool save_directory_block(Volume& v, const Inode& inode, uint64_t offset, uint32_t block,
                          uint8_t* data) {
    unsigned entries = directory_index_offset(v, inode, offset, data);
    return entries ? save_directory_index(v, inode, block, data, entries)
                   : save_directory_leaf(v, inode, block, data);
}
} // namespace ax::ext2_detail
