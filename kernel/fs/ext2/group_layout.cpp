// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/group_layout.cpp
 * @brief   Ext2 and ext4 physical block group metadata placement.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Validates and indexes reserved metadata, including flex group placements.
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

namespace ax::ext2_detail {
namespace {
void sift_down(MetadataRange* ranges, unsigned count, unsigned root) {
    while (root < count / 2) {
        unsigned child = 2 * root + 1;
        if (child + 1 < count && ranges[child + 1].begin > ranges[child].begin)
            child++;
        if (ranges[root].begin >= ranges[child].begin)
            break;
        auto entry = ranges[root];
        ranges[root] = ranges[child];
        ranges[child] = entry;
        root = child;
    }
}
} // namespace

bool Volume::build_metadata_ranges(bool flex_groups) {
    metadata_ranges = static_cast<MetadataRange*>(alloc(group_count * 4 * sizeof(MetadataRange)));
    if (!metadata_ranges)
        return fail(-12);
    unsigned table_blocks = inodes_per_group * inode_size / block_size;
    for (unsigned group = 0; group < group_count; group++) {
        const auto& g = groups[group];
        if (has_super(group)) {
            unsigned reserved = 1 + gdt_blocks + reserved_gdt;
            if (reserved > g.blocks)
                return fail();
            metadata_ranges[metadata_range_count++] = {g.first, g.first + reserved};
        }
        uint32_t first_allowed = flex_groups ? first : g.first;
        uint32_t end_allowed = flex_groups ? blocks : g.first + g.blocks;
        const uint32_t starts[] = {g.block_bitmap, g.inode_bitmap, g.inode_table};
        const unsigned lengths[] = {1, 1, table_blocks};
        for (unsigned i = 0; i < 3; i++) {
            uint64_t end = uint64_t(starts[i]) + lengths[i];
            if (starts[i] < first_allowed || end > end_allowed)
                return fail();
            metadata_ranges[metadata_range_count++] = {starts[i], uint32_t(end)};
        }
    }

    // Sort by physical block so a collision is detectable across logical groups.
    auto ranges = metadata_ranges;
    for (unsigned count = metadata_range_count, i = count / 2; i; i--)
        sift_down(ranges, count, i - 1);
    for (unsigned remaining = metadata_range_count; remaining > 1; remaining--) {
        auto last = ranges[remaining - 1];
        ranges[remaining - 1] = ranges[0];
        ranges[0] = last;
        sift_down(ranges, remaining - 1, 0);
    }
    for (unsigned i = 1; i < metadata_range_count; i++)
        if (ranges[i].begin < ranges[i - 1].end)
            return fail();
    return true;
}

bool Volume::metadata(uint32_t block) const {
    if (block < first || block >= blocks)
        return true;
    unsigned lo = 0, hi = metadata_range_count;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        if (metadata_ranges[mid].end <= block)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < metadata_range_count && metadata_ranges[lo].begin <= block;
}
} // namespace ax::ext2_detail
