// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/extent_tree.cpp
 * @brief   Ext4 extent mapping, mutation, and allocation validation.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Maintains extent nodes using the same transaction as data, inodes, and bitmaps.
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
constexpr unsigned header_bytes = 12, entry_bytes = 12, max_depth = 5;
constexpr uint16_t extent_magic = 0xf30a, initialized_max = 32768;

unsigned entry_limit(unsigned bytes) {
    return (bytes - header_bytes) / entry_bytes;
}

struct Extent {
    uint32_t logical, physical;
    unsigned length;
    bool unwritten;

    uint64_t end() const {
        return uint64_t(logical) + length;
    }
};

struct ExtentPage {
    // Replacing one unwritten extent can add two records before a split.
    uint8_t data[max_block_size + 2 * entry_bytes];

    unsigned count() const {
        return u16(data + 2);
    }

    unsigned limit() const {
        return u16(data + 4);
    }

    unsigned depth() const {
        return u16(data + 6);
    }

    void count(unsigned n) {
        set16(data + 2, n);
    }

    void limit(unsigned n) {
        set16(data + 4, n);
    }

    const uint8_t* row(unsigned i) const {
        return data + header_bytes + i * entry_bytes;
    }

    uint8_t* row(unsigned i) {
        return data + header_bytes + i * entry_bytes;
    }

    uint32_t key(unsigned i) const {
        return u32(row(i));
    }

    uint32_t child(unsigned i) const {
        return u32(row(i) + 4);
    }

    Extent leaf(unsigned i) const {
        unsigned length = u16(row(i) + 4);
        bool unwritten = length > initialized_max;
        return {key(i), u32(row(i) + 8), length - (unwritten ? initialized_max : 0), unwritten};
    }

    void leaf(unsigned i, const Extent& extent) {
        auto p = row(i);
        set32(p, extent.logical);
        set16(p + 4, extent.length + (extent.unwritten ? initialized_max : 0));
        set16(p + 6, 0);
        set32(p + 8, extent.physical);
    }

    void index(unsigned i, uint32_t key, uint32_t block) {
        set32(row(i), key);
        set32(row(i) + 4, block);
        set32(row(i) + 8, 0);
    }

    void resize_rows(unsigned at, unsigned remove, unsigned insert) {
        unsigned remaining = count() - at - remove;
        if (remaining && remove != insert)
            memmove(row(at + insert), row(at + remove), remaining * entry_bytes);
        count(count() - remove + insert);
    }

    unsigned upper_bound(uint32_t logical) const {
        unsigned left = 0, right = count();
        while (left < right) {
            unsigned middle = (left + right) / 2;
            if (key(middle) <= logical)
                left = middle + 1;
            else
                right = middle;
        }
        return left;
    }

    bool header_valid(unsigned bytes, unsigned expected_depth, bool root) const {
        return u16(data) == extent_magic && depth() == expected_depth && depth() <= max_depth &&
               limit() && limit() <= entry_limit(bytes) && count() <= limit() &&
               (count() || (root && !depth()));
    }
};

void reset_header(uint8_t* data, unsigned bytes, unsigned depth) {
    memset(data, 0, bytes);
    set16(data, extent_magic);
    set16(data + 4, entry_limit(bytes));
    set16(data + 6, depth);
}

bool load_root(Volume& v, const uint8_t* inode, ExtentPage& page) {
    memcpy(page.data, inode + 40, inode_block_bytes);
    return page.header_valid(inode_block_bytes, page.depth(), true) || v.fail();
}

bool load_child(Volume& v, const ExtentPage& page, unsigned i, ExtentPage& child) {
    uint32_t block = page.child(i), logical = page.key(i);
    unsigned depth = page.depth() - 1;
    if (u16(page.row(i) + 8) || !v.data_block(block) || !v.read_block(block, child.data))
        return v.fail();
    return (child.header_valid(v.block_size, depth, false) && child.key(0) == logical) || v.fail();
}

bool claim(Volume& v, const ExtentOwnership& ownership, uint32_t block, unsigned length) {
    if (!block || block < v.first || block >= v.blocks || length > v.blocks - block)
        return v.fail();
    for (unsigned i = 0; i < length; i++) {
        if (!bit(ownership.allocated, block + i) || bit(ownership.owned, block + i) ||
            v.metadata(block + i))
            return v.fail();
        setbit(ownership.owned, block + i, true);
    }
    ownership.blocks += length;
    return true;
}

bool validate(Volume& v, const ExtentPage& page, uint64_t high, uint64_t file_blocks,
              bool allow_unwritten, const ExtentOwnership& ownership) {
    uint64_t previous_end = 0;
    for (unsigned i = 0; i < page.count(); i++) {
        uint32_t logical = page.key(i);
        if (logical < previous_end || logical >= high)
            return v.fail();
        if (page.depth()) {
            uint64_t end = i + 1 < page.count() ? page.key(i + 1) : high;
            if (end <= logical || end > high || !claim(v, ownership, page.child(i), 1))
                return v.fail();
            ExtentPage child;
            if (!load_child(v, page, i, child) ||
                !validate(v, child, end, file_blocks, allow_unwritten, ownership))
                return false;
            previous_end = end;
        } else {
            auto row = page.leaf(i);
            if (!row.length || u16(page.row(i) + 6) || row.end() > high ||
                (row.unwritten ? !allow_unwritten : row.end() > file_blocks) ||
                !claim(v, ownership, row.physical, row.length))
                return v.fail();
            ownership.leaves += row.length;
            previous_end = row.end();
        }
    }
    return true;
}

struct Sibling {
    uint32_t physical = 0, logical = 0;
};

bool publish(Volume& v, uint8_t* inode, unsigned preferred, uint32_t block, ExtentPage& page,
             Sibling& sibling) {
    if (page.count() <= page.limit()) {
        if (block)
            return v.write_block(block, page.data, 1);
        memcpy(inode + 40, page.data, inode_block_bytes);
        return true;
    }
    if (!block && page.depth() == max_depth)
        return v.fail(-28);
    uint32_t allocated = v.allocate(false, preferred);
    if (!allocated || !v.add_blocks(inode, 1))
        return false;
    if (!block) {
        // Move the complete old root to one external node and index it inline.
        unsigned depth = page.depth();
        uint32_t logical = page.key(0);
        memset(page.row(page.count()), 0,
               v.block_size - (header_bytes + page.count() * entry_bytes));
        page.limit(entry_limit(v.block_size));
        if (!v.write_block(allocated, page.data, 1))
            return false;
        reset_header(page.data, inode_block_bytes, depth + 1);
        page.count(1);
        page.index(0, logical, allocated);
        memcpy(inode + 40, page.data, inode_block_bytes);
        return true;
    }

    ExtentPage right;
    unsigned middle = page.count() / 2, moved = page.count() - middle;
    reset_header(right.data, v.block_size, page.depth());
    memcpy(right.row(0), page.row(middle), moved * entry_bytes);
    right.count(moved);
    page.count(middle);
    sibling = {allocated, right.key(0)};
    return v.write_block(block, page.data, 1) && v.write_block(allocated, right.data, 1);
}

void insert_initialized(ExtentPage& page, unsigned slot, uint32_t logical, uint32_t block) {
    Extent added{logical, block, 1, false};
    if (slot) {
        auto left = page.leaf(slot - 1);
        if (!left.unwritten && left.end() == logical &&
            uint64_t(left.physical) + left.length == block && left.length < initialized_max) {
            added = left;
            added.length++;
            page.resize_rows(--slot, 1, 0);
        }
    }
    if (slot < page.count()) {
        auto right = page.leaf(slot);
        if (!right.unwritten && added.end() == right.logical &&
            uint64_t(added.physical) + added.length == right.physical &&
            added.length + right.length <= initialized_max) {
            added.length += right.length;
            page.resize_rows(slot, 1, 0);
        }
    }
    page.resize_rows(slot, 0, 1);
    page.leaf(slot, added);
}

bool initialize_block(Volume& v, ExtentPage& page, unsigned i, const Extent& extent,
                      uint32_t logical, uint32_t physical) {
    uint8_t zero[max_block_size]{};
    if (!v.write_block(physical, zero, 0))
        return false;
    unsigned before = logical - extent.logical, after = extent.length - before - 1;
    page.resize_rows(i, 1, 0);
    if (before) {
        page.resize_rows(i, 0, 1);
        page.leaf(i++, {extent.logical, extent.physical, before, true});
    }
    if (after) {
        page.resize_rows(i, 0, 1);
        page.leaf(i, {logical + 1, physical + 1, after, true});
    }
    insert_initialized(page, i, logical, physical);
    return true;
}

bool map_leaf(Volume& v, uint8_t* inode, ExtentPage& page, uint32_t block, uint32_t logical,
              bool create, unsigned preferred, uint32_t& result, Sibling& sibling) {
    unsigned slot = page.upper_bound(logical);
    if (slot) {
        auto extent = page.leaf(slot - 1);
        if (logical < extent.end()) {
            uint64_t physical = uint64_t(extent.physical) + logical - extent.logical;
            if (u16(page.row(slot - 1) + 6) || physical >= v.blocks || !v.data_block(physical))
                return v.fail();
            if (!extent.unwritten) {
                result = physical;
                return true;
            }
            if (!create)
                return true;
            result = physical;
            return initialize_block(v, page, slot - 1, extent, logical, result) &&
                   publish(v, inode, preferred, block, page, sibling);
        }
    }
    if (!create)
        return true;
    result = v.allocate(false, preferred);
    if (!result || !v.add_blocks(inode, 1))
        return false;
    insert_initialized(page, slot, logical, result);
    return publish(v, inode, preferred, block, page, sibling);
}

bool map_node(Volume& v, uint8_t* inode, ExtentPage& page, uint32_t block, uint32_t logical,
              unsigned preferred, uint32_t& result, Sibling& sibling) {
    if (!page.depth())
        return map_leaf(v, inode, page, block, logical, true, preferred, result, sibling);
    unsigned upper = page.upper_bound(logical);
    unsigned slot = upper ? upper - 1 : 0;
    uint32_t physical = page.child(slot);
    ExtentPage child;
    Sibling added;
    if (!load_child(v, page, slot, child) ||
        !map_node(v, inode, child, physical, logical, preferred, result, added))
        return false;
    if (!added.physical && page.key(slot) == child.key(0))
        return true;
    page.index(slot, child.key(0), physical);
    if (added.physical) {
        page.resize_rows(slot + 1, 0, 1);
        page.index(slot + 1, added.logical, added.physical);
    }
    return publish(v, inode, preferred, block, page, sibling);
}

bool prune_page(Volume& v, uint8_t* inode, ExtentPage& page, uint32_t block, uint64_t keep) {
    bool changed = false;
    while (page.count()) {
        unsigned last = page.count() - 1;
        uint32_t logical = page.key(last);
        if (page.depth()) {
            uint32_t physical = page.child(last);
            ExtentPage child;
            if (!load_child(v, page, last, child) || !prune_page(v, inode, child, physical, keep))
                return false;
            if (child.count())
                break;
            if (!v.free_number(physical, false) || !v.add_blocks(inode, -1))
                return false;
        } else {
            auto extent = page.leaf(last);
            if (extent.end() <= keep)
                break;
            unsigned retained = logical < keep ? keep - logical : 0;
            unsigned released = extent.length - retained;
            if (!v.free_blocks(extent.physical + retained, released) ||
                !v.add_blocks(inode, -int(released)))
                return false;
            if (retained) {
                extent.length = retained;
                page.leaf(last, extent);
                changed = true;
                break;
            }
        }
        page.count(last);
        changed = true;
    }
    return !block || !changed || !page.count() || v.write_block(block, page.data, 1);
}

bool unchanged_nodes(Volume& v, const ExtentPage& page) {
    if (!page.depth())
        return true;
    for (unsigned i = 0; i < page.count(); i++) {
        for (auto change = v.changes; change; change = change->next)
            if (change->block == page.child(i))
                return v.fail();
        ExtentPage child;
        if (!load_child(v, page, i, child) || !unchanged_nodes(v, child))
            return false;
    }
    return true;
}
} // namespace

void init_extent_tree(uint8_t* inode) {
    set32(inode + 32, u32(inode + 32) | extent_inode);
    reset_header(inode + 40, inode_block_bytes, 0);
}

bool validate_extent_tree(Volume& v, const uint8_t* inode, bool allow_unwritten,
                          const ExtentOwnership& ownership) {
    ExtentPage page;
    uint64_t file_blocks = (file_size(inode) + v.block_size - 1) / v.block_size;
    return load_root(v, inode, page) &&
           validate(v, page, extent_logical_limit, file_blocks, allow_unwritten, ownership);
}

bool unchanged_extent_nodes(Volume& v, const uint8_t* inode) {
    ExtentPage page;
    return load_root(v, inode, page) && unchanged_nodes(v, page);
}

bool map_extent(Volume& v, uint8_t* inode, uint64_t logical, bool create, uint32_t& result,
                unsigned preferred) {
    if (logical >= extent_logical_limit)
        return v.fail(-27);
    ExtentPage root;
    Sibling unused;
    result = 0;
    if (!load_root(v, inode, root))
        return false;
    if (create)
        return map_node(v, inode, root, 0, logical, preferred, result, unused);
    // Reads only need the current page, even when walking a deep tree.
    while (root.depth()) {
        unsigned upper = root.upper_bound(logical);
        if (!upper)
            return true;
        if (!load_child(v, root, upper - 1, root))
            return false;
    }
    return map_leaf(v, inode, root, 0, logical, false, preferred, result, unused);
}

bool prune_extents(Volume& v, uint8_t* inode, uint64_t keep) {
    ExtentPage root;
    if (!load_root(v, inode, root) || !prune_page(v, inode, root, 0, keep))
        return false;
    while (root.depth() && root.count() == 1) {
        ExtentPage child;
        if (!load_child(v, root, 0, child))
            return false;
        if (child.count() > entry_limit(inode_block_bytes))
            break;
        if (!v.free_number(root.child(0), false) || !v.add_blocks(inode, -1))
            return false;
        memcpy(root.data, child.data, header_bytes + child.count() * entry_bytes);
        root.limit(entry_limit(inode_block_bytes));
    }
    if (root.count())
        memcpy(inode + 40, root.data, inode_block_bytes);
    else
        init_extent_tree(inode);
    return true;
}
} // namespace ax::ext2_detail
