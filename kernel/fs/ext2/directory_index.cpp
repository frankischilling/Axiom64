// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/directory_index.cpp
 * @brief   Directory hash trees for classic ext volumes.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Validates names and index coverage, resolves collision chains, and stages bounded splits.
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
constexpr unsigned root_entries = 32, node_entries = 8;
constexpr uint64_t hash_end = 1ull << 32;

struct IndexPage {
    uint8_t data[max_block_size];
    uint32_t physical;
    unsigned offset, slot;

    unsigned count() const {
        return u16(data + offset + 2);
    }

    unsigned limit() const {
        return u16(data + offset);
    }

    uint32_t key(unsigned i) const {
        return u32(data + offset + i * 8);
    }

    uint32_t child(unsigned i) const {
        return u32(data + offset + i * 8 + 4);
    }

    void reset(unsigned start, unsigned size, unsigned count) {
        offset = start;
        set16(data + offset, (size - offset) / 8);
        set16(data + offset + 2, count);
    }

    unsigned select(uint32_t hash) const {
        unsigned left = 0, right = count();
        while (left + 1 < right) {
            unsigned middle = (left + right) / 2;
            if (key(middle) <= hash)
                left = middle;
            else
                right = middle;
        }
        return left;
    }

    void insert(unsigned after, uint32_t hash, uint32_t logical) {
        auto destination = data + offset + (after + 1) * 8;
        memmove(destination + 8, destination, (count() - after - 1) * 8);
        set32(destination, hash);
        set32(destination + 4, logical);
        set16(data + offset + 2, count() + 1);
    }
};

bool read_at(Volume& v, Inode& inode, uint32_t logical, uint32_t& physical, uint8_t* data) {
    uint64_t offset = uint64_t(logical) * v.block_size;
    return offset < file_size(inode) ? directory_block(v, inode, offset, physical, data) : v.fail();
}

bool read_index(Volume& v, Inode& inode, uint32_t logical, IndexPage& page) {
    page.offset = logical ? node_entries : root_entries;
    if (!read_at(v, inode, logical, page.physical, page.data))
        return false;
    auto bytes = page.data;
    if (logical) {
        if (u32(bytes) || u16(bytes + 4) != v.block_size || u16(bytes + 6))
            return v.fail();
    } else {
        Record dot, parent;
        if (!record(v, bytes, 0, dot) || !record(v, bytes, 12, parent) || dot.length != 12 ||
            parent.length != v.block_size - 12 || !dot.inode || !parent.inode ||
            dot.name_length != 1 || bytes[8] != '.' || parent.name_length != 2 ||
            memcmp(bytes + 20, "..", 2) || u32(bytes + 24) || bytes[29] != 8)
            return v.fail();
        if (bytes[28] > 2 || bytes[30] > 1 || bytes[31])
            return v.fail(-95);
    }
    if (page.limit() != (directory_index_bytes(v) - page.offset) / 8 || !page.count() ||
        page.count() > page.limit())
        return v.fail();
    return true;
}

uint32_t hash_name(Volume& v, const uint8_t* bytes, unsigned length, unsigned version) {
    return directory_hash(bytes, length, version, v.directory_hash_seed, v.unsigned_directory_hash);
}

bool visit(Volume& v, Inode& inode, const IndexPage& page, unsigned levels, unsigned version,
           uint64_t low, uint64_t high, uint8_t* seen, uint32_t& total) {
    uint64_t previous = low;
    for (unsigned i = 0; i < page.count(); i++) {
        uint64_t next = i ? page.key(i) : low;
        if (next < previous || next > high || (i && next == previous && !(next & 1)) ||
            (next == high && !(high & 1)))
            return v.fail();
        previous = next;
    }

    for (unsigned i = 0; i < page.count(); i++) {
        uint64_t first = i ? page.key(i) : low;
        uint64_t last = i + 1 < page.count() ? page.key(i + 1) : high;
        uint32_t logical = page.child(i);
        if (!logical || logical >= file_size(inode) / v.block_size || bit(seen, logical))
            return v.fail();
        setbit(seen, logical, true);
        total++;
        if (levels) {
            IndexPage child;
            if (!read_index(v, inode, logical, child) ||
                !visit(v, inode, child, levels - 1, version, first, last, seen, total))
                return false;
            continue;
        }
        uint32_t physical;
        uint8_t leaf[max_block_size];
        if (!read_at(v, inode, logical, physical, leaf))
            return false;
        uint64_t minimum = first & ~1ull, maximum = (last & ~1ull) + (last & 1);
        unsigned end = directory_leaf_bytes(v);
        for (unsigned offset = 0; offset < end;) {
            Record row;
            if (!record(v, leaf, offset, row, end))
                return false;
            if (row.inode) {
                uint32_t hash = hash_name(v, leaf + offset + 8, row.name_length, version);
                if (hash < minimum || hash >= maximum)
                    return v.fail();
            }
            offset += row.length;
        }
    }
    return true;
}

bool lookup_leaf(Volume& v, const uint8_t* bytes, unsigned end, const char* name, unsigned length,
                 uint32_t& number, unsigned& offset) {
    for (offset = 0; offset < end;) {
        Record row;
        if (!record(v, bytes, offset, row, end))
            return false;
        if (row.inode && row.name_length == length && !memcmp(bytes + offset + 8, name, length)) {
            number = row.inode;
            return true;
        }
        offset += row.length;
    }
    return false;
}

bool continues(uint32_t key, uint32_t hash) {
    return key == (hash | 1u);
}

bool append_block(Volume& v, Inode& inode, unsigned preferred, uint32_t& logical,
                  uint32_t& physical) {
    uint64_t size = file_size(inode);
    if (size > UINT32_MAX - v.block_size)
        return v.fail(-27);
    logical = size / v.block_size;
    if (!v.map_block(inode, logical, true, physical, preferred))
        return false;
    set32(inode + 4, size + v.block_size);
    return true;
}

bool split_index(Volume& v, Inode& inode, unsigned preferred, IndexPage& root, IndexPage& node,
                 bool indirect) {
    if (indirect && root.count() == root.limit())
        return v.fail(-28);
    uint32_t logical;
    IndexPage right{};
    if (!append_block(v, inode, preferred, logical, right.physical))
        return false;
    set16(right.data + 4, v.block_size);
    if (!indirect) {
        unsigned count = root.count();
        memcpy(right.data + node_entries, root.data + root_entries, count * 8);
        right.reset(node_entries, directory_index_bytes(v), count);
        right.slot = root.slot;
        set16(root.data + root_entries + 2, 1);
        set32(root.data + root_entries + 4, logical);
        root.data[30] = 1;
        node = right;
        return save_directory_index(v, inode, root.physical, root.data, root_entries);
    }
    unsigned middle = node.count() / 2, moved = node.count() - middle;
    uint32_t boundary = node.key(middle);
    memcpy(right.data + node_entries, node.data + node_entries + middle * 8, moved * 8);
    right.reset(node_entries, directory_index_bytes(v), moved);
    set16(node.data + node_entries + 2, middle);
    root.insert(root.slot, boundary, logical);
    if (!save_directory_index(v, inode, root.physical, root.data, root_entries))
        return false;
    if (node.slot >= middle) {
        if (!save_directory_index(v, inode, node.physical, node.data, node_entries))
            return false;
        right.slot = node.slot - middle;
        node = right;
    } else if (!save_directory_index(v, inode, right.physical, right.data, node_entries)) {
        return false;
    }
    return true;
}

struct LeafRow {
    uint32_t hash;
    uint16_t offset, size;
};

bool split_leaf(Volume& v, Inode& inode, unsigned preferred, IndexPage& page, uint32_t physical,
                const uint8_t* leaf, const char* name, uint32_t number, uint32_t mode,
                unsigned version, uint32_t hash) {
    constexpr unsigned new_row = UINT16_MAX;
    LeafRow rows[max_block_size / 12 + 1];
    unsigned count = 0, total = 0;
    unsigned usable = directory_leaf_bytes(v);
    for (unsigned offset = 0; offset < usable;) {
        Record row;
        if (!record(v, leaf, offset, row, usable))
            return false;
        if (row.inode) {
            unsigned size = dir_record_size(row.name_length);
            rows[count++] = {hash_name(v, leaf + offset + 8, row.name_length, version),
                             uint16_t(offset), uint16_t(size)};
            total += size;
        }
        offset += row.length;
    }
    unsigned extra = dir_record_size(strlen(name));
    rows[count++] = {hash, new_row, uint16_t(extra)};
    total += extra;
    for (unsigned i = 1; i < count; i++) {
        LeafRow row = rows[i];
        unsigned j = i;
        while (j && rows[j - 1].hash > row.hash) {
            rows[j] = rows[j - 1];
            j--;
        }
        rows[j] = row;
    }

    unsigned middle = 0, bytes = 0;
    while (middle + 1 < count && bytes < total / 2)
        bytes += rows[middle++].size;
    if (!middle || bytes > usable || total - bytes > usable)
        return v.fail();
    uint32_t logical, new_physical;
    if (!append_block(v, inode, preferred, logical, new_physical))
        return false;
    uint8_t packed[max_block_size];
    unsigned starts[] = {0, middle};
    for (unsigned start : starts) {
        unsigned end = start ? count : middle, offset = 0;
        for (unsigned i = start; i < end; i++) {
            const auto& row = rows[i];
            unsigned length = i + 1 == end ? usable - offset : row.size;
            if (row.offset == new_row) {
                put_record(v, packed, offset, length, name, number, mode);
            } else {
                memcpy(packed + offset, leaf + row.offset, row.size);
                memset(packed + offset + row.size, 0, length - row.size);
                set16(packed + offset + 4, length);
            }
            offset += length;
        }
        if (!save_directory_leaf(v, inode, start ? new_physical : physical, packed))
            return false;
    }
    uint32_t separator = rows[middle].hash | uint32_t(rows[middle - 1].hash == rows[middle].hash);
    page.insert(page.slot, separator, logical);
    return save_directory_index(v, inode, page.physical, page.data, page.offset);
}
} // namespace

bool insert_directory_record(Volume& v, uint8_t* data, const char* name, uint32_t number,
                             uint32_t mode) {
    unsigned need = dir_record_size(strlen(name));
    unsigned end = directory_leaf_bytes(v);
    for (unsigned offset = 0; offset < end;) {
        Record row;
        if (!record(v, data, offset, row, end))
            return false;
        unsigned used = row.inode ? dir_record_size(row.name_length) : 0;
        if (row.length - used >= need) {
            if (used)
                set16(data + offset + 4, used);
            put_record(v, data, offset + used, row.length - used, name, number, mode);
            return true;
        }
        offset += row.length;
    }
    return false;
}

bool start_directory_index(Volume& v, Inode& inode, unsigned preferred, uint32_t physical,
                           uint8_t* data) {
    Record dot, parent;
    unsigned end = directory_leaf_bytes(v);
    if (!record(v, data, 0, dot, end) || dot.length != 12 || !dot.inode || dot.name_length != 1 ||
        data[8] != '.')
        return false;
    if (!record(v, data, 12, parent, end) || !parent.inode || parent.name_length != 2 ||
        memcmp(data + 20, "..", 2) || 12 + parent.length == end)
        return false;

    unsigned first = 12 + parent.length, last = first;
    for (unsigned offset = first; offset < end;) {
        Record row;
        if (!record(v, data, offset, row, end))
            return false;
        last = offset;
        offset += row.length;
    }
    uint32_t logical, leaf;
    if (!append_block(v, inode, preferred, logical, leaf))
        return false;
    uint8_t names[max_block_size];
    memcpy(names, data + first, end - first);
    memset(names + end - first, 0, first);
    set16(names + last - first + 4, u16(data + last + 4) + first);
    if (!save_directory_leaf(v, inode, leaf, names))
        return false;

    set16(data + 16, v.block_size - 12);
    memset(data + 24, 0, v.block_size - 24);
    data[28] = v.default_directory_hash_version;
    data[29] = 8;
    set16(data + root_entries, (directory_index_bytes(v) - root_entries) / 8);
    set16(data + root_entries + 2, 1);
    set32(data + root_entries + 4, logical);
    set32(inode + 32, u32(inode + 32) | indexed_directory);
    return save_directory_index(v, inode, physical, data, root_entries);
}

bool validate_directory_index(Volume& v, Inode& inode) {
    IndexPage root;
    if (!read_index(v, inode, 0, root))
        return false;
    uint32_t blocks = file_size(inode) / v.block_size, seen_count = 1;
    size_t bytes = (size_t(blocks) + 7) / 8;
    auto seen = static_cast<uint8_t*>(alloc(bytes));
    if (!seen)
        return v.fail(-12);
    memset(seen, 0, bytes);
    setbit(seen, 0, true);
    bool ok = visit(v, inode, root, root.data[30], root.data[28], 0, hash_end, seen, seen_count);
    release(seen);
    return ok && seen_count == blocks ? true : v.fail();
}

bool find_indexed_name(Volume& v, Inode& inode, const char* name, uint32_t& number,
                       uint64_t* position) {
    IndexPage root, child;
    if (!read_index(v, inode, 0, root))
        return false;
    unsigned length = strlen(name), offset;
    if ((length == 1 && name[0] == '.') || (length == 2 && !memcmp(name, "..", 2))) {
        if (!lookup_leaf(v, root.data, v.block_size, name, length, number, offset))
            return v.fail();
        if (position)
            *position = offset;
        return true;
    }
    bool indirect = root.data[30];
    uint32_t hash = hash_name(v, reinterpret_cast<const uint8_t*>(name), length, root.data[28]);
    root.slot = root.select(hash);
    IndexPage* page = &root;
    if (indirect) {
        if (!read_index(v, inode, root.child(root.slot), child))
            return false;
        child.slot = child.select(hash);
        page = &child;
    }
    for (;;) {
        uint8_t leaf[max_block_size];
        uint32_t logical = page->child(page->slot), physical;
        if (!read_at(v, inode, logical, physical, leaf))
            return false;
        if (lookup_leaf(v, leaf, directory_leaf_bytes(v), name, length, number, offset)) {
            if (position)
                *position = uint64_t(logical) * v.block_size + offset;
            return true;
        }
        if (v.error)
            return false;
        if (page->slot + 1 < page->count()) {
            if (!continues(page->key(++page->slot), hash))
                break;
        } else if (indirect && root.slot + 1 < root.count() &&
                   continues(root.key(++root.slot), hash)) {
            if (!read_index(v, inode, root.child(root.slot), child))
                return false;
            child.slot = 0;
        } else {
            break;
        }
    }
    return v.fail(-2);
}

bool insert_indexed_name(Volume& v, Inode& inode, unsigned preferred, const char* name,
                         uint32_t number, uint32_t mode) {
    IndexPage root, node;
    if (!read_index(v, inode, 0, root))
        return false;
    unsigned version = root.data[28];
    uint32_t hash = hash_name(v, reinterpret_cast<const uint8_t*>(name), strlen(name), version);
    root.slot = root.select(hash);
    bool indirect = root.data[30];
    IndexPage* page = &root;
    if (indirect) {
        if (!read_index(v, inode, root.child(root.slot), node))
            return false;
        node.slot = node.select(hash);
        page = &node;
    }
    uint8_t leaf[max_block_size];
    uint32_t physical;
    if (!read_at(v, inode, page->child(page->slot), physical, leaf))
        return false;
    if (insert_directory_record(v, leaf, name, number, mode))
        return save_directory_leaf(v, inode, physical, leaf);
    if (v.error)
        return false;
    if (page->count() == page->limit()) {
        if (!split_index(v, inode, preferred, root, node, indirect))
            return false;
        page = &node;
    }
    return split_leaf(v, inode, preferred, *page, physical, leaf, name, number, mode, version,
                      hash);
}
} // namespace ax::ext2_detail
