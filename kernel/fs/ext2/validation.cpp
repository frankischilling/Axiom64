// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/validation.cpp
 * @brief   Validate ext2 volumes at mount.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks allocation maps, inodes and directories before any mount recovery commits.
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
constexpr uint32_t unknown_directory_links = UINT32_MAX;

// Validate allocation, ownership and directories before staging any mount writes.
// Checked writable dirty mounts may reconcile counters and reclaim completely
// validated inodes carrying the on-disk deletion marker. A named file, symlink
// or empty directory can keep its checked namespace and bounded parent links.
// Dirty journaled mounts may reclaim unreferenced retired inodes, with strict
// counters and no restoration of names or parent-link contributions.
struct Validation {
    Volume& v;
    Recovery recovery;
    NativeOrphans orphans;
    bool reconcile_counts, native_summary;
    uint16_t *group_free_blocks = nullptr, *group_free_inodes = nullptr;
    uint64_t free_block_total = 0, free_inode_total = 0;
    uint8_t *block_bits = nullptr, *inode_bits = nullptr, *owners = nullptr;
    uint8_t* deleted_bits = nullptr;
    uint8_t* named_directory_parents = nullptr;
    uint16_t* modes = nullptr;
    uint32_t* links = nullptr;
    uint16_t* xattr_references = nullptr;
    uint32_t *references = nullptr, *parents = nullptr, *dotdots = nullptr;
    uint8_t inode_table[max_block_size]{};
    uint32_t cached_table = UINT32_MAX;

    explicit Validation(Volume& value, Recovery mode, bool native = false)
        : v(value), recovery(mode), orphans(value), reconcile_counts(mode == Recovery::checked),
          native_summary(native) {
    }

    bool recovering() const {
        return recovery != Recovery::none;
    }

    ~Validation() {
        release(group_free_blocks);
        release(group_free_inodes);
        release(block_bits);
        release(inode_bits);
        release(owners);
        release(deleted_bits);
        release(named_directory_parents);
        release(modes);
        release(links);
        release(xattr_references);
        release(references);
        release(parents);
        release(dotdots);
    }

    bool allocate() {
        size_t block_bytes = (uint64_t(v.blocks) + 7) / 8;
        size_t inode_count = uint64_t(v.inodes) + 1, inode_bytes = (inode_count + 7) / 8;
        block_bits = (uint8_t*)alloc(block_bytes);
        inode_bits = (uint8_t*)alloc(inode_bytes);
        owners = (uint8_t*)alloc(block_bytes);
        modes = (uint16_t*)alloc(inode_count * sizeof(uint16_t));
        links = (uint32_t*)alloc(inode_count * sizeof(*links));
        xattr_references = (uint16_t*)alloc(uint64_t(v.blocks) * sizeof(uint16_t));
        references = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        parents = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        dotdots = (uint32_t*)alloc(inode_count * sizeof(uint32_t));
        if (recovering()) {
            deleted_bits = (uint8_t*)alloc(inode_bytes);
            named_directory_parents = (uint8_t*)alloc(inode_bytes);
        }
        if (reconcile_counts) {
            group_free_blocks = (uint16_t*)alloc(v.group_count * sizeof(uint16_t));
            group_free_inodes = (uint16_t*)alloc(v.group_count * sizeof(uint16_t));
        }
        if (!block_bits || !inode_bits || !owners || !modes || !links || !xattr_references ||
            !references || !parents || !dotdots ||
            (recovering() && (!deleted_bits || !named_directory_parents)) ||
            (reconcile_counts && (!group_free_blocks || !group_free_inodes)))
            return v.fail(-12);
        memset(block_bits, 0, block_bytes);
        memset(owners, 0, block_bytes);
        memset(inode_bits, 0, inode_bytes);
        if (deleted_bits)
            memset(deleted_bits, 0, inode_bytes);
        if (named_directory_parents)
            memset(named_directory_parents, 0, inode_bytes);
        memset(modes, 0, inode_count * sizeof(uint16_t));
        memset(links, 0, inode_count * sizeof(*links));
        memset(xattr_references, 0, uint64_t(v.blocks) * sizeof(uint16_t));
        memset(references, 0, inode_count * sizeof(uint32_t));
        memset(parents, 0, inode_count * sizeof(uint32_t));
        memset(dotdots, 0, inode_count * sizeof(uint32_t));
        parents[2] = 2;
        return true;
    }

    bool deleted(uint32_t number) const {
        return deleted_bits && bit(deleted_bits, number);
    }

    bool bitmaps(const uint8_t* header) {
        uint64_t free_blocks = 0, free_inodes = 0;
        uint8_t data[max_block_size], desc[max_descriptor_bytes];
        for (unsigned group = 0; group < v.group_count; group++) {
            auto& g = v.groups[group];
            if (!v.descriptor(group, desc) || !v.read_bitmap(group, false, data, desc))
                return false;
            uint32_t free = 0;
            for (unsigned i = 0; i < v.block_size * 8; i++) {
                if (i >= g.blocks) {
                    if (!bit(data, i))
                        return v.fail();
                    continue;
                }
                bool used = bit(data, i);
                setbit(block_bits, g.first + i, used);
                if (v.metadata(g.first + i) && !used)
                    return v.fail();
                if (!used)
                    free++;
            }
            if (!reconcile_counts && free != u16(desc + 12))
                return v.fail();
            if (reconcile_counts)
                group_free_blocks[group] = free;
            free_blocks += free;
            if (!v.read_bitmap(group, true, data, desc))
                return false;
            free = 0;
            for (unsigned i = 0; i < v.block_size * 8; i++) {
                if (i >= g.inodes) {
                    if (!bit(data, i))
                        return v.fail();
                    continue;
                }
                uint32_t number = group * v.inodes_per_group + i + 1;
                bool used = bit(data, i);
                setbit(inode_bits, number, used);
                if (v.checksums() && used && i >= v.inodes_per_group - u16(desc + 28))
                    return v.fail();
                if (number < v.first_inode && !used)
                    return v.fail();
                if (!used)
                    free++;
            }
            if (!reconcile_counts && free != u16(desc + 14))
                return v.fail();
            if (reconcile_counts)
                group_free_inodes[group] = free;
            free_inodes += free;
        }
        free_block_total = free_blocks;
        free_inode_total = free_inodes;
        return reconcile_counts || native_summary ||
                       (free_blocks == u32(header + 12) && free_inodes == u32(header + 16))
                   ? true
                   : v.fail();
    }

    bool reconcile(uint8_t* header) {
        if (!reconcile_counts)
            return true;
        // The complete structural scan has succeeded. All counts are derived
        // from the validated bitmaps; layout bounds and directory counts stay strict.
        uint8_t desc[max_descriptor_bytes];
        for (unsigned group = 0; group < v.group_count; group++) {
            if (!v.descriptor(group, desc))
                return false;
            if (u16(desc + 12) == group_free_blocks[group] &&
                u16(desc + 14) == group_free_inodes[group])
                continue;
            set16(desc + 12, group_free_blocks[group]);
            set16(desc + 14, group_free_inodes[group]);
            if (!v.save_descriptor(group, desc))
                return false;
        }
        // The mount's final staged superblock write must use these same totals.
        set32(header + 12, free_block_total);
        set32(header + 16, free_inode_total);
        return true;
    }

    bool inode(uint32_t number, Inode& data) {
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % v.inodes_per_group) * v.inode_size;
        uint32_t block = v.groups[index / v.inodes_per_group].inode_table + offset / v.block_size;
        if (block != cached_table) {
            if (!v.read_block(block, inode_table))
                return false;
            cached_table = block;
        }
        return v.decode_inode(number, inode_table + offset % v.block_size, data);
    }

    bool reserved_descriptor(uint32_t block) {
        auto group = (block - v.first) / v.blocks_per_group;
        uint32_t offset = block - v.groups[group].first;
        return v.has_super(group) && offset >= 1 + v.gdt_blocks &&
               offset < 1 + v.gdt_blocks + v.reserved_gdt;
    }

    bool tree(uint32_t block, unsigned depth, bool resize, uint64_t base, uint64_t limit,
              uint64_t& count, uint64_t& leaves) {
        if (!block)
            return true;
        if (!resize && base >= limit)
            return v.fail();
        if (block < v.first || block >= v.blocks || !bit(block_bits, block) || bit(owners, block))
            return v.fail();
        if (v.metadata(block) && !(resize && reserved_descriptor(block)))
            return v.fail();
        setbit(owners, block, true);
        count++;
        if (!depth) {
            leaves++;
            return true;
        }
        uint8_t data[max_block_size];
        if (!v.read_block(block, data))
            return false;
        uint64_t span = 1;
        for (unsigned i = 1; i < depth; i++)
            span *= v.block_size / 4;
        for (unsigned i = 0; i < v.block_size / 4; i++)
            if (!tree(u32(data + i * 4), depth - 1, resize, base + i * span, limit, count, leaves))
                return false;
        return true;
    }

    bool inode_maps() {
        Inode data;
        uint8_t desc[max_descriptor_bytes];
        for (unsigned group = 0; group < v.group_count; group++) {
            unsigned dirs = 0;
            auto& g = v.groups[group];
            for (unsigned i = 0; i < g.inodes; i++) {
                uint32_t number = group * v.inodes_per_group + i + 1;
                if (!bit(inode_bits, number))
                    continue;
                if (!inode(number, data))
                    return false;
                uint32_t mode = u16(data), type = mode & 0170000;
                bool reserved = number < v.first_inode && number != 2;
                bool resize = number == 7 && (v.compatible & 16);
                bool journal = number == 8 && v.journal;
                bool orphan_file = number == v.orphan_inode;
                bool orphan = orphans.contains(number);
                if (reserved && !resize && !journal) {
                    if (mode || file_size(data) || v.inode_sectors(data) || u32(data + 104))
                        return v.fail(-95);
                    for (unsigned slot = 0; slot < 15; slot++)
                        if (u32(data + 40 + slot * 4))
                            return v.fail(-95);
                    continue;
                }
                if (type != regular_file && type != directory && type != symlink && type != fifo &&
                    type != 0140000)
                    return v.fail(-95);
                uint32_t accepted_flags = v.block_count_flag();
                if (type == directory && (v.compatible & directory_index_feature))
                    accepted_flags |= indexed_directory;
                if (v.extent_enabled && !resize &&
                    (type == regular_file || type == directory || type == symlink))
                    accepted_flags |= extent_inode;
                // Other inode flags and fragments need separate policy/layout support.
                if ((u32(data + 32) & ~accepted_flags) || u32(data + 112) ||
                    (!(v.readonly_features & huge_file_feature) && u16(data + 116)) ||
                    u16(data + 118) || (type != regular_file && u32(data + 108)))
                    return v.fail(-95);
                uint64_t length = file_size(data), count = 0, leaves = 0;
                uint32_t attribute = u32(data + 104);
                if (attribute) {
                    if (resize || !(v.compatible & 8) || attribute < v.first ||
                        attribute >= v.blocks || v.metadata(attribute) ||
                        !bit(block_bits, attribute) ||
                        (bit(owners, attribute) && !xattr_references[attribute]))
                        return v.fail();
                    uint8_t block[max_block_size];
                    uint32_t actual;
                    if (!v.read_xattr_block(attribute, block))
                        return false;
                    if (!ext2_xattr_valid(block, v.block_size, actual))
                        return v.fail();
                    if (!ext2_xattr_supported(block, v.block_size))
                        return v.fail(-95);
                    if (++xattr_references[attribute] > actual)
                        return v.fail();
                    setbit(owners, attribute, true);
                    count++;
                }
                if (length > v.capacity(data) || (type == regular_file && length > INT32_MAX &&
                                                  (v.revision == 0 || !(v.readonly_features & 2))))
                    return v.fail();
                if (type == directory &&
                    ((!length && !(orphan && !u16(data + 26))) || length % v.block_size ||
                     length > uint64_t(v.blocks) * v.block_size))
                    return v.fail();
                if (type == symlink && ((!length && !(orphan && !u16(data + 26))) || length > 4095))
                    return v.fail();
                if ((type == fifo || type == 0140000) &&
                    (length || v.inode_sectors(data) != count * (v.block_size / sector_size)))
                    return v.fail();
                if (resize) {
                    if (type != regular_file || !u32(data + 92))
                        return v.fail();
                    for (unsigned slot = 0; slot < 15; slot++)
                        if (slot != 13 && u32(data + 40 + slot * 4))
                            return v.fail();
                }
                bool fast_link = v.fast_symlink(data);
                if (fast_link && length > inode_block_bytes)
                    return v.fail();
                if (has_extents(data)) {
                    if (!validate_extent_tree(v, data,
                                              type == regular_file && !journal && !orphan_file,
                                              {block_bits, owners, count, leaves}, orphan))
                        return false;
                } else if (!fast_link) {
                    uint64_t base = 0, limit = orphan ? v.capacity(data) / v.block_size
                                                      : (length + v.block_size - 1) / v.block_size;
                    for (unsigned slot = 0; slot < 15; slot++) {
                        unsigned depth = slot < 12 ? 0 : slot - 11;
                        if (!tree(u32(data + 40 + slot * 4), depth, resize, base, limit, count,
                                  leaves))
                            return false;
                        uint64_t span = 1;
                        for (unsigned i = 0; i < depth; i++)
                            span *= v.block_size / 4;
                        base += span;
                    }
                }
                if (count * (v.block_size / sector_size) != v.inode_sectors(data))
                    return v.fail();
                if (type == directory && !orphan && leaves != length / v.block_size)
                    return v.fail();
                if (type == symlink && has_extents(data) && !orphan &&
                    leaves != (length + v.block_size - 1) / v.block_size)
                    return v.fail();
                if (!reserved && !orphan_file) {
                    bool removed = !u16(data + 26) && (orphan || u32(data + 20));
                    if (removed && recovering() && number >= v.first_inode)
                        setbit(deleted_bits, number, true);
                    else if (!u16(data + 26) || (!orphan && u32(data + 20)))
                        return v.fail();
                    modes[number] = mode;
                    links[number] = u16(data + 26);
                    if (links[number] == 1 && v.directory_can_omit_links(data))
                        links[number] = unknown_directory_links;
                    if (type == directory)
                        dirs++;
                }
            }
            if (!v.descriptor(group, desc))
                return false;
            if (dirs != u16(desc + 16))
                return v.fail();
        }
        for (uint32_t block = v.first; block < v.blocks; block++) {
            if (xattr_references[block]) {
                uint8_t data[max_block_size];
                if (!v.read_block(block, data))
                    return false;
                if (xattr_references[block] != u32(data + 4))
                    return v.fail();
            }
            if (bit(block_bits, block) && !v.metadata(block) && !bit(owners, block))
                return v.fail();
        }
        return (modes[2] & 0170000) == directory ? true : v.fail();
    }

    struct Name {
        uint64_t hash, position;
    };

    bool check_directory(uint32_t number) {
        bool detached = deleted(number);
        Inode disk_inode;
        uint8_t data[max_block_size];
        if (!inode(number, disk_inode))
            return false;
        // Linux clears i_size when removing a directory, before freeing its blocks.
        if (detached && orphans.contains(number) && !file_size(disk_inode))
            return true;
        if ((u32(disk_inode + 32) & indexed_directory) && !validate_directory_index(v, disk_inode))
            return false;
        size_t slots = 8;
        while (slots < file_size(disk_inode) / 12 * 2)
            slots *= 2;
        auto names = (Name*)alloc(slots * sizeof(Name));
        if (!names)
            return v.fail(-12);
        memset(names, 0, slots * sizeof(Name));
        bool success = true, dot = false, dotdot = false;
        for (uint64_t base = 0; success && base < file_size(disk_inode); base += v.block_size) {
            uint32_t block;
            success = directory_block(v, disk_inode, base, block, data);
            if (!success)
                break;
            unsigned end = directory_record_end(v, disk_inode, base, data);
            for (unsigned offset = 0; success && offset < end;) {
                Record r;
                if (!record(v, data, offset, r, end)) {
                    success = false;
                    break;
                }
                if (r.inode) {
                    if (!bit(inode_bits, r.inode) || !modes[r.inode] ||
                        (r.type && r.type != file_type(modes[r.inode])) ||
                        (!detached && deleted(r.inode) &&
                         (modes[r.inode] & 0170000) != regular_file &&
                         (modes[r.inode] & 0170000) != symlink &&
                         (modes[r.inode] & 0170000) != ax::directory)) {
                        success = v.fail();
                        break;
                    }
                    bool self = r.name_length == 1 && data[offset + 8] == '.';
                    bool up = r.name_length == 2 && !memcmp(data + offset + 8, "..", 2);
                    if (detached && !self && !up) {
                        success = v.fail();
                        break;
                    }
                    if (self) {
                        if (dot || r.inode != number) {
                            success = v.fail();
                            break;
                        }
                        dot = true;
                    } else if (up) {
                        if (dotdot || (modes[r.inode] & 0170000) != ax::directory) {
                            success = v.fail();
                            break;
                        }
                        dotdot = true;
                        dotdots[number] = r.inode;
                    } else if ((modes[r.inode] & 0170000) == ax::directory) {
                        if (parents[r.inode]) {
                            success = v.fail();
                            break;
                        }
                        parents[r.inode] = number;
                    }
                    if (!detached && (references[r.inode] == UINT32_MAX ||
                                      (++references[r.inode] > UINT16_MAX &&
                                       links[r.inode] != unknown_directory_links))) {
                        success = v.fail();
                        break;
                    }
                    uint64_t hash = 14695981039346656037ull;
                    for (unsigned i = 0; i < r.name_length; i++)
                        hash = (hash ^ data[offset + 8 + i]) * 1099511628211ull;
                    size_t slot = hash & (slots - 1);
                    while (names[slot].position) {
                        if (names[slot].hash == hash) {
                            uint8_t previous[max_block_size];
                            uint32_t old_block;
                            uint64_t position = names[slot].position - 1;
                            if (!directory_block(v, disk_inode, position, old_block, previous)) {
                                success = false;
                                break;
                            }
                            Record old;
                            if (!record(v, previous, position % v.block_size, old,
                                        directory_record_end(v, disk_inode, position, previous))) {
                                success = false;
                                break;
                            }
                            if (old.name_length == r.name_length &&
                                !memcmp(previous + position % v.block_size + 8, data + offset + 8,
                                        r.name_length)) {
                                success = v.fail();
                                break;
                            }
                        }
                        slot = (slot + 1) & (slots - 1);
                    }
                    if (!success)
                        break;
                    names[slot] = {hash, base + offset + 1};
                }
                offset += r.length;
            }
        }
        release(names);
        return success && dot && dotdot ? true : v.fail();
    }

    bool directories() {
        for (uint32_t number = 2; number <= v.inodes; number++)
            if ((modes[number] & 0170000) == ax::directory && !check_directory(number))
                return false;
        for (uint32_t number = v.first_inode; number <= v.inodes; number++) {
            if (!deleted(number))
                continue;
            if ((!reconcile_counts || orphans.contains(number)) && references[number])
                return v.fail();
            if ((modes[number] & 0170000) != ax::directory || !references[number])
                continue;
            uint32_t parent = parents[number];
            Inode data;
            // An empty directory can keep one existing parent name. Its dotdot
            // must identify that live parent; only that known link may be missing.
            if (references[number] != 1 || !parent || dotdots[number] != parent ||
                deleted(parent) || (modes[parent] & 0170000) != ax::directory ||
                bit(named_directory_parents, parent) || references[parent] == UINT32_MAX ||
                (references[parent] >= UINT16_MAX && links[parent] != unknown_directory_links) ||
                !inode(number, data) || u32(data + 20) != u32(data + 12))
                return v.fail();
            setbit(named_directory_parents, parent, true);
            references[number]++;
            references[parent]++;
        }
        for (uint32_t number = 2; number <= v.inodes; number++) {
            if (!modes[number])
                continue;
            if (references[number] != links[number] && links[number] != unknown_directory_links) {
                Inode data;
                unsigned type = modes[number] & 0170000;
                bool parent_link = named_directory_parents &&
                                   bit(named_directory_parents, number) && !deleted(number) &&
                                   references[number] == uint32_t(links[number]) + 1;
                bool retained =
                    deleted(number) &&
                    (((type == regular_file || type == symlink) && references[number] == 1) ||
                     (type == ax::directory && references[number] == 2 && parents[number])) &&
                    inode(number, data) && u32(data + 20) == u32(data + 12);
                if (!parent_link && !retained)
                    return v.fail();
            }
            if ((modes[number] & 0170000) != ax::directory)
                continue;
            if (deleted(number)) {
                // A removed directory must be empty and its retained ancestry
                // must terminate at a live, reachable directory without cycles.
                uint32_t parent = number;
                unsigned depth = 0;
                while (deleted(parent)) {
                    if (!dotdots[parent] && orphans.contains(parent))
                        break;
                    if (++depth > v.inodes || !dotdots[parent] ||
                        (modes[dotdots[parent]] & 0170000) != ax::directory)
                        return v.fail();
                    parent = dotdots[parent];
                }
                continue;
            }
            if (!parents[number] || dotdots[number] != parents[number])
                return v.fail();
            uint32_t parent = number;
            unsigned depth = 0;
            while (parent != 2) {
                if (++depth > v.inodes || !parents[parent])
                    return v.fail();
                parent = parents[parent];
            }
        }
        return true;
    }

    bool scan(const uint8_t* header) {
        return allocate() && bitmaps(header) && orphans.collect(header, inode_bits) &&
               inode_maps() && directories();
    }

    bool reclaim_deleted(uint8_t* header) {
        if (!deleted_bits)
            return true;
        bool any = false;
        for (uint32_t number = v.first_inode; number <= v.inodes; number++)
            any |= deleted(number);
        if (!any)
            return true;
        // Every allocation and directory reference has already been checked.
        // Reconcile staged counters before the ordinary deletion path adjusts
        // them, including shared external-attribute ownership.
        if (!v.save_super(header))
            return false;
        Inode data;
        for (uint32_t number = 2; number <= v.inodes; number++) {
            if (!bit(named_directory_parents, number) || links[number] == unknown_directory_links)
                continue;
            if (!v.load_inode(number, data))
                return false;
            set16(data + 26, references[number]);
            if (!v.save_inode(number, data))
                return false;
        }
        for (uint32_t number = v.first_inode; number <= v.inodes; number++) {
            if (!deleted(number))
                continue;
            if (!v.load_inode(number, data))
                return false;
            if (references[number]) {
                set16(data + 26, references[number]);
                set32(data + 20, 0);
                if (!v.save_inode(number, data))
                    return false;
            } else if (!v.delete_inode(number, data))
                return false;
        }
        if (!v.super(header))
            return false;
        // Validate the complete proposed disk image before mount can commit it.
        Validation result{v, Recovery::none};
        return result.scan(header);
    }
};
} // namespace

bool validate_volume(Volume& v, uint8_t* header, Recovery recovery) {
    if (native_orphans_pending(header)) {
        Validation native{v, Recovery::journal, true};
        if (!native.scan(header) ||
            !native.orphans.recover(header, native.free_block_total, native.free_inode_total))
            return false;
        recovery = Recovery::journal;
    }
    Validation check{v, recovery};
    if (!(check.scan(header) && check.reconcile(header) && check.reclaim_deleted(header)))
        return false;
    if (v.journal) {
        int error = journal_checkpoint(v.journal);
        if (error)
            return v.fail(error);
        if (v.mount->readonly && ((u32(header + 96) & 4) || v.changes)) {
            if (!v.state(true) || !v.flush() || !v.super(header))
                return false;
        }
    }
    return true;
}
} // namespace ax::ext2_detail
