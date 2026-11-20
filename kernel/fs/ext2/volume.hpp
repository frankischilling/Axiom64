// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/volume.hpp
 * @brief   Private ext2 volume and disk record helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Shares the volume state, block mapping and directory records with mount validation.
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

#include "fs/ext2/ext2.hpp"
#include "fs/ext2/xattr.hpp"
#include "fs/ext2/journal.hpp"
#include "process/task.hpp"
#include "drivers/block/block.hpp"
#include "drivers/platform/devices.hpp"
#include "entries.hpp"

namespace ax::ext2_detail {
constexpr size_t max_block_size = 4096, inode_bytes = 128;
constexpr unsigned max_changes = 4096, cached_blocks = 128;

inline uint16_t u16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}

inline uint32_t u32(const uint8_t* p) {
    return uint32_t(u16(p)) | (uint32_t(u16(p + 2)) << 16);
}

inline void set16(uint8_t* p, uint16_t v) {
    p[0] = v;
    p[1] = v >> 8;
}

inline void set32(uint8_t* p, uint32_t v) {
    set16(p, v);
    set16(p + 2, v >> 16);
}

inline bool bit(const uint8_t* p, uint32_t n) {
    return p[n / 8] & (1u << (n % 8));
}

inline void setbit(uint8_t* p, uint32_t n, bool value) {
    if (value)
        p[n / 8] |= 1u << (n % 8);
    else
        p[n / 8] &= ~(1u << (n % 8));
}

inline uint64_t file_size(const uint8_t* inode) {
    return u32(inode + 4) |
           ((u16(inode) & 0170000) == regular_file ? uint64_t(u32(inode + 108)) << 32 : 0);
}

inline bool fast_symlink(const uint8_t* inode, unsigned block_size) {
    return (u16(inode) & 0170000) == symlink &&
           u32(inode + 28) == (u32(inode + 104) ? block_size / sector_size : 0);
}

inline uint8_t file_type(uint32_t mode) {
    switch (mode & 0170000) {
    case regular_file:
        return 1;
    case directory:
        return 2;
    case character:
        return 3;
    case block_device:
        return 4;
    case fifo:
        return 5;
    case 0140000:
        return 6;
    case symlink:
        return 7;
    default:
        return 0;
    }
}

struct Group {
    uint32_t first, blocks, inodes, block_bitmap, inode_bitmap, inode_table;
};

struct Change {
    Change* next;
    uint32_t block;
    unsigned rank;
    uint8_t data[max_block_size];
};

struct CachedBlock {
    uint32_t block;
    bool valid;
    uint8_t data[max_block_size];
};

struct Volume {
    Mount* mount;
    unsigned device, block_size, inode_size, group_count, change_count;
    uint32_t blocks, inodes, first, blocks_per_group, inodes_per_group, first_inode;
    uint32_t gdt, gdt_blocks, reserved_gdt, revision, compatible, readonly_features;
    bool typed_entries, claimed, writable_safe;
    Group* groups;
    Change* changes;
    EntryCache entries;
    CachedBlock* cache;
    Journal* journal;
    uint32_t* journal_map;
    uint32_t journal_blocks;
    uint32_t touched[64];
    unsigned touched_count;
    int error;

    bool fail(int code = -117) {
        if (!error)
            error = code;
        return false;
    }

    bool has_super(unsigned group) const {
        if (!(readonly_features & 1) || group < 2)
            return true;
        constexpr unsigned bases[] = {3, 5, 7};
        for (unsigned base : bases) {
            unsigned n = group;
            while (n % base == 0)
                n /= base;
            if (n == 1)
                return true;
        }
        return false;
    }

    bool metadata(uint32_t block) const {
        if (block < first || block >= blocks)
            return true;
        auto group = unsigned((block - first) / blocks_per_group);
        auto& g = groups[group];
        uint64_t table_blocks =
            (uint64_t(inodes_per_group) * inode_size + block_size - 1) / block_size;
        return block == g.block_bitmap || block == g.inode_bitmap ||
               (block >= g.inode_table && block - g.inode_table < table_blocks) ||
               (has_super(group) && block - g.first < 1 + gdt_blocks + reserved_gdt);
    }

    bool read_block(uint32_t block, void* data) {
        if (block >= blocks)
            return fail();
        for (auto change = changes; change; change = change->next)
            if (change->block == block) {
                memcpy(data, change->data, block_size);
                return true;
            }
        auto cached = cache ? &cache[block % cached_blocks] : nullptr;
        if (cached && cached->valid && cached->block == block) {
            memcpy(data, cached->data, block_size);
            return true;
        }
        int result = block_read(device, uint64_t(block) * (block_size / sector_size), data,
                                block_size / sector_size);
        if (result)
            return fail(result);
        if (cached) {
            cached->block = block;
            cached->valid = true;
            memcpy(cached->data, data, block_size);
        }
        return true;
    }

    bool write_block(uint32_t block, const void* data, unsigned rank) {
        if (block >= blocks)
            return fail();
        for (auto change = changes; change; change = change->next)
            if (change->block == block) {
                memcpy(change->data, data, block_size);
                change->rank = max(change->rank, rank);
                return true;
            }
        if (change_count == max_changes)
            return fail(-12);
        auto change = (Change*)alloc(sizeof(Change));
        if (!change)
            return fail(-12);
        change->next = changes;
        change->block = block;
        change->rank = rank;
        memcpy(change->data, data, block_size);
        changes = change;
        change_count++;
        return true;
    }

    void discard() {
        while (changes) {
            auto next = changes->next;
            release(changes);
            changes = next;
        }
        change_count = touched_count = 0;
    }

    bool super(uint8_t* data) {
        uint8_t block[max_block_size];
        if (!read_block(1024 / block_size, block))
            return false;
        memcpy(data, block + (1024 % block_size), 1024);
        return true;
    }

    bool save_super(const uint8_t* data) {
        uint8_t block[max_block_size];
        if (!read_block(1024 / block_size, block))
            return false;
        memcpy(block + (1024 % block_size), data, 1024);
        return write_block(1024 / block_size, block, 5);
    }

    bool descriptor(unsigned group, uint8_t* data) {
        uint8_t block[max_block_size];
        if (group >= group_count || !read_block(gdt + group * 32 / block_size, block))
            return fail();
        memcpy(data, block + (group * 32 % block_size), 32);
        return true;
    }

    bool save_descriptor(unsigned group, const uint8_t* data) {
        uint8_t block[max_block_size];
        if (group >= group_count || !read_block(gdt + group * 32 / block_size, block))
            return fail();
        memcpy(block + (group * 32 % block_size), data, 32);
        return write_block(gdt + group * 32 / block_size, block, 4);
    }

    bool allocated(uint32_t number, bool inode) {
        if (!number || (inode ? number > inodes : number < first || number >= blocks))
            return fail();
        uint32_t index = inode ? number - 1 : number - first;
        unsigned per_group = inode ? inodes_per_group : blocks_per_group;
        auto& group = groups[index / per_group];
        uint8_t bitmap[max_block_size];
        if (!read_block(inode ? group.inode_bitmap : group.block_bitmap, bitmap))
            return false;
        return bit(bitmap, index % per_group) ? true : fail();
    }

    bool data_block(uint32_t block) {
        return !metadata(block) ? allocated(block, false) : fail();
    }

    Entry* canonical(uint32_t number) {
        for (auto entry = entries.inode_bucket(number); entry; entry = entry->inode_next)
            if (entry->number == number && !entry->node.hardlink)
                return entry;
        return nullptr;
    }

    bool load_inode(uint32_t number, uint8_t* data, bool check = true) {
        if (!number || number > inodes || (check && !allocated(number, true)))
            return fail();
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % inodes_per_group) * inode_size;
        uint8_t block[max_block_size];
        if (!read_block(groups[index / inodes_per_group].inode_table + offset / block_size, block))
            return false;
        memcpy(data, block + offset % block_size, inode_bytes);
        if (auto cached = canonical(number); cached && cached->atime_dirty)
            set32(data + 8, cached->node.atime.sec);
        return true;
    }

    bool save_inode(uint32_t number, const uint8_t* data, bool clear = false) {
        uint32_t index = number - 1;
        uint64_t offset = uint64_t(index % inodes_per_group) * inode_size;
        uint8_t block[max_block_size];
        if (!number || number > inodes ||
            !read_block(groups[index / inodes_per_group].inode_table + offset / block_size, block))
            return fail();
        if (clear)
            memset(block + offset % block_size, 0, inode_size);
        memcpy(block + offset % block_size, data, inode_bytes);
        if (!write_block(groups[index / inodes_per_group].inode_table + offset / block_size, block,
                         2))
            return false;
        // Initial mount recovery has no cached identities to refresh.
        if (!entries.first())
            return true;
        for (unsigned i = 0; i < touched_count; i++)
            if (touched[i] == number)
                return true;
        if (touched_count == sizeof(touched) / sizeof(touched[0]))
            return fail(-12);
        touched[touched_count++] = number;
        return true;
    }

    void populate(Entry* entry, const uint8_t* data) {
        auto& node = entry->node;
        node.mode = u16(data);
        node.uid = u16(data + 2) | (uint32_t(u16(data + 120)) << 16);
        node.gid = u16(data + 24) | (uint32_t(u16(data + 122)) << 16);
        node.links = u16(data + 26);
        node.size = file_size(data);
        node.allocated_blocks = u32(data + 28);
        node.atime = {int32_t(u32(data + 8)), 0};
        node.ctime = {int32_t(u32(data + 12)), 0};
        node.mtime = {int32_t(u32(data + 16)), 0};
        entry->atime_dirty = false;
        if (!node.mode)
            entry->number = 0;
    }

    bool flush() {
        for (unsigned i = 0; i < touched_count; i++) {
            if (auto entry = canonical(touched[i])) {
                uint8_t inode[inode_bytes];
                if (!load_inode(touched[i], inode, false))
                    return false;
                populate(entry, inode);
                for (auto alias = entries.inode_bucket(touched[i]); alias;
                     alias = alias->inode_next)
                    if (alias->node.hardlink == &entry->node)
                        alias->node.mode = entry->node.mode;
            }
        }
        // Keep the complete overlay after an error; a later sync retries every write.
        if (journal && changes) {
            auto writes = static_cast<JournalWrite*>(alloc(sizeof(JournalWrite) * change_count));
            if (!writes)
                return fail(-12);
            unsigned index = 0;
            for (auto change = changes; change; change = change->next) {
                writes[index++] = {change->block, change->data};
                if (cache) {
                    auto& cached = cache[change->block % cached_blocks];
                    if (cached.block == change->block)
                        cached.valid = false;
                }
            }
            int result = journal_commit(journal, writes, change_count);
            release(writes);
            if (result)
                return fail(result);
            discard();
            return true;
        }
        for (unsigned rank = 0; rank <= 5; rank++)
            for (auto change = changes; change; change = change->next)
                if (change->rank == rank) {
                    // Invalidate before submission, including failed or partial writes.
                    // Pending changes take precedence until their flush completes.
                    if (cache) {
                        auto& cached = cache[change->block % cached_blocks];
                        if (cached.block == change->block)
                            cached.valid = false;
                    }
                    int result =
                        block_write(device, uint64_t(change->block) * (block_size / sector_size),
                                    change->data, block_size / sector_size, this);
                    if (result)
                        return fail(result);
                }
        if (changes) {
            int result = block_flush(device);
            if (result)
                return fail(result);
        }
        discard();
        return true;
    }

    bool begin() {
        error = 0;
        return flush();
    }

    int finish(bool success) {
        if (!success) {
            int result = error ? error : -117;
            discard();
            return result;
        }
        return flush() ? 0 : error;
    }

    Entry* reserve_entry() {
        auto entry = entries.reserve();
        if (!entry)
            fail(-12);
        return entry;
    }

    Node* add_entry(Entry* entry, uint32_t number, Node* parent, const char* name,
                    const uint8_t* inode) {
        entry->number = number;
        entry->node.inode = number;
        entry->node.parent = parent;
        entry->node.mount = mount;
        entry->node.filesystem_data = entry;
        memcpy(entry->node.name, name, strlen(name) + 1);
        if (auto original = canonical(number); original && (u16(inode) & 0170000) != directory) {
            entry->node.hardlink = &original->node;
            entry->node.mode = original->node.mode;
        } else
            populate(entry, inode);
        entries.insert(entry);
        return &entry->node;
    }

    bool counts(unsigned group, bool inode, int delta, int directory_delta = 0) {
        uint8_t desc[32], header[1024];
        if (!descriptor(group, desc) || !super(header))
            return false;
        unsigned field = inode ? 14 : 12, global = inode ? 16 : 12;
        int64_t count = int64_t(u16(desc + field)) + delta;
        int64_t total = int64_t(u32(header + global)) + delta;
        int64_t dirs = int64_t(u16(desc + 16)) + directory_delta;
        if (count < 0 || count > (inode ? groups[group].inodes : groups[group].blocks) ||
            total < 0 || total > (inode ? inodes : blocks) || dirs < 0 ||
            dirs > groups[group].inodes)
            return fail();
        set16(desc + field, count);
        set16(desc + 16, dirs);
        set32(header + global, total);
        set32(header + 48, node_now().sec);
        return save_descriptor(group, desc) && save_super(header);
    }

    uint32_t allocate(bool inode, unsigned preferred, bool dir = false) {
        uint8_t bitmap[max_block_size];
        for (unsigned step = 0; step < group_count; step++) {
            unsigned index = (preferred + step) % group_count;
            auto& group = groups[index];
            uint8_t desc[32];
            if (!descriptor(index, desc))
                return 0;
            // Validated counters include this operation's staged allocations.
            if (!u16(desc + (inode ? 14 : 12)))
                continue;
            uint32_t bitmap_block = inode ? group.inode_bitmap : group.block_bitmap;
            if (!read_block(bitmap_block, bitmap))
                return 0;
            uint32_t count = inode ? group.inodes : group.blocks;
            for (uint32_t i = 0; i < count; i++) {
                // Skip occupied words while keeping first-free allocation order.
                if (!(i % 32) && u32(bitmap + i / 8) == UINT32_MAX) {
                    i += 31;
                    continue;
                }
                uint32_t number = inode ? index * inodes_per_group + i + 1 : group.first + i;
                if (bit(bitmap, i) || (inode && number < first_inode))
                    continue;
                if (!inode && metadata(number)) {
                    fail();
                    return 0;
                }
                setbit(bitmap, i, true);
                if (!write_block(bitmap_block, bitmap, 4) || !counts(index, inode, -1, dir ? 1 : 0))
                    return 0;
                if (!inode) {
                    uint8_t zero[max_block_size]{};
                    if (!write_block(number, zero, 0))
                        return 0;
                }
                return number;
            }
        }
        fail(-28);
        return 0;
    }

    bool free_number(uint32_t number, bool inode, bool dir = false) {
        if ((inode && number < first_inode) || (!inode && metadata(number)) ||
            !allocated(number, inode))
            return fail();
        uint32_t offset = inode ? number - 1 : number - first;
        unsigned per_group = inode ? inodes_per_group : blocks_per_group,
                 index = offset / per_group;
        uint32_t bitmap_block = inode ? groups[index].inode_bitmap : groups[index].block_bitmap;
        uint8_t bitmap[max_block_size];
        if (!read_block(bitmap_block, bitmap))
            return false;
        setbit(bitmap, offset % per_group, false);
        return write_block(bitmap_block, bitmap, 4) && counts(index, inode, 1, dir ? -1 : 0);
    }

    uint64_t capacity() const {
        uint64_t n = block_size / 4;
        return (12 + n + n * n + n * n * n) * block_size;
    }

    bool add_blocks(uint8_t* inode, int delta) {
        int64_t count = int64_t(u32(inode + 28)) + int64_t(delta) * (block_size / sector_size);
        if (count < 0 || count > UINT32_MAX)
            return fail(-27);
        set32(inode + 28, count);
        return true;
    }

    bool map_block(uint8_t* inode, uint64_t logical, bool create, uint32_t& result,
                   unsigned preferred) {
        uint64_t n = block_size / 4, index = logical, span = 1;
        unsigned slot, depth;
        if (index < 12) {
            slot = index;
            depth = 0;
        } else {
            index -= 12;
            if (index < n) {
                slot = 12;
                depth = 1;
            } else {
                index -= n;
                if (index < n * n) {
                    slot = 13;
                    depth = 2;
                    span = n;
                } else {
                    index -= n * n;
                    if (index >= n * n * n)
                        return fail(-27);
                    slot = 14;
                    depth = 3;
                    span = n * n;
                }
            }
        }
        uint32_t pointer = u32(inode + 40 + slot * 4);
        if (!pointer && create) {
            pointer = allocate(false, preferred);
            if (!pointer || !add_blocks(inode, 1))
                return false;
            set32(inode + 40 + slot * 4, pointer);
        }
        if (!pointer) {
            result = 0;
            return true;
        }
        if (!data_block(pointer))
            return false;
        uint8_t block[max_block_size];
        while (depth) {
            if (!read_block(pointer, block))
                return false;
            uint32_t position = index / span;
            uint32_t child = u32(block + position * 4);
            if (!child && create) {
                child = allocate(false, preferred);
                if (!child || !add_blocks(inode, 1))
                    return false;
                set32(block + position * 4, child);
                if (!write_block(pointer, block, 1))
                    return false;
            }
            if (!child) {
                result = 0;
                return true;
            }
            if (!data_block(child))
                return false;
            pointer = child;
            index %= span;
            span /= n;
            depth--;
        }
        result = pointer;
        return true;
    }

    bool prune(uint32_t& pointer, unsigned depth, uint64_t base, uint64_t keep, uint8_t* inode) {
        if (!pointer)
            return true;
        if (!data_block(pointer))
            return false;
        uint64_t span = 1;
        for (unsigned i = 0; i < depth; i++)
            span *= block_size / 4;
        if (base + span <= keep)
            return true;
        if (!depth) {
            if (!free_number(pointer, false) || !add_blocks(inode, -1))
                return false;
            pointer = 0;
            return true;
        }
        uint8_t data[max_block_size];
        if (!read_block(pointer, data))
            return false;
        bool any = false, changed = false;
        for (unsigned i = 0; i < block_size / 4; i++) {
            uint32_t child = u32(data + i * 4), old = child;
            if (!prune(child, depth - 1, base + uint64_t(i) * (span / (block_size / 4)), keep,
                       inode))
                return false;
            if (child != old) {
                set32(data + i * 4, child);
                changed = true;
            }
            any |= child != 0;
        }
        if (!any) {
            if (!free_number(pointer, false) || !add_blocks(inode, -1))
                return false;
            pointer = 0;
            return true;
        }
        return !changed || write_block(pointer, data, 1);
    }

    bool size(uint8_t* inode, uint64_t length) {
        if (length > capacity() || int64_t(length) < 0)
            return fail(-27);
        if (length > INT32_MAX) {
            if (revision == 0)
                return fail(-27);
            uint8_t header[1024];
            if (!super(header))
                return false;
            set32(header + 100, u32(header + 100) | 2);
            if (!save_super(header))
                return false;
        }
        uint64_t old = file_size(inode), keep = (length + block_size - 1) / block_size;
        if (length < old) {
            uint64_t base = 0;
            for (unsigned slot = 0; slot < 15; slot++) {
                unsigned depth = slot < 12 ? 0 : slot - 11;
                uint64_t span = 1;
                for (unsigned i = 0; i < depth; i++)
                    span *= block_size / 4;
                uint32_t pointer = u32(inode + 40 + slot * 4);
                if (!prune(pointer, depth, base, keep, inode))
                    return false;
                set32(inode + 40 + slot * 4, pointer);
                base += span;
            }
        }
        uint64_t tail = min(old, length);
        if (tail % block_size) {
            uint32_t block;
            if (!map_block(inode, tail / block_size, false, block, 0))
                return false;
            if (block) {
                uint8_t data[max_block_size];
                if (!read_block(block, data))
                    return false;
                memset(data + tail % block_size, 0, block_size - tail % block_size);
                if (!write_block(block, data, 0))
                    return false;
            }
        }
        set32(inode + 4, length);
        if ((u16(inode) & 0170000) == regular_file)
            set32(inode + 108, length >> 32);
        return true;
    }

    bool xattr_block(const uint8_t* inode, uint8_t* data, uint32_t& references) {
        uint32_t block = u32(inode + 104);
        references = 0;
        if (!block)
            return true;
        if (!data_block(block) || !read_block(block, data))
            return false;
        return ext2_xattr_valid(data, block_size, references) ? true : fail();
    }

    bool release_xattr(uint32_t block, uint8_t* data, uint32_t references) {
        if (references == 1)
            return free_number(block, false);
        set32(data + 4, references - 1);
        return write_block(block, data, 1);
    }

    bool delete_inode(uint32_t number, uint8_t* inode) {
        bool dir = (u16(inode) & 0170000) == directory;
        if (!fast_symlink(inode, block_size) && !size(inode, 0))
            return false;
        uint32_t block = u32(inode + 104), references;
        uint8_t data[max_block_size];
        if (block &&
            (!xattr_block(inode, data, references) || !release_xattr(block, data, references)))
            return false;
        memset(inode, 0, inode_bytes);
        return save_inode(number, inode, true) && free_number(number, true, dir);
    }

    bool state(bool clean) {
        uint8_t header[1024];
        if (!super(header))
            return false;
        set16(header + 58, clean ? u16(header + 58) | 1 : u16(header + 58) & ~1u);
        if (journal)
            set32(header + 96, clean ? u32(header + 96) & ~4u : u32(header + 96) | 4u);
        set32(header + 48, node_now().sec);
        return save_super(header);
    }
};

struct Record {
    uint32_t inode;
    unsigned length, name_length;
    uint8_t type;
};

inline bool record(Volume& v, const uint8_t* data, unsigned offset, Record& r) {
    if (offset > v.block_size - 8)
        return v.fail();
    r = {u32(data + offset), u16(data + offset + 4),
         unsigned(v.typed_entries ? data[offset + 6] : u16(data + offset + 6)),
         uint8_t(v.typed_entries ? data[offset + 7] : 0)};
    if (r.length < 8 || r.length % 4 || r.length > v.block_size - offset || r.name_length > 255 ||
        r.name_length > r.length - 8 || r.inode > v.inodes || r.type > 7)
        return v.fail();
    if (r.inode)
        for (unsigned i = 0; i < r.name_length; i++)
            if (!data[offset + 8 + i] || data[offset + 8 + i] == '/')
                return v.fail();
    return r.inode && !r.name_length ? v.fail() : true;
}

inline bool directory_block(Volume& v, uint8_t* inode, uint64_t offset, uint32_t& block,
                            uint8_t* data) {
    if ((u16(inode) & 0170000) != directory || file_size(inode) % v.block_size)
        return v.fail();
    if (!v.map_block(inode, offset / v.block_size, false, block, 0))
        return false;
    return block ? v.read_block(block, data) : v.fail();
}

enum class Recovery { none, checked, journal };
bool validate_volume(Volume&, uint8_t* header, Recovery);
} // namespace ax::ext2_detail
