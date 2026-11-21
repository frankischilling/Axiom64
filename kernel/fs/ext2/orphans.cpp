// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/orphans.cpp
 * @brief   Record and recover native ext-family orphans.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Journals orphan tracking with namespace mutations, validates the replay
 * view, and reclaims inode mappings in restartable transactions.
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

bool load_orphan_file(Volume& v, Inode& inode) {
    if (!v.load_inode(v.orphan_inode, inode))
        return false;
    uint64_t length = file_size(inode);
    return ((u16(inode) & 0170000) == regular_file && u16(inode + 26) == 1 && !u32(inode + 20) &&
            !u32(inode + 104) && !(length % v.block_size) &&
            length / v.block_size <= orphan_block_limit) ||
           v.fail();
}

bool read_orphan_block(Volume& v, Inode& inode, unsigned index, uint32_t& block, uint8_t* data) {
    if (!v.map_block(inode, index, false, block, 0) || !block || !v.read_block(block, data))
        return v.fail();
    unsigned tail = v.block_size - orphan_tail_bytes;
    return (u32(data + tail) == orphan_block_magic &&
            (!v.checksums() || u32(data + tail + 4) == checksum(v, inode, block, data))) ||
           v.fail();
}

bool write_orphan_block(Volume& v, const Inode& inode, uint32_t block, uint8_t* data) {
    if (v.checksums())
        set32(data + v.block_size - 4, checksum(v, inode, block, data));
    return v.write_block(block, data, 4);
}

// On success, updated is false if every slot was occupied (insertion) or
// the inode had no slot (removal).
bool change_slot(Volume& v, uint32_t before, uint32_t after, bool& updated) {
    updated = false;
    if (!v.orphan_inode)
        return true;
    Inode inode;
    if (!load_orphan_file(v, inode))
        return false;
    for (unsigned index = 0; index < file_size(inode) / v.block_size; index++) {
        uint32_t block;
        uint8_t data[max_block_size];
        if (!read_orphan_block(v, inode, index, block, data))
            return false;
        for (unsigned offset = 0; offset < v.block_size - orphan_tail_bytes; offset += 4) {
            if (u32(data + offset) != before)
                continue;
            set32(data + offset, after);
            updated = true;
            return write_orphan_block(v, inode, block, data);
        }
    }
    return true;
}

bool remove_record(Volume& v, const Inode& inode) {
    uint8_t header[1024];
    if (!v.super(header))
        return false;
    uint32_t head = u32(header + last_orphan_offset), next = u32(inode + 20);
    if (head == inode.number) {
        set32(header + last_orphan_offset, next);
        return v.save_super(header);
    }
    for (uint32_t number = head, depth = 0; number; depth++) {
        Inode predecessor;
        if (depth >= v.inodes || number < v.first_inode || !v.load_inode(number, predecessor) ||
            u16(predecessor + 26))
            return v.fail();
        number = u32(predecessor + 20);
        if (number == inode.number) {
            set32(predecessor + 20, next);
            return v.save_inode(predecessor.number, predecessor);
        }
    }
    bool updated;
    return (next == 0 && (u32(header + 100) & orphan_present_feature) &&
            change_slot(v, inode.number, 0, updated) && updated) ||
           v.fail();
}
} // namespace

struct NativeOrphans::Batch {
    unsigned limit, completed = 0;
    uint32_t first = 0;
    bool slots_remaining = false;
};

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

bool NativeOrphans::finish_inode(uint32_t number, Inode& inode) {
    if (!u16(inode + 26))
        return v.delete_inode(number, inode);
    if (!v.fast_symlink(inode) && !v.size(inode, file_size(inode), SizeChange::recovery))
        return false;
    set32(inode + 20, 0);
    return v.save_inode(number, inode);
}

bool NativeOrphans::check_file(const uint8_t* header, const uint8_t* allocated, Batch* batch) {
    if (!v.orphan_inode)
        return true;
    Inode inode;
    if (!load_orphan_file(v, inode))
        return false;
    unsigned tail = v.block_size - orphan_tail_bytes;
    bool present = (u32(header + 100) & orphan_present_feature) != 0;
    for (unsigned index = 0; index < file_size(inode) / v.block_size; index++) {
        uint32_t block;
        uint8_t data[max_block_size];
        if (!read_orphan_block(v, inode, index, block, data))
            return false;
        bool changed = false;
        for (unsigned offset = 0; offset < tail; offset += 4) {
            uint32_t number = u32(data + offset);
            if (!number)
                continue;
            if (!present)
                return v.fail();
            if (batch) {
                if (batch->completed == batch->limit) {
                    batch->slots_remaining = true;
                    continue;
                }
                if (!batch->first)
                    batch->first = number;
                Inode orphan;
                if (!contains(number) || !v.load_inode(number, orphan) ||
                    !finish_inode(number, orphan))
                    return v.fail();
                set32(data + offset, 0);
                changed = true;
                batch->completed++;
            } else {
                Inode orphan;
                if (!mark(number, allocated, orphan) || u32(orphan + 20))
                    return v.fail();
            }
        }
        if (changed && !write_orphan_block(v, inode, block, data))
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
    return check_file(header, allocated);
}

bool NativeOrphans::stage_batch(uint8_t* header, Batch& batch) {
    uint32_t head = u32(header + last_orphan_offset);
    while (head && batch.completed < batch.limit) {
        if (!batch.first)
            batch.first = head;
        Inode inode;
        if (!contains(head) || !v.load_inode(head, inode))
            return v.fail();
        uint32_t next = u32(inode + 20);
        if (!finish_inode(head, inode))
            return false;
        head = next;
        batch.completed++;
    }
    bool present = u32(header + 100) & orphan_present_feature;
    if (present && !head && !check_file(header, nullptr, &batch))
        return false;
    if (!v.super(header))
        return false;
    set32(header + last_orphan_offset, head);
    if (!head && !batch.slots_remaining)
        set32(header + 100, u32(header + 100) & ~orphan_present_feature);
    // Keep recovery armed across commits, including for older deletion markers.
    set16(header + 58, u16(header + 58) & ~1u);
    set32(header + 96, u32(header + 96) | 4u);
    return v.save_super(header);
}

bool NativeOrphans::trim_inode(uint32_t number, bool shrinking) {
    Inode inode;
    if (!v.load_inode(number, inode) || v.fast_symlink(inode))
        return v.fail(-28);
    unsigned capacity = min(max_changes, journal_payload_limit(v.journal));
    // Extents count released group spans. Indirect mappings count released
    // blocks, where one pointer block can cover many adjacent data blocks.
    unsigned limit = max(1u, capacity / 2) * (has_extents(inode) ? 1 : v.block_size / 4);
    uint64_t length = shrinking || u16(inode + 26) ? file_size(inode) : 0;
    uint64_t before = v.inode_sectors(inode);
    for (;;) {
        unsigned budget = limit;
        if (v.prune_mapping(inode, (length + v.block_size - 1) / v.block_size, &budget)) {
            if (v.inode_sectors(inode) >= before)
                return v.fail(-28);
            if (!length) {
                set32(inode + 4, 0);
                set32(inode + 108, 0);
            }
            // Keep the original record until the final cleanup transaction.
            if (v.save_inode(number, inode) && v.state(false))
                return true;
        }
        if (v.error != -28 || limit == 1)
            return false;
        v.discard();
        v.error = 0;
        limit /= 2;
        if (!v.load_inode(number, inode))
            return false;
    }
}

bool NativeOrphans::add(Inode& inode) {
    uint8_t header[1024];
    bool inserted;
    if (!v.super(header) || !change_slot(v, 0, inode.number, inserted))
        return false;
    if (inserted) {
        set32(inode + 20, 0);
        set32(header + 100, u32(header + 100) | orphan_present_feature);
    } else {
        set32(inode + 20, u32(header + last_orphan_offset));
        set32(header + last_orphan_offset, inode.number);
    }
    return v.save_super(header) && v.save_inode(inode.number, inode);
}

int NativeOrphans::cleanup(uint32_t number, bool shrinking) {
    for (;;) {
        Inode inode;
        if (!v.load_inode(number, inode))
            return v.finish(false);
        bool linked = u16(inode + 26) != 0;
        if ((shrinking && (u16(inode) & 0170000) != regular_file) || (!shrinking && linked))
            return v.finish(v.fail());
        bool success;
        if (shrinking) {
            // An open unlinked file keeps its unlink record until reclamation.
            success = v.size(inode, file_size(inode), SizeChange::recovery);
            if (success && linked) {
                success = remove_record(v, inode);
                set32(inode + 20, 0);
            }
            success = success && v.save_inode(number, inode);
        } else {
            success = remove_record(v, inode) && v.delete_inode(number, inode);
        }
        if (success) {
            // Flush retains the final overlay on error. The next begin must
            // retry that overlay, even if it already removes the record.
            if (shrinking)
                v.pending_shrink = 0;
            return v.finish(true);
        }
        int result = v.finish(false);
        if (result != -28)
            return result;
        v.error = 0;
        if (!trim_inode(number, shrinking))
            return v.finish(false);
        if (!v.flush())
            return v.error;
    }
}

bool Volume::begin() {
    error = 0;
    if (!flush())
        return false;
    // Complete a published shrink before a writer can grow into its old
    // mappings or a namespace change can retire the same inode.
    return !pending_shrink || !NativeOrphans(*this).finish_shrink(pending_shrink);
}

bool NativeOrphans::recover(uint8_t* header, uint32_t free_blocks, uint32_t free_inodes) {
    // The caller has validated the complete replay view. Publish that view
    // first, so each cleanup attempt can discard just its own staged changes.
    int error = journal_checkpoint(v.journal);
    if (error)
        return v.fail(error);
    v.discard();
    if (!v.super(header))
        return false;
    // Linux persists group counters before it refreshes the superblock totals.
    // Rebase the counters before any cleanup transaction subtracts from them.
    if (u32(header + 12) != free_blocks || u32(header + 16) != free_inodes) {
        set32(header + 12, free_blocks);
        set32(header + 16, free_inodes);
        if (!v.save_super(header) || !v.state(false) || !v.flush() || !v.super(header))
            return false;
    }
    unsigned limit = UINT32_MAX;
    while (native_orphans_pending(header)) {
        Batch batch{limit};
        if (stage_batch(header, batch)) {
            if (!v.flush())
                return false;
            continue;
        }
        if (v.error != -28)
            return false;
        v.discard();
        v.error = 0;
        if (!v.super(header))
            return false;
        if (batch.completed && limit > 1) {
            limit = max(1u, min(batch.completed, limit / 2));
        } else if (!batch.first || !trim_inode(batch.first) || !v.flush() || !v.super(header)) {
            return v.fail(-28);
        }
    }
    return true;
}
} // namespace ax::ext2_detail
