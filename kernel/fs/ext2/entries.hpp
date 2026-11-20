// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/entries.hpp
 * @brief   Stable, inode-indexed ext2 namespace entries.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Packs entries into allocator pages and retains published addresses until
 * unmount. Open files and directory handles can keep those addresses.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once

#include "fs/vfs.hpp"

namespace ax::ext2_detail {
struct Entry {
    Node node;
    Entry *next, *inode_next;
    uint32_t number;
    bool atime_dirty;
};

class EntryCache {
    static constexpr unsigned batch_size = 8, max_batches = 8192, bucket_count = 4096;

    struct Batch {
        Batch* next;
        unsigned used;
        Entry entries[batch_size];
    };

    // Leave room for the heap header so each batch costs one physical page.
    static_assert(sizeof(Batch) + 32 <= page_size);

    Batch* batches;
    Entry** buckets;
    Entry *published, *unused;
    unsigned batch_count;

    static unsigned index(uint32_t number) {
        return (number * 2654435761u) >> 20;
    }

  public:
    Entry* first() const {
        return published;
    }

    Entry* inode_bucket(uint32_t number) const {
        return buckets ? buckets[index(number)] : nullptr;
    }

    Entry* reserve() {
        if (unused) {
            auto entry = unused;
            unused = entry->next;
            *entry = {};
            return entry;
        }
        if (!buckets) {
            buckets = static_cast<Entry**>(alloc(bucket_count * sizeof(Entry*)));
            if (!buckets)
                return nullptr;
            memset(buckets, 0, bucket_count * sizeof(Entry*));
        }
        if (!batches || batches->used == batch_size) {
            if (batch_count == max_batches)
                return nullptr;
            auto batch = static_cast<Batch*>(alloc(sizeof(Batch)));
            if (!batch)
                return nullptr;
            batch->next = batches;
            batch->used = 0;
            batches = batch;
            batch_count++;
        }
        auto entry = &batches->entries[batches->used++];
        *entry = {};
        return entry;
    }

    // Only unpublished reservations can be reused.
    void cancel(Entry* entry) {
        entry->next = unused;
        unused = entry;
    }

    void insert(Entry* entry) {
        entry->next = published;
        published = entry;
        auto& bucket = buckets[index(entry->number)];
        entry->inode_next = bucket;
        bucket = entry;
    }

    void clear() {
        while (batches) {
            auto batch = batches;
            batches = batch->next;
            release(batch);
        }
        release(buckets);
        *this = {};
    }
};
} // namespace ax::ext2_detail
