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
    Entry *next, *inode_next, *reclaim_next;
    uint32_t number;
    bool atime_dirty, reclaim_queued;
};

class EntryCache {
    static constexpr unsigned batch_size = 8;
    static constexpr size_t initial_buckets = 4096, entries_per_bucket = 16;
    static constexpr size_t memory_divisor = 8;
    static inline size_t cache_pages;

    struct Batch {
        Batch* next;
        unsigned used;
        Entry entries[batch_size];
    };

    static_assert(sizeof(Batch) <= page_size);

    Batch* batches;
    Entry** buckets;
    Entry *published, *unused;
    size_t bucket_count, published_count;

    static size_t index(uint32_t number, size_t count) {
        uint32_t hash = number * 2654435761u;
        return (hash ^ (hash >> 16)) & (count - 1);
    }

    static void* allocate_pages(size_t count) {
        // Published entries keep their addresses until unmount. Share a
        // physical memory budget across mounts so pinned entries leave room
        // for userspace, filesystem operations and new mounts.
        const auto budget = physical_memory_stats().total / page_size / memory_divisor;
        if (count > budget || cache_pages > budget - count)
            return nullptr;
        auto address = page_alloc(count);
        if (!address)
            return nullptr;
        cache_pages += count;
        return physical(address);
    }

    static void free_pages(void* address, size_t count) {
        if (!address)
            return;
        page_free(reinterpret_cast<uint64_t>(address) - direct_map, count);
        cache_pages -= count;
    }

    static size_t index_pages(size_t count) {
        return align_up(count * sizeof(Entry*)) / page_size;
    }

    bool grow_index() {
        const size_t count = bucket_count ? bucket_count * 2 : initial_buckets;
        auto replacement = static_cast<Entry**>(allocate_pages(index_pages(count)));
        if (!replacement)
            return false;
        for (size_t bucket = 0; bucket < bucket_count; ++bucket) {
            // Doubling splits a bucket in two. Preserve the order of each
            // chain, as lookup prefers the most recently published entry.
            Entry** lower = &replacement[bucket];
            Entry** upper = &replacement[bucket + bucket_count];
            for (auto entry = buckets[bucket]; entry;) {
                auto next = entry->inode_next;
                auto& tail = index(entry->number, count) == bucket ? lower : upper;
                *tail = entry;
                tail = &entry->inode_next;
                entry = next;
            }
            *lower = *upper = nullptr;
        }
        free_pages(buckets, index_pages(bucket_count));
        buckets = replacement;
        bucket_count = count;
        return true;
    }

  public:
    Entry* first() const {
        return published;
    }

    Entry* inode_bucket(uint32_t number) const {
        return buckets ? buckets[index(number, bucket_count)] : nullptr;
    }

    Entry* reserve() {
        if (unused) {
            auto entry = unused;
            unused = entry->next;
            *entry = {};
            return entry;
        }
        if (!buckets && !grow_index())
            return nullptr;
        if (!batches || batches->used == batch_size) {
            auto batch = static_cast<Batch*>(allocate_pages(1));
            if (!batch)
                return nullptr;
            batch->next = batches;
            batch->used = 0;
            batches = batch;
            if (published_count >= entries_per_bucket * bucket_count)
                grow_index();
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
        auto& bucket = buckets[index(entry->number, bucket_count)];
        entry->inode_next = bucket;
        bucket = entry;
        ++published_count;
    }

    void clear() {
        while (batches) {
            auto batch = batches;
            batches = batch->next;
            free_pages(batch, 1);
        }
        free_pages(buckets, index_pages(bucket_count));
        *this = {};
    }
};
} // namespace ax::ext2_detail
