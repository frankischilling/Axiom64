// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/virtio/queue.hpp
 * @brief   VirtIO split queue interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines descriptor and ring state for submitting requests and returning
 * completed buffers.
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
#include "core/base.hpp"

namespace ax {
class VirtioPci;

inline void virtio_dma_barrier() {
    asm volatile("mfence" ::: "memory");
}

struct VirtioBuffer {
    uint64_t address;
    uint32_t length;
    bool writable;
};

struct VirtioCompletion {
    uint64_t cookie;
    uint32_t length;
    uint16_t head;
};

struct VirtioQueueLayout {
    uint64_t descriptors, available, used;
    uint16_t size;
};

// One CPU, serialized callers. Payload buffers remain the driver's responsibility.
class SplitQueue {
  public:
    SplitQueue() = default;

    SplitQueue(const SplitQueue&) = delete;

    SplitQueue& operator=(const SplitQueue&) = delete;

    bool create(uint16_t size);

    VirtioQueueLayout layout() const;

    // Returns the head index, -EAGAIN for ordinary exhaustion, or a negative error.
    int submit(const VirtioBuffer*, unsigned count, uint64_t cookie);

    // Returns 1 for a completion, 0 for none, or -EIO for a broken queue.
    int complete(VirtioCompletion&);

    // Refuses to free storage until the transport acknowledges a device reset.
    bool release();

  private:
    friend class VirtioPci;

    struct Descriptor {
        uint64_t address;
        uint32_t length;
        uint16_t flags, next;
    };

    struct UsedEntry {
        uint32_t id, length;
    };

    struct Owner {
        uint64_t cookie;
        uint16_t next, count;
        bool occupied;
    };

    static_assert(sizeof(Descriptor) == 16 && sizeof(UsedEntry) == 8);
    uint64_t physical_ = 0;
    size_t pages_ = 0;
    Descriptor* descriptors_ = nullptr;
    volatile uint16_t* available_ring_ = nullptr;
    volatile uint16_t* used_ring_ = nullptr;
    volatile UsedEntry* used_entries_ = nullptr;
    Owner* owners_ = nullptr;
    uint16_t size_ = 0, free_head_ = 0xffff, free_count_ = 0;
    uint16_t available_ = 0, consumed_ = 0, pending_ = 0;
    bool device_owned_ = false, broken_ = false;

    int fail() {
        broken_ = true;
        return -5;
    }
};
} // namespace ax
