// SPDX-License-Identifier: GPL-3.0-or-later
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
