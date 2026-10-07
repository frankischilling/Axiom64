// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/virtio/queue.hpp"

namespace ax {
bool SplitQueue::create(uint16_t size) {
    if (physical_ || !size || size > 32768 || (size & (size - 1)))
        return false;
    size_t available_offset = size_t(size) * sizeof(Descriptor);
    size_t used_offset = align_up(available_offset + 6 + size_t(size) * 2);
    pages_ = align_up(used_offset + 6 + size_t(size) * sizeof(UsedEntry)) / page_size;
    physical_ = page_alloc(pages_);
    owners_ = (Owner*)alloc(size_t(size) * sizeof(Owner));
    if (!physical_ || !owners_) {
        release();
        return false;
    }
    memset(physical(physical_), 0, pages_ * page_size);
    memset(owners_, 0, size_t(size) * sizeof(Owner));
    size_ = free_count_ = size;
    free_head_ = 0;
    descriptors_ = (Descriptor*)physical(physical_);
    available_ring_ = (volatile uint16_t*)physical(physical_ + available_offset);
    used_ring_ = (volatile uint16_t*)physical(physical_ + used_offset);
    used_entries_ = (volatile UsedEntry*)((volatile uint8_t*)used_ring_ + 4);
    for (unsigned i = 0; i < size; i++)
        owners_[i].next = i + 1 == size ? 0xffff : uint16_t(i + 1);
    available_ring_[0] = 1; // Polling; no EVENT_IDX or interrupt delivery.
    virtio_dma_barrier();
    return true;
}
VirtioQueueLayout SplitQueue::layout() const {
    if (!size_)
        return {};
    return {physical_, physical_ + size_t(size_) * sizeof(Descriptor),
            physical_ + align_up(size_t(size_) * sizeof(Descriptor) + 6 + size_t(size_) * 2),
            size_};
}
int SplitQueue::submit(const VirtioBuffer* buffers, unsigned count, uint64_t cookie) {
    if (!physical_ || broken_)
        return -5;
    if (!buffers || !count || count > size_)
        return -22;
    bool writable = false;
    uint64_t bytes = 0;
    for (unsigned i = 0; i < count; i++) {
        const auto& b = buffers[i];
        if (b.address >= (1ull << 52) || b.length > (1ull << 52) - b.address ||
            (writable && !b.writable))
            return -22;
        writable |= b.writable;
        bytes += b.length;
        if (bytes > UINT32_MAX)
            return -22;
    }
    if (count > free_count_)
        return -11;
    uint16_t head = free_head_, at = head;
    for (unsigned i = 0; i < count; i++) {
        auto& owner = owners_[at];
        uint16_t next = owner.next;
        const auto& b = buffers[i];
        descriptors_[at] = {b.address, b.length,
                            uint16_t((b.writable ? 2 : 0) | (i + 1 < count ? 1 : 0)),
                            uint16_t(i + 1 < count ? next : 0)};
        owner.occupied = true;
        owner.count = i ? 0 : uint16_t(count);
        owner.cookie = i ? 0 : cookie;
        at = next;
    }
    free_head_ = at;
    free_count_ -= count;
    pending_++;
    available_ring_[2 + (available_ & (size_ - 1))] = head;
    virtio_dma_barrier();
    available_ring_[1] = ++available_;
    virtio_dma_barrier();
    return head;
}
int SplitQueue::complete(VirtioCompletion& result) {
    if (!physical_ || broken_)
        return -5;
    uint16_t published = used_ring_[1], ready = uint16_t(published - consumed_);
    if (!ready)
        return 0;
    virtio_dma_barrier();
    if (ready > pending_)
        return fail();
    const auto& entry = used_entries_[consumed_ & (size_ - 1)];
    uint32_t id = entry.id, length = entry.length;
    if (id >= size_ || !owners_[id].occupied || !owners_[id].count)
        return fail();
    const uint16_t count = owners_[id].count;
    result = {owners_[id].cookie, length, uint16_t(id)};
    uint16_t at = id;
    for (unsigned i = 0; i < count; i++) {
        auto& owner = owners_[at];
        uint16_t next = owner.next;
        owner.occupied = false;
        owner.count = 0;
        owner.cookie = 0;
        owner.next = free_head_;
        free_head_ = at;
        at = next;
    }
    free_count_ += count;
    pending_--;
    consumed_++;
    return 1;
}
bool SplitQueue::release() {
    if (device_owned_)
        return false;
    if (physical_)
        page_free(physical_, pages_);
    if (owners_)
        ax::release(owners_);
    physical_ = pages_ = 0;
    size_ = free_count_ = available_ = consumed_ = pending_ = 0;
    free_head_ = 0xffff;
    descriptors_ = nullptr;
    available_ring_ = used_ring_ = nullptr;
    used_entries_ = nullptr;
    owners_ = nullptr;
    broken_ = false;
    return true;
}
} // namespace ax
