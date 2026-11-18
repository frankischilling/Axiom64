// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/inotify_queue.hpp"
#include <assert.h>
#include <stdlib.h>

namespace {
size_t allocated;
bool refuse;
} // namespace

namespace ax {
void* alloc(size_t size) {
    if (refuse)
        return nullptr;
    assert(size <= page_size - 16);
    void* memory = malloc(size);
    assert(memory);
    ++allocated;
    return memory;
}

void release(void* memory) {
    assert(allocated && memory);
    --allocated;
    free(memory);
}
} // namespace ax

static void named_records() {
    ax::InotifyQueue queue;
    constexpr uint32_t moved_from = 0x40;
    constexpr uint32_t moved_to = 0x80;
    for (size_t length = 1; length < 256; ++length) {
        char name[256];
        memset(name, 'n', length);
        name[length] = 0;
        queue.push(5, moved_from, 6, name);
        queue.push(5, moved_from, 7, name);
        queue.push(5, moved_to, 6, name);
        const auto* entry = queue.front();
        assert(entry && entry->header.wd == 5 && entry->header.mask == moved_from &&
               entry->header.cookie == 6);
        const size_t padded = ((length + 1 + 15) / 16) * 16;
        assert(entry->header.len == padded && queue.bytes() == 2 * (16 + padded));
        assert(!memcmp(entry->name, name, length));
        for (size_t at = length; at < padded; ++at)
            assert(entry->name[at] == 0);
        queue.pop();
        assert(queue.front()->header.mask == moved_to);
        queue.pop();
        assert(!queue.front() && !queue.bytes() && !allocated);
    }
    queue.push(1, ax::inotify_watch_ignored, 0, nullptr);
    queue.push(1, ax::inotify_watch_ignored, 0, nullptr);
    assert(queue.front()->header.len == 0 && queue.bytes() == 32);
    queue.clear();
    assert(!queue.front() && !queue.bytes() && !allocated);
}

static void queue_limit() {
    ax::InotifyQueue queue;
    constexpr auto capacity = int32_t(ax::InotifyQueue::capacity);
    for (int32_t id = 1; id <= capacity; ++id)
        queue.push(id, 0x2, 0, nullptr);
    // Capacity is checked before coalescing, including an exact duplicate.
    queue.push(capacity, 0x2, 0, nullptr);
    queue.push(1, 0x2, 0, nullptr);
    assert(queue.bytes() == size_t(capacity + 1) * 16);
    for (int32_t id = 1; id <= 2; ++id) {
        assert(queue.front()->header.wd == id);
        queue.pop();
    }
    queue.push(1, 0x2, 0, nullptr);
    for (int32_t id = 3; id <= capacity; ++id) {
        assert(queue.front()->header.wd == id);
        queue.pop();
    }
    assert(queue.bytes() == 32);
    const auto& overflow = queue.front()->header;
    assert(overflow.wd == -1 && overflow.mask == ax::inotify_queue_overflow && !overflow.cookie &&
           !overflow.len);
    queue.pop();
    assert(queue.front()->header.wd == 1 && queue.bytes() == 16);
    queue.pop();
    assert(!queue.front() && !queue.bytes() && !allocated);
}

static void allocation_failure() {
    ax::InotifyQueue queue;
    refuse = true;
    queue.push(3, 0x2, 0, "file");
    queue.push(3, 0x2, 0, "file");
    assert(queue.front()->header.mask == ax::inotify_queue_overflow && queue.bytes() == 16);
    refuse = false;
    queue.push(3, 0x2, 0, "file");
    assert(queue.bytes() == 48);
    queue.pop();
    assert(queue.front()->header.wd == 3);
    queue.clear();
    assert(!queue.front() && !queue.bytes() && !allocated);
}

int main() {
    named_records();
    queue_limit();
    allocation_failure();
}
