// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/inotify_queue.cpp
 * @brief   Inotify event queues.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Buffers notification records and handles queue limits, overflow, and record
 * retrieval.
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
#include "fs/inotify_queue.hpp"

namespace ax {
namespace {
constexpr InotifyEvent overflow_event{{-1, inotify_queue_overflow, 0, 0}, {}};
}

struct InotifyQueue::Block {
    Block* next;
    unsigned first;
    unsigned end;
    InotifyEvent entries[14];
};

const InotifyEvent* InotifyQueue::front() const {
    if (overflow_ && !before_overflow_)
        return &overflow_event;
    return head_ ? &head_->entries[head_->first] : nullptr;
}

void InotifyQueue::mark_overflow() {
    if (overflow_)
        return;
    overflow_ = true;
    before_overflow_ = events_;
    bytes_ += overflow_event.size();
}

void InotifyQueue::push(int32_t wd, uint32_t mask, uint32_t cookie, const char* name) {
    if (events_ + overflow_ >= capacity) {
        mark_overflow();
        return;
    }
    if (!name)
        name = "";
    const size_t name_length = strlen(name);
    if (name_length >= sizeof(InotifyEvent::name)) {
        mark_overflow();
        return;
    }
    const bool tail_is_event = tail_ && (!overflow_ || before_overflow_ < events_);
    if (tail_is_event && mask != inotify_watch_ignored) {
        const auto& previous = tail_->entries[tail_->end - 1];
        // Adjacent equivalent events retain the cookie of the first event.
        if (previous.header.wd == wd && previous.header.mask == mask &&
            !strcmp(previous.name, name))
            return;
    }
    if (!tail_ || tail_->end == sizeof(tail_->entries) / sizeof(InotifyEvent)) {
        static_assert(sizeof(Block) + 16 <= page_size);
        auto* block = static_cast<Block*>(alloc(sizeof(Block)));
        if (!block) {
            mark_overflow();
            return;
        }
        block->next = nullptr;
        block->first = 0;
        block->end = 0;
        if (tail_)
            tail_->next = block;
        else
            head_ = block;
        tail_ = block;
    }
    auto& entry = tail_->entries[tail_->end++];
    constexpr size_t alignment = sizeof(InotifyEventHeader);
    const auto padded = name_length ? uint32_t((name_length + alignment) & ~(alignment - 1)) : 0;
    entry.header = {wd, mask, cookie, padded};
    entry.name[0] = 0;
    if (padded) {
        memcpy(entry.name, name, name_length);
        memset(entry.name + name_length, 0, padded - name_length);
    }
    bytes_ += entry.size();
    ++events_;
}

void InotifyQueue::pop() {
    const auto* event = front();
    if (!event)
        return;
    bytes_ -= event->size();
    if (event == &overflow_event) {
        overflow_ = false;
        return;
    }
    --events_;
    if (overflow_)
        --before_overflow_;
    if (++head_->first == head_->end) {
        auto* consumed = head_;
        head_ = head_->next;
        if (!head_)
            tail_ = nullptr;
        release(consumed);
    }
}

void InotifyQueue::clear() {
    while (head_) {
        auto* block = head_;
        head_ = block->next;
        release(block);
    }
    *this = {};
}
} // namespace ax
