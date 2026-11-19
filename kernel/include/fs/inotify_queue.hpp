// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/inotify_queue.hpp
 * @brief   Inotify event queue interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the queued record layout and the operations used to append and drain
 * filesystem events.
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
constexpr uint32_t inotify_queue_overflow = 0x00004000;
constexpr uint32_t inotify_watch_ignored = 0x00008000;

struct InotifyEventHeader {
    int32_t wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};

static_assert(sizeof(InotifyEventHeader) == 16);

struct InotifyEvent {
    InotifyEventHeader header;
    char name[256];

    size_t size() const {
        return sizeof(header) + header.len;
    }
};

static_assert(offsetof(InotifyEvent, name) == sizeof(InotifyEventHeader));

class InotifyQueue {
  public:
    static constexpr size_t capacity = 16384;

    const InotifyEvent* front() const;

    size_t bytes() const {
        return bytes_;
    }

    void push(int32_t wd, uint32_t mask, uint32_t cookie, const char* name);
    void pop();
    void clear();

  private:
    struct Block;
    Block* head_ = nullptr;
    Block* tail_ = nullptr;
    size_t events_ = 0;
    size_t bytes_ = 0;
    bool overflow_ = false;
    // Keep the overflow record in order without allocating memory for it.
    size_t before_overflow_ = 0;

    void mark_overflow();
};
} // namespace ax
