// SPDX-License-Identifier: GPL-3.0-or-later
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
