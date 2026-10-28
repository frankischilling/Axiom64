// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

// A receive-control copy owns its cursor, commits only successful stores, and
// leaves alignment padding untouched. Failed copies consume no capacity.
class SocketControlWriter {
  public:
    SocketControlWriter(Task& owner, uint32_t protocol_level, uint64_t pointer, uint64_t limit,
                        uint32_t& result)
        : task(owner), level(protocol_level), address(pointer), capacity(limit), flags(result) {
    }

    void append(uint32_t type, const void* bytes, size_t size);

    uint64_t used = 0;

  private:
    Task& task;
    uint32_t level;
    uint64_t address, capacity;
    uint32_t& flags;
};
} // namespace ax
