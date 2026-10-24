// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "../socket.hpp"
#include "process/task.hpp"

namespace ax {
class Inet6ControlWriter {
  public:
    Inet6ControlWriter(Task& owner, uint64_t pointer, uint64_t limit, uint32_t& result)
        : task(owner), address(pointer), capacity(limit), flags(result) {
    }

    void append(uint32_t type, const void* bytes, size_t size);
    void metadata(const Inet6Socket*, const ip6::Address& destination, unsigned index, uint8_t hops,
                  uint8_t traffic_class);
    void extensions(const Inet6Socket*, const uint8_t*, size_t length, uint8_t protocol);
    void legacy_metadata(const Inet6Socket*, uint8_t hops);

    uint64_t used = 0;

  private:
    Task& task;
    uint64_t address, capacity;
    uint32_t& flags;
};
} // namespace ax
