// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "../socket.hpp"
#include "net/socket_control.hpp"

namespace ax {
class Inet6ControlWriter : public SocketControlWriter {
  public:
    Inet6ControlWriter(Task& owner, uint64_t pointer, uint64_t limit, uint32_t& result)
        : SocketControlWriter(owner, 41, pointer, limit, result) {
    }

    void metadata(const Inet6Socket*, const ip6::Address& destination, unsigned index, uint8_t hops,
                  uint8_t traffic_class);
    void extensions(const Inet6Socket*, const uint8_t*, size_t length, uint8_t protocol);
    void legacy_metadata(const Inet6Socket*, uint8_t hops);
};
} // namespace ax
