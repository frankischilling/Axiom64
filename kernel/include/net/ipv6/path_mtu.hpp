// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
constexpr unsigned path_mtu_capacity = 64;
constexpr uint64_t path_mtu_lifetime = 60000; // Ten minutes at 100 Hz.

struct PathKey {
    Address source, destination, next_hop;
    unsigned index = 0;
    uint64_t route_owner = 0;
    bool operator==(const PathKey&) const = default;
};

// The receiver validates the enclosing checksum and transport ownership.
// Entries own no packet or socket storage. Reads never extend a deadline.
class PathMtuCache {
  public:
    uint32_t lookup(const PathKey&, uint32_t device_mtu, uint64_t now);
    uint32_t learn(const PathKey&, uint32_t device_mtu, uint32_t announced, uint64_t now);
    void update_mtu(unsigned index, uint32_t previous, uint32_t current);
    void discard();
    void discard_route(uint64_t owner);
    void discard_source(const Address&, unsigned index = 0);

  private:
    struct Entry {
        PathKey key;
        uint32_t mtu = 0;
        uint64_t expires = 0, touched = 0;
    } entries[path_mtu_capacity]{};

    Entry* find(const PathKey&, uint64_t now);
};
} // namespace ax::ip6
