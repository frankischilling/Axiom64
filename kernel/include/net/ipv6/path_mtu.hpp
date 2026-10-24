// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
constexpr unsigned path_mtu_capacity = 64;
constexpr unsigned path_mtu_reference_capacity = 256;
constexpr uint64_t path_mtu_lifetime = 60000; // Ten minutes at 100 Hz.

struct PathKey {
    Address source, destination, next_hop;
    unsigned index = 0;
    uint64_t route_owner = 0;
    bool operator==(const PathKey&) const = default;
};

class PathMtuCache;

struct PathMtuReference {
    const PathMtuCache* owner = nullptr;
    unsigned slot = 0;
    uint64_t generation = 0;

    explicit operator bool() const {
        return owner && slot && generation;
    }
};

// The receiver validates the enclosing checksum and transport ownership.
// Entries own no packet or socket storage. Reads never extend a deadline.
class PathMtuCache {
  public:
    PathMtuCache() = default;
    PathMtuCache(const PathMtuCache&) = delete;
    PathMtuCache& operator=(const PathMtuCache&) = delete;
    uint32_t lookup(const PathKey&, uint32_t device_mtu, uint64_t now);
    uint32_t learn(const PathKey&, uint32_t device_mtu, uint32_t announced, uint64_t now);
    // A retained destination metric can outlive its active output exception.
    // Each successful retain owns one reference until release clears it.
    PathMtuReference retain(const PathKey&, uint64_t now);
    void release(PathMtuReference&);
    uint32_t metric(const PathMtuReference&) const;
    bool active(const PathMtuReference&, const PathKey&, uint64_t now);
    void update_mtu(unsigned index, uint32_t previous, uint32_t current);
    void discard();
    void discard_route(uint64_t owner);
    void discard_source(const Address&, unsigned index = 0);

  private:
    struct Entry {
        PathKey key;
        uint32_t mtu = 0;
        uint64_t expires = 0, touched = 0;
        unsigned metric = 0;
    } entries[path_mtu_capacity]{};

    struct Metric {
        uint32_t mtu = 0;
        unsigned references = 0;
    } metrics[path_mtu_capacity + path_mtu_reference_capacity]{};

    struct Reference {
        uint64_t generation = 0;
        unsigned metric = 0;
    } references[path_mtu_reference_capacity]{};

    Entry* find(const PathKey&, uint64_t now);
    const Reference* reference(const PathMtuReference&) const;
    void retire(Entry&);
    void drop(unsigned metric);
};
} // namespace ax::ip6
