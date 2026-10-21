// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/path_mtu.hpp"

namespace ax::ip6 {
namespace {
bool valid(const PathKey& key, uint32_t mtu) {
    auto unicast = [](const Address& address) {
        return !address.unspecified() && !address.multicast() && !address.mapped();
    };
    return key.index && key.route_owner && unicast(key.source) && unicast(key.destination) &&
           unicast(key.next_hop) && mtu >= minimum_mtu && mtu <= 65535;
}
} // namespace

PathMtuCache::Entry* PathMtuCache::find(const PathKey& key, uint64_t now) {
    Entry* found = nullptr;
    for (auto& entry : entries) {
        if (entry.mtu && now >= entry.expires)
            entry = {};
        if (entry.mtu && entry.key == key)
            found = &entry;
    }
    return found;
}

uint32_t PathMtuCache::lookup(const PathKey& key, uint32_t device_mtu, uint64_t now) {
    if (valid(key, device_mtu))
        if (auto entry = find(key, now)) {
            if (now > entry->touched)
                entry->touched = now;
            return entry->mtu < device_mtu ? entry->mtu : device_mtu;
        }
    return device_mtu;
}

uint32_t PathMtuCache::learn(const PathKey& key, uint32_t device_mtu, uint32_t announced,
                             uint64_t now) {
    if (!valid(key, device_mtu))
        return device_mtu;
    auto entry = find(key, now);
    uint32_t current = entry && entry->mtu < device_mtu ? entry->mtu : device_mtu;
    // A sub-minimum report cannot reduce IPv6's minimum link MTU. Equal and
    // increasing reports cannot keep an old exception alive indefinitely.
    if (announced < minimum_mtu || announced >= current)
        return current;
    if (!entry) {
        for (auto& candidate : entries)
            if (!candidate.mtu) {
                entry = &candidate;
                break;
            }
        if (!entry) {
            entry = &entries[0];
            for (auto& candidate : entries)
                if (candidate.touched < entry->touched)
                    entry = &candidate;
        }
    }
    uint64_t expires = now > UINT64_MAX - path_mtu_lifetime ? UINT64_MAX : now + path_mtu_lifetime;
    *entry = {key, announced, expires, now};
    return announced;
}

void PathMtuCache::update_mtu(unsigned index, uint32_t previous, uint32_t current) {
    for (auto& entry : entries) {
        if (!entry.mtu || entry.key.index != index)
            continue;
        if (current < minimum_mtu)
            entry = {};
        else if (entry.mtu > current || entry.mtu == previous)
            entry.mtu = current;
    }
}

void PathMtuCache::discard() {
    for (auto& entry : entries)
        entry = {};
}

void PathMtuCache::discard_route(uint64_t owner) {
    for (auto& entry : entries)
        if (owner && entry.key.route_owner == owner)
            entry = {};
}

void PathMtuCache::discard_source(const Address& source, unsigned index) {
    for (auto& entry : entries)
        if ((!index || entry.key.index == index) && entry.key.source == source)
            entry = {};
}
} // namespace ax::ip6
