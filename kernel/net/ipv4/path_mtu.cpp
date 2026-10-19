// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/path_mtu.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::ip4 {
namespace {
bool valid(const PathKey& key, uint32_t mtu) {
    return key.index && unicast(key.source) && unicast(key.destination) && unicast(key.next_hop) &&
           mtu >= 68 && mtu <= 65535;
}

PathMtu bounded(uint32_t device, uint32_t learned, bool locked, uint64_t expires) {
    return {device < learned ? device : learned, locked, expires};
}
} // namespace

PathMtuCache::Entry* PathMtuCache::find(const PathKey& key, uint64_t now) {
    Entry* found = nullptr;
    for (auto& entry : entries) {
        if (entry.key.source && now >= entry.expires)
            entry = {};
        if (entry.key.source && entry.key == key)
            found = &entry;
    }
    return found;
}

PathMtu PathMtuCache::lookup(const PathKey& key, uint32_t device_mtu, uint64_t now) {
    if (valid(key, device_mtu))
        if (auto entry = find(key, now)) {
            if (now > entry->touched)
                entry->touched = now;
            return bounded(device_mtu, entry->mtu, entry->locked, entry->expires);
        }
    return {device_mtu};
}

PathMtu PathMtuCache::learn(const PathKey& key, uint32_t device_mtu, uint16_t announced_mtu,
                            uint16_t quoted_length, uint64_t now, bool* updated) {
    if (updated)
        *updated = false;
    if (!valid(key, device_mtu))
        return {device_mtu};
    auto entry = find(key, now);
    auto current = entry ? bounded(device_mtu, entry->mtu, entry->locked, entry->expires)
                         : PathMtu{device_mtu};
    if (current.locked || quoted_length < 28 ||
        (announced_mtu && (announced_mtu >= quoted_length || announced_mtu > current.mtu)))
        return current;
    bool locked = announced_mtu < path_mtu_floor;
    uint32_t mtu =
        locked ? (current.mtu < path_mtu_floor ? current.mtu : path_mtu_floor) : announced_mtu;
    // Equal reports refresh only in the second half of the original lifetime.
    // Invalid/increasing reports and ordinary lookups never refresh it.
    if (entry && mtu == entry->mtu && !locked && entry->expires - now > path_mtu_lifetime / 2)
        return current;
    if (!entry) {
        for (auto& candidate : entries)
            if (!candidate.key.source) {
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
    *entry = {key, mtu, locked, expires, now};
    if (updated)
        *updated = true;
    return {mtu, locked, expires};
}

void PathMtuCache::update_mtu(unsigned index, uint32_t previous, uint32_t current) {
    if (!index || previous < 68 || previous > 65535 || current < 68 || current > 65535 ||
        previous == current)
        return;
    for (auto& entry : entries) {
        if (entry.key.index != index)
            continue;
        if (entry.locked) {
            if (current <= entry.mtu) {
                entry.mtu = current;
                entry.locked = false;
            }
        } else if (entry.mtu > current || entry.mtu == previous)
            entry.mtu = current;
    }
}

void PathMtuCache::discard(unsigned index) {
    for (auto& entry : entries)
        if (!index || entry.key.index == index)
            entry = {};
}

void PathMtuCache::discard_route(uint64_t route_owner) {
    for (auto& entry : entries)
        if (route_owner && entry.key.route_owner == route_owner)
            entry = {};
}

void PathMtuCache::discard_source(unsigned index, uint32_t preferred_source) {
    for (auto& entry : entries)
        if (entry.key.index == index && entry.key.source == preferred_source)
            entry = {};
}
} // namespace ax::ip4
