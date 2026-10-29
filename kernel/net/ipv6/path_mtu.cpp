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

void PathMtuCache::drop(unsigned number) {
    if (number && number <= path_mtu_capacity + path_mtu_reference_capacity) {
        auto& value = metrics[number - 1];
        if (value.references && !--value.references)
            value = {};
    }
}

void PathMtuCache::retire(Entry& entry) {
    drop(entry.metric);
    entry = {};
}

const PathMtuCache::Reference* PathMtuCache::reference(const PathMtuReference& value) const {
    if (value.owner != this || !value.slot || value.slot > path_mtu_reference_capacity)
        return nullptr;
    const auto& held = references[value.slot - 1];
    return held.metric && held.generation == value.generation ? &held : nullptr;
}

PathMtuReference PathMtuCache::retain(const PathKey& key, uint64_t now) {
    auto entry = find(key, now);
    if (!entry)
        return {};
    for (unsigned n = 0; n < path_mtu_reference_capacity; n++) {
        auto& held = references[n];
        if (!held.metric && held.generation != UINT64_MAX) {
            held.generation++;
            held.metric = entry->metric;
            metrics[held.metric - 1].references++;
            return {this, n + 1, held.generation};
        }
    }
    return {};
}

void PathMtuCache::release(PathMtuReference& value) {
    if (auto held = reference(value)) {
        drop(held->metric);
        references[value.slot - 1].metric = 0;
    }
    value = {};
}

uint32_t PathMtuCache::metric(const PathMtuReference& value) const {
    auto held = reference(value);
    return held ? metrics[held->metric - 1].mtu : 0;
}

bool PathMtuCache::active(const PathMtuReference& value, const PathKey& key, uint64_t now) {
    auto held = reference(value);
    auto entry = find(key, now);
    return held && entry && held->metric == entry->metric;
}

PathMtuCache::Entry* PathMtuCache::find(const PathKey& key, uint64_t now) {
    Entry* found = nullptr;
    for (auto& entry : entries) {
        if (entry.mtu && now >= entry.expires)
            retire(entry);
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
    uint64_t expires = now > UINT64_MAX - path_mtu_lifetime ? UINT64_MAX : now + path_mtu_lifetime;
    if (entry && entry->expires < expires)
        expires = entry->expires;
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
        retire(*entry);
        for (unsigned n = 0; n < path_mtu_capacity + path_mtu_reference_capacity; n++)
            if (!metrics[n].references) {
                metrics[n] = {announced, 1};
                entry->metric = n + 1;
                break;
            }
        if (!entry->metric)
            return current;
    }
    metrics[entry->metric - 1].mtu = announced;
    *entry = {key, announced, expires, now, entry->metric};
    return announced;
}

void PathMtuCache::update_mtu(unsigned index, uint32_t previous, uint32_t current) {
    for (auto& entry : entries) {
        if (!entry.mtu || entry.key.index != index)
            continue;
        if (current < minimum_mtu)
            retire(entry);
        else if (entry.mtu > current || entry.mtu == previous) {
            entry.mtu = current;
            metrics[entry.metric - 1].mtu = current;
        }
    }
}

void PathMtuCache::discard() {
    for (auto& entry : entries)
        retire(entry);
}

void PathMtuCache::discard_route(uint64_t owner) {
    for (auto& entry : entries)
        if (owner && entry.key.route_owner == owner)
            retire(entry);
}

void PathMtuCache::discard_source(const Address& source, unsigned index) {
    for (auto& entry : entries)
        if ((!index || entry.key.index == index) && entry.key.source == source)
            retire(entry);
}
} // namespace ax::ip6
