// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/reassembly.hpp"

namespace ax {
ip6::PathMtuCache ip6::path_mtu_cache;

namespace {
struct AddressSlot {
    Ipv6Address value;
    Ipv6AddressLifetimes lifetime;
    uint64_t created = 0, updated = 0;
    uint64_t due = 0;
    bool sent = false;
};

AddressSlot addresses[ipv6_address_capacity];
unsigned address_count;

bool ready(const Ipv6Address& entry) {
    return !(entry.flags & (0x40 | 8)) && ((entry.flags & 0x80) || ipv6_address_cache(entry).valid);
}

uint32_t remaining(uint32_t lifetime, uint64_t age) {
    return lifetime == UINT32_MAX ? UINT32_MAX : age >= lifetime ? 0 : lifetime - age;
}

uint16_t configured_flags(const Ipv6Address& value, Ipv6AddressLifetimes lifetime) {
    return (value.flags & (2 | 0x200)) | (lifetime.valid == UINT32_MAX ? 0x80 : 0) |
           (lifetime.preferred ? 0 : 0x20);
}

const Ipv6Address& loopback() {
    static Ipv6Address entry;
    entry.address.bytes[15] = 1;
    entry.index = ipv6_loopback;
    entry.flags = 0x80;
    entry.prefix = 128;
    return entry;
}

unsigned matching_prefix(const Ipv6Address& entry, const ip6::Address& destination) {
    unsigned matched = 0, limit = entry.prefix;
    for (unsigned at = 0; matched < limit; at++) {
        unsigned difference = entry.address.bytes[at] ^ destination.bytes[at];
        if (difference)
            return min(limit, matched + unsigned(__builtin_clz(difference) - 24));
        matched += min(8u, limit - matched);
    }
    return matched;
}

unsigned address_scope(const ip6::Address& address) {
    if (address.multicast())
        return address.bytes[1] & 15;
    if (address.loopback())
        return 1;
    if (address.link_local())
        return 2;
    if (address.bytes[0] == 0xfe && (address.bytes[1] & 0xc0) == 0xc0)
        return 5;
    return 14;
}

unsigned address_label(const ip6::Address& address) {
    const auto* bytes = address.bytes;
    if (address.loopback())
        return 0;
    bool compatible = true;
    for (unsigned n = 0; n < 12; n++)
        compatible &= !bytes[n];
    if (compatible)
        return 3;
    if ((bytes[0] & 0xfe) == 0xfc)
        return 5;
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0)
        return 11;
    if (bytes[0] == 0x20 && bytes[1] == 2)
        return 2;
    if (bytes[0] == 0x3f && bytes[1] == 0xfe)
        return 12;
    if (bytes[0] == 0x20 && bytes[1] == 1 && !bytes[2]) {
        if (!bytes[3])
            return 6;
        if ((bytes[3] & 0xf0) == 0x10)
            return 7;
    }
    return 1;
}

unsigned source_rank(const Ipv6Address& entry, unsigned index, const ip6::Address& destination) {
    unsigned scope = address_scope(entry.address);
    unsigned source_label = address_label(entry.address),
             destination_label = address_label(destination);
    // Adequate scope wins; then choose the smallest adequate or largest
    // inadequate scope. Later fields cannot override an earlier rule.
    unsigned rank = scope >= address_scope(destination) ? 32 - scope : scope;
    // Linux keeps IPv4-compatible candidates preferred even when deprecated.
    rank = rank * 2 + (!(entry.flags & 0x20) || source_label == 3);
    rank = rank * 2 + (entry.index == index);
    rank = rank * 2 + (source_label == destination_label);
    rank = rank * 2 + ((source_label == 7) == (destination_label == 7));
    return rank * 129 + matching_prefix(entry, destination);
}

const Ipv6Address* source_for(unsigned index, const ip6::Address& destination) {
    const Ipv6Address* best = nullptr;
    unsigned best_rank = 0;
    for (unsigned n = 0; auto entry = ipv6_address(n); n++) {
        if (!ready(*entry) || entry->address.loopback() ||
            ((destination.link_local() || destination.multicast()) && entry->index != index))
            continue;
        unsigned rank = source_rank(*entry, index, destination);
        if (!best || rank > best_rank || (rank == best_rank && entry->index <= best->index)) {
            best = entry;
            best_rank = rank;
        }
    }
    return best;
}
} // namespace

const Ipv6Address* ipv6_address(unsigned position) {
    if (!position)
        return &loopback();
    return --position < address_count ? &addresses[position].value : nullptr;
}

Ipv6AddressCacheInfo ipv6_address_cache(const Ipv6Address& value) {
    if (value.index == ipv6_loopback && value.address.loopback())
        return {};
    for (unsigned n = 0; n < address_count; n++) {
        const auto& entry = addresses[n];
        if (entry.value.index == value.index && entry.value.address == value.address) {
            uint64_t age = ticks >= entry.updated ? (ticks - entry.updated) / 100 : 0;
            return {remaining(entry.lifetime.preferred, age), remaining(entry.lifetime.valid, age),
                    uint32_t(entry.created), uint32_t(entry.updated)};
        }
    }
    return {0, 0, 0, 0};
}

int ipv6_address_add(const Ipv6Address& value, Ipv6AddressLifetimes lifetime, bool replace) {
    if (!lifetime.valid || lifetime.preferred > lifetime.valid)
        return -22;
    if (!net_info(value.index))
        return -19;
    if (value.prefix > 128 || value.address.unspecified() || value.address.multicast() ||
        value.address.loopback() || value.address.mapped())
        return -22;
    if (value.flags & ~uint16_t(0x80 | 2 | 0x200))
        return -95;
    if (net_info(value.index)->mtu < ip6::minimum_mtu)
        return -22;
    for (unsigned n = 0; n < address_count; n++) {
        auto& entry = addresses[n];
        if (entry.value.index != value.index || !(entry.value.address == value.address))
            continue;
        if (!replace)
            return -17;
        Ipv6Address updated = entry.value;
        updated.flags = (entry.value.flags & (0x40 | 8)) | configured_flags(value, lifetime);
        if (!(updated.flags & 0x200)) {
            int error = ip6::prefix_add(updated, lifetime.valid,
                                        (entry.value.flags & 0x80) && !(entry.value.flags & 0x200));
            if (error)
                return error;
        } else if ((entry.value.flags & 0x80) && !(entry.value.flags & 0x200))
            ip6::prefix_remove(entry.value);
        entry.value = updated;
        entry.lifetime = lifetime;
        entry.updated = ticks;
        return 0;
    }
    if (address_count == ipv6_address_capacity)
        return -105;
    int error = ip6::prefix_add(value, lifetime.valid);
    if (error)
        return error;
    auto& entry = addresses[address_count++];
    entry = {};
    entry.value = value;
    entry.value.flags = configured_flags(value, lifetime);
    entry.lifetime = lifetime;
    entry.created = entry.updated = ticks;
    if (!(value.flags & 2))
        entry.value.flags |= 0x40;
    return 0;
}

int ipv6_address_remove(unsigned index, const ip6::Address& address) {
    for (unsigned n = 0; n < address_count; n++)
        if (addresses[n].value.index == index && addresses[n].value.address == address) {
            ip6::prefix_remove(addresses[n].value);
            for (unsigned next = n + 1; next < address_count; next++)
                addresses[next - 1] = addresses[next];
            addresses[--address_count] = {};
            if (address.link_local() || !ipv6_owned(0, address)) {
                ip6::reassembly_discard(&address, index);
                ip6::path_mtu_cache.discard_source(address, address.link_local() ? index : 0);
            }
            return 0;
        }
    return -99;
}

bool ipv6_owned(unsigned index, const ip6::Address& address, bool tentative) {
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if ((!index || entry->index == index) && entry->address == address && !(entry->flags & 8) &&
            (tentative || ready(*entry)) &&
            ((entry->flags & 0x80) || ipv6_address_cache(*entry).valid))
            return true;
    return false;
}

int ipv6_path(const ip6::Address& requested, const ip6::Address& destination, unsigned bound,
              Ipv6Path& path, bool interface_mtu, Ipv6SourcePolicy source_policy) {
    if (destination.unspecified() || destination.mapped())
        return -101;
    if (bound && bound != ipv6_loopback && !net_info(bound))
        return -19;
    bool local = ipv6_owned(destination.link_local() ? bound : 0, destination);
    if (local && (!destination.link_local() || bound)) {
        auto source = requested.unspecified() ? destination : requested;
        if (source_policy == Ipv6SourcePolicy::assigned && !ipv6_owned(0, source))
            return -99;
        if ((source.loopback() || destination.loopback()) && bound && bound != ipv6_loopback)
            return -101;
        path = {source, destination, ipv6_loopback, 65536, 0, 128};
        return 0;
    }
    if (destination.loopback() || requested.loopback())
        return -101;
    Ipv6Route inventory[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(inventory, sizeof(inventory) / sizeof(*inventory));
    const Ipv6Route* best = nullptr;
    for (size_t n = 0; n < count; n++) {
        const auto& candidate = inventory[n];
        if ((bound && candidate.index != bound) || !ip6::usable(candidate.index) ||
            (candidate.expires && ticks >= candidate.expires) ||
            !destination.matches(candidate.destination, candidate.prefix))
            continue;
        if (!best || candidate.prefix > best->prefix ||
            (candidate.prefix == best->prefix && candidate.metric < best->metric))
            best = &candidate;
    }
    if (!best)
        return -101;
    auto source = requested;
    if (source.unspecified()) {
        auto selected = source_for(best->index, destination);
        if (!selected)
            return -99;
        source = selected->address;
    } else if (source_policy == Ipv6SourcePolicy::assigned &&
               !ipv6_owned(source.link_local() ? best->index : 0, source))
        return -99;
    path = {source,      best->gateway.unspecified() ? destination : best->gateway,
            best->index, net_info(best->index)->mtu,
            best->owner, best->prefix};
    if (!interface_mtu)
        path.mtu = ip6::path_mtu_cache.lookup(ip6::path_key(path, destination), path.mtu, ticks);
    return 0;
}

void ipv6_mtu_changed(unsigned index, uint32_t previous) {
    if (auto info = net_info(index))
        ip6::path_mtu_cache.update_mtu(index, previous, info->mtu);
}

namespace ip6 {
uint64_t address_deadline(const Ipv6Address& value) {
    for (unsigned n = 0; n < address_count; n++) {
        const auto& entry = addresses[n];
        if (entry.value.index == value.index && entry.value.address == value.address)
            return entry.lifetime.valid == UINT32_MAX
                       ? 0
                       : entry.updated + uint64_t(entry.lifetime.valid) * 100;
    }
    return ticks;
}

bool usable(unsigned index) {
    if (index == ipv6_loopback)
        return true;
    auto info = net_info(index);
    return info && info->live && info->administrative && info->carrier && info->mtu >= minimum_mtu;
}

void address_poll() {
    for (unsigned n = 0; n < address_count;) {
        auto& entry = addresses[n];
        uint64_t age = ticks >= entry.updated ? (ticks - entry.updated) / 100 : 0;
        if (!remaining(entry.lifetime.valid, age)) {
            auto value = entry.value;
            ipv6_address_remove(value.index, value.address);
            continue;
        }
        if (!remaining(entry.lifetime.preferred, age))
            entry.value.flags |= 0x20;
        n++;
        if (!(entry.value.flags & 0x40) || (entry.value.flags & 8))
            continue;
        if (!usable(entry.value.index)) {
            entry.sent = false;
            continue;
        }
        if (entry.sent) {
            if (ticks >= entry.due)
                entry.value.flags &= ~uint16_t(0x40);
        } else if (!dad_probe(entry.value) && (entry.value.flags & 0x40)) {
            entry.sent = true;
            entry.due = ticks + 100;
        }
    }
}

void address_duplicate(unsigned index, const Address& address) {
    for (unsigned n = 0; n < address_count; n++) {
        auto& entry = addresses[n].value;
        if (entry.index == index && entry.address == address && (entry.flags & 0x40)) {
            entry.flags |= 8;
            log("IPv6 duplicate address index=%u\n", uint64_t(index));
        }
    }
}

void address_reset() {
    path_mtu_cache.discard();
    for (auto& entry : addresses)
        entry = {};
    address_count = 0;
    route_reset();
}
} // namespace ip6
} // namespace ax
