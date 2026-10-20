// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/reassembly.hpp"

namespace ax {
namespace {
struct AddressSlot {
    Ipv6Address value;
    uint64_t due = 0;
    bool sent = false;
};

AddressSlot addresses[ipv6_address_capacity];
unsigned address_count;

bool ready(const Ipv6Address& entry) {
    return !(entry.flags & (0x40 | 8));
}

const Ipv6Address& loopback() {
    static Ipv6Address entry;
    entry.address.bytes[15] = 1;
    entry.index = ipv6_loopback;
    entry.flags = 0x80;
    entry.prefix = 128;
    return entry;
}

const Ipv6Address* source_for(unsigned index, const ip6::Address& destination) {
    const Ipv6Address* best = nullptr;
    for (unsigned n = 0; auto entry = ipv6_address(n); n++) {
        if (entry->index != index || !ready(*entry) ||
            (destination.link_local() && !entry->address.link_local()) ||
            (!destination.link_local() && !destination.multicast() && entry->address.link_local()))
            continue;
        if (!best || (destination.matches(entry->address, entry->prefix) &&
                      !destination.matches(best->address, best->prefix)))
            best = entry;
    }
    return best;
}
} // namespace

const Ipv6Address* ipv6_address(unsigned position) {
    if (!position)
        return &loopback();
    return --position < address_count ? &addresses[position].value : nullptr;
}

int ipv6_address_add(const Ipv6Address& value) {
    if (!net_info(value.index))
        return -19;
    if (value.prefix > 128 || value.address.unspecified() || value.address.multicast() ||
        value.address.loopback() || value.address.mapped())
        return -22;
    if (value.flags & ~uint16_t(0x80 | 2 | 0x200))
        return -95;
    if (net_info(value.index)->mtu < ip6::minimum_mtu)
        return -22;
    for (unsigned n = 0; n < address_count; n++)
        if (addresses[n].value.index == value.index && addresses[n].value.address == value.address)
            return -17;
    if (address_count == ipv6_address_capacity)
        return -105;
    int error = ip6::prefix_add(value);
    if (error)
        return error;
    auto& entry = addresses[address_count++];
    entry = {};
    entry.value = value;
    entry.value.flags |= 0x80;
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
            if (address.link_local() || !ipv6_owned(0, address))
                ip6::reassembly_discard(&address, index);
            return 0;
        }
    return -99;
}

bool ipv6_owned(unsigned index, const ip6::Address& address, bool tentative) {
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if ((!index || entry->index == index) && entry->address == address && !(entry->flags & 8) &&
            (tentative || ready(*entry)))
            return true;
    return false;
}

int ipv6_path(const ip6::Address& requested, const ip6::Address& destination, unsigned bound,
              Ipv6Path& path) {
    if (destination.unspecified() || destination.mapped())
        return -101;
    if (bound && bound != ipv6_loopback && !net_info(bound))
        return -19;
    bool local = ipv6_owned(destination.link_local() ? bound : 0, destination);
    if (local && (!destination.link_local() || bound)) {
        auto source = requested.unspecified() ? destination : requested;
        if (!ipv6_owned(0, source))
            return -99;
        if ((source.loopback() || destination.loopback()) && bound && bound != ipv6_loopback)
            return -101;
        path = {source, destination, ipv6_loopback, 65536};
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
    } else if (!ipv6_owned(source.link_local() ? best->index : 0, source))
        return -99;
    path = {source, best->gateway.unspecified() ? destination : best->gateway, best->index,
            net_info(best->index)->mtu};
    return 0;
}

namespace ip6 {
bool usable(unsigned index) {
    if (index == ipv6_loopback)
        return true;
    auto info = net_info(index);
    return info && info->live && info->administrative && info->carrier && info->mtu >= minimum_mtu;
}

void address_poll() {
    for (unsigned n = 0; n < address_count; n++) {
        auto& entry = addresses[n];
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
    for (auto& entry : addresses)
        entry = {};
    address_count = 0;
    route_reset();
}
} // namespace ip6
} // namespace ax
