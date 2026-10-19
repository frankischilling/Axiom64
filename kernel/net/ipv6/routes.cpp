// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"

namespace ax {
namespace {
Ipv6Route routes[ipv6_route_capacity], prefixes[ipv6_address_capacity];
unsigned route_count, prefix_count;

void erase(Ipv6Route* entries, unsigned& count, unsigned position) {
    for (unsigned next = position + 1; next < count; next++)
        entries[next - 1] = entries[next];
    entries[--count] = {};
}

template <class Predicate> bool erase_lowest_metric(Predicate matches) {
    Ipv6Route* selected = nullptr;
    unsigned* count = nullptr;
    unsigned position = 0;
    auto consider = [&](Ipv6Route* entries, unsigned& length) {
        for (unsigned n = 0; n < length; n++)
            if (matches(entries[n]) &&
                (!selected || entries[n].metric < selected[position].metric)) {
                selected = entries;
                count = &length;
                position = n;
            }
    };
    consider(routes, route_count);
    consider(prefixes, prefix_count);
    if (!selected)
        return false;
    erase(selected, *count, position);
    return true;
}

Ipv6Route prefix_for(const Ipv6Address& value) {
    auto destination = value.address;
    for (unsigned bit = value.prefix; bit < 128; bit++)
        destination.bytes[bit / 8] &= ~(1u << (7 - bit % 8));
    return {destination, {}, value.index, 256, value.prefix, 2};
}

bool same_prefix(const Ipv6Route& a, const Ipv6Route& b) {
    return a.index == b.index && a.prefix == b.prefix && a.destination == b.destination;
}
} // namespace

int ipv6_route_control(const Ipv6Route& requested, bool remove, bool exclusive) {
    auto route = requested;
    if (!net_info(route.index))
        return -19;
    if (route.prefix > 128 || route.destination.multicast() || route.gateway.multicast() ||
        route.gateway.loopback() || route.gateway.mapped())
        return -22;
    for (unsigned bit = route.prefix; bit < 128; bit++)
        route.destination.bytes[bit / 8] &= ~(1u << (7 - bit % 8));
    if (!remove) {
        if (!exclusive)
            return -95;
        if (!route.protocol)
            route.protocol = 3;
        if (!route.metric)
            route.metric = 1024;
        if (!route.gateway.unspecified()) {
            for (unsigned n = 0; auto entry = ipv6_address(n); n++)
                if (entry->address == route.gateway &&
                    (!route.gateway.link_local() || entry->index == route.index))
                    return -22;
            if (!route.gateway.link_local()) {
                Ipv6Route inventory[ipv6_route_capacity + ipv6_address_capacity + 1];
                size_t count = ipv6_routes(inventory, sizeof(inventory) / sizeof(*inventory));
                const Ipv6Route* best = nullptr;
                for (size_t n = 0; n < count; n++) {
                    const auto& candidate = inventory[n];
                    if (candidate.index != route.index ||
                        !route.gateway.matches(candidate.destination, candidate.prefix))
                        continue;
                    if (!best || candidate.prefix > best->prefix ||
                        (candidate.prefix == best->prefix && candidate.metric < best->metric))
                        best = &candidate;
                }
                if (!best || !best->gateway.unspecified())
                    return -113;
            }
        }
    }
    if (!remove) {
        Ipv6Route inventory[ipv6_route_capacity + ipv6_address_capacity + 1];
        size_t count = ipv6_routes(inventory, sizeof(inventory) / sizeof(*inventory));
        for (size_t n = 0; n < count; n++)
            if (inventory[n].index != ipv6_loopback && inventory[n].prefix == route.prefix &&
                inventory[n].metric == route.metric &&
                inventory[n].destination.matches(route.destination, route.prefix))
                return -17;
    }
    if (remove) {
        bool erased = erase_lowest_metric([&](const Ipv6Route& current) {
            return same_prefix(route, current) &&
                   (!route.metric || current.metric == route.metric) &&
                   (!route.protocol || current.protocol == route.protocol) &&
                   (route.gateway.unspecified() || route.gateway == current.gateway);
        });
        return erased ? 0 : -3;
    }
    if (route_count == ipv6_route_capacity)
        return -105;
    routes[route_count++] = route;
    return 0;
}

size_t ipv6_routes(Ipv6Route* output, size_t capacity) {
    size_t count = 0;
    for (unsigned n = 0; n < route_count && count < capacity; n++)
        output[count++] = routes[n];
    for (unsigned n = 0; n < prefix_count && count < capacity; n++)
        output[count++] = prefixes[n];
    if (count < capacity) {
        ip6::Address loopback;
        loopback.bytes[15] = 1;
        output[count++] = {loopback, {}, ipv6_loopback, 256, 128, 2};
    }
    return count;
}

namespace ip6 {
int prefix_add(const Ipv6Address& value) {
    if (value.flags & 0x200)
        return 0;
    auto prefix = prefix_for(value);
    for (unsigned n = 0; n < prefix_count; n++)
        if (same_prefix(prefix, prefixes[n]))
            return 0;
    for (unsigned n = 0; n < route_count; n++)
        if (same_prefix(prefix, routes[n]) && routes[n].metric == 256 &&
            routes[n].gateway.unspecified())
            return 0;
    if (prefix_count == ipv6_address_capacity)
        return -105;
    prefixes[prefix_count++] = prefix;
    return 0;
}

void prefix_remove(const Ipv6Address& value) {
    if (value.flags & 0x200)
        return;
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if (entry != &value && entry->index == value.index && entry->prefix == value.prefix &&
            entry->address.matches(value.address, value.prefix))
            return;
    auto prefix = prefix_for(value);
    erase_lowest_metric([&](const Ipv6Route& route) {
        return same_prefix(prefix, route) && route.gateway.unspecified();
    });
}

void route_reset() {
    for (auto& route : routes)
        route = {};
    for (auto& prefix : prefixes)
        prefix = {};
    route_count = prefix_count = 0;
}
} // namespace ip6
} // namespace ax
