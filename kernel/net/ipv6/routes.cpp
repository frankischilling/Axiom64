// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"

namespace ax {
namespace {
Ipv6Route routes[ipv6_route_capacity], prefixes[ipv6_address_capacity];
unsigned route_count, prefix_count;
uint64_t next_owner;
uint64_t next_gc;

uint64_t owner() {
    if (!++next_owner)
        ++next_owner;
    return next_owner;
}

void erase(Ipv6Route* entries, unsigned& count, unsigned position) {
    ip6::path_mtu_cache.discard_route(entries[position].owner);
    for (unsigned next = position + 1; next < count; next++)
        entries[next - 1] = entries[next];
    entries[--count] = {};
}

struct Selection {
    Ipv6Route* entries = nullptr;
    unsigned* count = nullptr;
    unsigned position = 0;
};

template <class Predicate> Selection lowest_metric(Predicate matches) {
    Selection selected;
    auto consider = [&](Ipv6Route* entries, unsigned& length) {
        for (unsigned n = 0; n < length; n++)
            if (matches(entries[n]) &&
                (!selected.entries ||
                 entries[n].metric < selected.entries[selected.position].metric)) {
                selected = {entries, &length, n};
            }
    };
    consider(routes, route_count);
    consider(prefixes, prefix_count);
    return selected;
}

template <class Predicate> bool erase_lowest_metric(Predicate matches) {
    auto selected = lowest_metric(matches);
    if (!selected.entries)
        return false;
    erase(selected.entries, *selected.count, selected.position);
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
    if (!remove && ip6::configuration_disabled(route.index))
        return -13;
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
                        (candidate.expires && ticks >= candidate.expires) ||
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
    route.owner = owner();
    routes[route_count++] = route;
    return 0;
}

size_t ipv6_routes(Ipv6Route* output, size_t capacity) {
    size_t count = 0;
    auto append = [&](const Ipv6Route& route) {
        // Manual and advertised ownership remain separate. Their identical
        // connected prefix has one observable route with the longer lifetime.
        for (size_t n = 0; n < count; n++) {
            auto& current = output[n];
            if (route.learned == current.learned || route.protocol != 2 || current.protocol != 2 ||
                route.metric != current.metric || !route.gateway.unspecified() ||
                !current.gateway.unspecified() || !same_prefix(route, current))
                continue;
            if ((current.expires && (!route.expires || route.expires > current.expires)) ||
                (current.expires == route.expires && !route.learned))
                current = route;
            return;
        }
        if (count < capacity)
            output[count++] = route;
    };
    for (unsigned n = 0; n < route_count; n++)
        append(routes[n]);
    for (unsigned n = 0; n < prefix_count; n++)
        append(prefixes[n]);
    if (count < capacity && !ip6::configuration_disabled(ipv6_loopback)) {
        ip6::Address loopback;
        loopback.bytes[15] = 1;
        output[count++] = {loopback, {}, ipv6_loopback, 256, 128, 2};
    }
    return count;
}

namespace ip6 {
bool learned_route_present(uint64_t handle) {
    for (unsigned n = 0; n < route_count; n++)
        if (handle && routes[n].owner == handle)
            return true;
    return false;
}

int learned_route(const Ipv6Route& requested, uint64_t& handle, bool remove) {
    if (!net_info(requested.index))
        return -19;
    for (unsigned n = 0; n < route_count; n++) {
        auto& current = routes[n];
        if (!handle || current.owner != handle)
            continue;
        if (remove) {
            erase(routes, route_count, n);
            handle = 0;
            return 0;
        }
        if (current.index != requested.index || current.prefix != requested.prefix ||
            !(current.destination == requested.destination) ||
            !(current.gateway == requested.gateway))
            return -22;
        if (current.expires && ticks >= current.expires) {
            path_mtu_cache.discard_route(current.owner);
            handle = owner();
        }
        current = requested;
        current.owner = handle;
        current.learned = true;
        return 0;
    }
    handle = 0;
    if (remove)
        return 0;
    if (configuration_disabled(requested.index))
        return -13;
    if (route_count == ipv6_route_capacity)
        return -105;
    auto route = requested;
    route.owner = handle = owner();
    route.learned = true;
    routes[route_count++] = route;
    return 0;
}

int prefix_add(const Ipv6Address& value, uint32_t valid, bool replace_permanent) {
    if (value.flags & 0x200)
        return 0;
    auto prefix = prefix_for(value);
    prefix.expires = valid == UINT32_MAX ? 0 : ticks + uint64_t(valid) * 100;
    if (prefix.expires && !next_gc)
        next_gc = ticks + 3000;
    auto update = [&](Ipv6Route& current) {
        if (current.expires && ticks >= current.expires) {
            path_mtu_cache.discard_route(current.owner);
            current.owner = owner();
        }
        if (replace_permanent || current.expires)
            current.expires = prefix.expires;
    };
    for (unsigned n = 0; n < prefix_count; n++)
        if (same_prefix(prefix, prefixes[n])) {
            update(prefixes[n]);
            return 0;
        }
    for (unsigned n = 0; n < route_count; n++)
        if (!routes[n].learned && same_prefix(prefix, routes[n]) && routes[n].metric == 256 &&
            routes[n].gateway.unspecified()) {
            update(routes[n]);
            return 0;
        }
    if (prefix_count == ipv6_address_capacity)
        return -105;
    prefix.owner = owner();
    prefixes[prefix_count++] = prefix;
    return 0;
}

void prefix_remove(const Ipv6Address& value) {
    if (value.flags & 0x200)
        return;
    bool remaining = false;
    uint64_t expires = ticks;
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if (entry != &value && entry->index == value.index && entry->prefix == value.prefix &&
            address_manages_prefix(entry->index, entry->address) &&
            entry->address.matches(value.address, value.prefix)) {
            if (entry->flags & 0x200)
                return;
            uint64_t deadline = address_deadline(*entry);
            if (!deadline)
                return;
            remaining = true;
            if (deadline > expires)
                expires = deadline;
        }
    auto prefix = prefix_for(value);
    if (remaining) {
        auto selected = lowest_metric([&](const Ipv6Route& route) {
            return !route.learned && same_prefix(prefix, route) && route.gateway.unspecified();
        });
        if (selected.entries && !selected.entries[selected.position].expires) {
            selected.entries[selected.position].expires = expires;
            if (!next_gc)
                next_gc = ticks + 3000;
        }
        return;
    }
    erase_lowest_metric([&](const Ipv6Route& route) {
        return !route.learned && same_prefix(prefix, route) && route.gateway.unspecified();
    });
}

void route_withdraw(unsigned index) {
    auto discard = [&](Ipv6Route* entries, unsigned& count) {
        for (unsigned n = 0; n < count;)
            if (entries[n].index == index)
                erase(entries, count, n);
            else
                n++;
    };
    discard(routes, route_count);
    discard(prefixes, prefix_count);
}

void route_poll() {
    bool collect = next_gc && ticks >= next_gc;
    if (collect)
        next_gc = ticks + 3000;
    auto poll = [&](Ipv6Route* entries, unsigned& count) {
        for (unsigned n = 0; n < count;) {
            if (entries[n].expires && ticks >= entries[n].expires) {
                path_mtu_cache.discard_route(entries[n].owner);
                if (collect) {
                    erase(entries, count, n);
                    continue;
                }
            }
            n++;
        }
    };
    poll(routes, route_count);
    poll(prefixes, prefix_count);
}

void route_reset() {
    for (auto& route : routes)
        route = {};
    for (auto& prefix : prefixes)
        prefix = {};
    route_count = prefix_count = 0;
    next_gc = 0;
}
} // namespace ip6
} // namespace ax
