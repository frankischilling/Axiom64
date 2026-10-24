// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/router.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"
#include "core/random.hpp"

namespace ax::ip6 {
namespace {
struct Link {
    Address source;
    uint32_t mtu = 0;
    uint8_t hops = 64;
    uint64_t retransmit = 100, reachable_base = 3000, reachable = 3000;
    uint64_t randomize_due = 0, due = 0, interval = 0;
    unsigned sent = 0;
    bool ready = false, active = false, answered = false;
};

struct Router {
    Address source;
    unsigned index = 0;
    uint64_t route = 0, expires = 0;
};

struct Prefix {
    Address prefix, address;
    unsigned index = 0, counter = 0;
    uint8_t length = 0;
    uint64_t route = 0, route_expires = 0, owner = 0;
    uint64_t valid = 0, preferred = 0;
    bool valid_forever = false, preferred_forever = false;
    bool pending = false;
};

Link links[max_net_devices];
Router routers[ipv6_route_capacity];
Prefix prefixes[ipv6_address_capacity];

uint32_t integer(const uint8_t* bytes) {
    return uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 |
           uint32_t(bytes[3]);
}

uint64_t deadline(uint32_t seconds) {
    return ticks + uint64_t(seconds) * 100;
}

uint32_t remaining(uint64_t expiry, bool forever) {
    return forever ? UINT32_MAX : expiry <= ticks ? 0 : uint32_t((expiry - ticks + 99) / 100);
}

bool enabled(unsigned index, ConfigurationKey key) {
    int32_t value = 0;
    return !configuration_read(index, key, value) && value;
}

bool valid_mac(const uint8_t* bytes) {
    bool nonzero = false;
    for (unsigned n = 0; n < 6; n++)
        nonzero |= bytes[n] != 0;
    return nonzero && !(bytes[0] & 1);
}

bool validate(const Packet& packet) {
    if (packet.protocol != 58 || packet.length < 16 || packet.payload[0] != 134 ||
        packet.payload[1] || packet.header.hop_limit != 255 || packet.fragmented ||
        !packet.header.source.link_local())
        return false;
    for (size_t at = 16; at < packet.length;) {
        if (packet.length - at < 2 || !packet.payload[at + 1])
            return false;
        size_t size = size_t(packet.payload[at + 1]) * 8;
        if (size > packet.length - at)
            return false;
        if (packet.payload[at] == 1 && (size != 8 || !valid_mac(packet.payload + at + 2)))
            return false;
        at += size;
    }
    return true;
}

bool has_router(unsigned index) {
    for (const auto& router : routers)
        if (router.index == index && learned_route_present(router.route) && ticks < router.expires)
            return true;
    return false;
}

void randomize(Link& link) {
    uint32_t value;
    if (random_read(&value, sizeof(value))) {
        link.randomize_due = ticks + 100;
        return;
    }
    link.reachable = link.reachable_base / 2 + value % (link.reachable_base + 1);
    link.randomize_due = ticks + 720000;
}

Router* router_slot(unsigned index, const Address& source, bool create) {
    Router* vacant = nullptr;
    for (auto& router : routers) {
        if (router.index == index && router.source == source)
            return &router;
        if (!router.index && !vacant)
            vacant = &router;
    }
    if (!create || !vacant)
        return nullptr;
    vacant->index = index;
    vacant->source = source;
    return vacant;
}

void default_router(unsigned index, const Packet& packet) {
    uint32_t lifetime = uint16_t(packet.payload[6]) << 8 | packet.payload[7];
    auto router = router_slot(index, packet.header.source, lifetime);
    if (!router)
        return;
    Ipv6Route route{{}, packet.header.source, index, 1024, 0, 9};
    unsigned preference = (packet.payload[5] >> 3) & 3;
    route.preference = preference == 1 ? 1 : preference == 3 ? -1 : 0;
    route.expires = deadline(lifetime);
    if (!learned_route(route, router->route, !lifetime))
        router->expires = route.expires;
    if (!router->route)
        *router = {};
}

Prefix* prefix_slot(unsigned index, const Address& address, uint8_t length, bool create) {
    Prefix* vacant = nullptr;
    for (auto& prefix : prefixes) {
        if (prefix.index == index && prefix.length == length && prefix.prefix == address)
            return &prefix;
        if (!prefix.index && !vacant)
            vacant = &prefix;
    }
    if (!create || !vacant)
        return nullptr;
    vacant->index = index;
    vacant->prefix = address;
    vacant->length = length;
    return vacant;
}

const Ipv6Address* assigned_address(unsigned index, const Address& address) {
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if (entry->index == index && entry->address == address)
            return entry;
    return nullptr;
}

const Ipv6Address* owned_address(const Prefix& prefix) {
    if (!prefix.owner || address_owner(prefix.index, prefix.address) != prefix.owner)
        return nullptr;
    return assigned_address(prefix.index, prefix.address);
}

void generate(Prefix& prefix) {
    auto valid = remaining(prefix.valid, prefix.valid_forever);
    if (!valid) {
        prefix.pending = false;
        return;
    }
    if (!enabled(prefix.index, ConfigurationKey::autoconf))
        return;
    auto address = prefix.prefix;
    bool privacy = false;
    int error = configuration_identifier(prefix.index, address, prefix.counter, privacy);
    if (error) {
        prefix.pending = error == -11;
        return;
    }
    Ipv6Address value{address, prefix.index, uint16_t(0x100 | (privacy ? 0x800 : 0)), 64};
    if (!configuration_autoconf_allowed(prefix.index)) {
        prefix.pending = false;
        return;
    }
    error = automatic_address(value, {remaining(prefix.preferred, prefix.preferred_forever), valid},
                              false, prefix.counter);
    prefix.pending = false;
    if (!error) {
        prefix.address = address;
        prefix.owner = address_owner(prefix.index, address);
    }
}

void prefix_information(unsigned index, const uint8_t* option, size_t length) {
    if (length < 32 || option[2] > 128)
        return;
    uint32_t valid = integer(option + 4), preferred = integer(option + 8);
    Address address;
    memcpy(address.bytes, option + 16, 16);
    if (preferred > valid || address.multicast() || address.link_local())
        return;
    for (unsigned bit = option[2]; bit < 128; bit++)
        address.bytes[bit / 8] &= ~(1u << (7 - bit % 8));
    auto prefix = prefix_slot(index, address, option[2], valid && (option[3] & 0xc0));
    if (!prefix && !valid && (option[3] & 0x40) && option[2] == 64 &&
        enabled(index, ConfigurationKey::autoconf)) {
        // A first zero PIO can refresh an existing configured address. Do
        // not allocate a prefix slot for an unmatched zero advertisement.
        auto candidate = address;
        unsigned counter = 0;
        bool privacy = false;
        if (!configuration_identifier(index, candidate, counter, privacy))
            if (auto current = assigned_address(index, candidate);
                current && ipv6_address_cache(*current).valid)
                prefix = prefix_slot(index, address, option[2], true);
    }
    if (!prefix)
        return;
    if (option[3] & 0x80) {
        Ipv6Route route{address, {}, index, 256, option[2], 2};
        route.expires = valid == UINT32_MAX ? 0 : deadline(valid);
        if (!learned_route(route, prefix->route, !valid))
            prefix->route_expires = route.expires;
    }
    if (!(option[3] & 0x40) || option[2] != 64 || !enabled(index, ConfigurationKey::autoconf))
        return;
    if (!owned_address(*prefix)) {
        // A fresh PIO looks up the current matching address, including an
        // explicit remove/re-add. Cached maintenance retains its old owner
        // guard and cannot adopt a later configured object on its own.
        auto candidate = prefix->prefix;
        bool privacy = false;
        if (!configuration_identifier(index, candidate, prefix->counter, privacy))
            if (assigned_address(index, candidate)) {
                prefix->address = candidate;
                prefix->owner = address_owner(index, candidate);
                prefix->pending = false;
            }
    }
    if (auto current = owned_address(*prefix); current && !ipv6_address_cache(*current).valid) {
        auto expired = current->address;
        ipv6_address_remove(index, expired);
        prefix->owner = 0;
    }
    if (auto current = owned_address(*prefix)) {
        auto value = *current;
        auto stored = ipv6_address_cache(value).valid;
        // RFC 4862 protects an existing address against an unauthenticated
        // reduction below two hours, while always refreshing preferred time.
        valid = max(valid, min(stored, uint32_t(7200)));
        if (!valid)
            return;
        value.flags &= uint16_t(2 | 0x100 | 0x200 | 0x800);
        if (automatic_address(value, {preferred, valid}, true))
            return;
    } else {
        prefix->owner = 0;
        if (!valid)
            return;
        prefix->counter = 0;
        prefix->pending = true;
    }
    prefix->valid_forever = valid == UINT32_MAX;
    prefix->preferred_forever = preferred == UINT32_MAX;
    prefix->valid = deadline(valid);
    prefix->preferred = deadline(preferred);
    if (prefix->pending)
        generate(*prefix);
}
} // namespace

uint32_t link_mtu(unsigned index) {
    if (index == ipv6_loopback)
        return 65536;
    auto info = net_info(index);
    if (!info || index > max_net_devices)
        return 0;
    auto value = links[index - 1].mtu;
    return value ? min(info->mtu, value) : info->mtu;
}

uint8_t link_hop_limit(unsigned index) {
    return index && index <= max_net_devices ? links[index - 1].hops : 64;
}

uint64_t link_retransmit(unsigned index) {
    return index && index <= max_net_devices ? links[index - 1].retransmit : 100;
}

uint64_t link_reachable(unsigned index) {
    return index && index <= max_net_devices ? links[index - 1].reachable : 3000;
}

void router_receive(unsigned index, const Packet& packet) {
    if (!index || index > max_net_devices || !usable(index) || !validate(packet))
        return;
    const uint8_t* source_mac = nullptr;
    for (size_t at = 16; at < packet.length; at += size_t(packet.payload[at + 1]) * 8)
        if (packet.payload[at] == 1 && !source_mac)
            source_mac = packet.payload + at + 2;
    if (source_mac)
        neighbor_solicitation(index, packet.header.source, source_mac);
    if (!enabled(index, ConfigurationKey::accept_ra))
        return;
    auto& link = links[index - 1];
    if (!ipv6_owned(index, packet.header.source)) {
        default_router(index, packet);
        if (packet.payload[4])
            link.hops = packet.payload[4];
    }
    link.answered = has_router(index);
    uint32_t retransmit = integer(packet.payload + 12);
    if (retransmit)
        link.retransmit = (uint64_t(retransmit) + 9) / 10;
    uint32_t reachable = integer(packet.payload + 8);
    if (reachable) {
        uint64_t base = max(uint64_t(10), (uint64_t(reachable) + 9) / 10);
        if (base != link.reachable_base) {
            link.reachable_base = base;
            randomize(link);
        }
    }
    bool seen_mtu = false;
    for (size_t at = 16; at < packet.length;) {
        const auto* option = packet.payload + at;
        size_t size = size_t(option[1]) * 8;
        if (option[0] == 3)
            prefix_information(index, option, size);
        if (option[0] == 5 && size == 8 && !seen_mtu) {
            seen_mtu = true;
            uint32_t mtu = integer(option + 4);
            if (mtu >= minimum_mtu && mtu <= net_info(index)->mtu) {
                auto previous = link_mtu(index);
                link.mtu = mtu;
                path_mtu_cache.update_mtu(index, previous, link_mtu(index));
            }
        }
        at += size;
    }
}

void router_address_regenerated(const Ipv6Address& original, uint64_t owner,
                                const Ipv6Address& replacement, uint64_t replacement_owner,
                                unsigned counter) {
    for (auto& prefix : prefixes) {
        if (prefix.index != original.index || prefix.owner != owner ||
            !(prefix.address == original.address))
            continue;
        prefix.address = replacement.address;
        prefix.owner = replacement_owner;
        prefix.counter = counter;
        prefix.pending = false;
        // Regeneration copies the failed object's configured lifetimes;
        // the independently learned on-link route keeps its deadline.
        auto lifetime =
            address_lifetimes(replacement.index, replacement.address, replacement_owner);
        prefix.valid_forever = lifetime.valid == UINT32_MAX;
        prefix.preferred_forever = lifetime.preferred == UINT32_MAX;
        prefix.valid = deadline(lifetime.valid);
        prefix.preferred = deadline(lifetime.preferred);
    }
}

void router_address_removed(const Ipv6Address& removed, uint64_t owner) {
    if (!owner)
        return;
    for (auto& prefix : prefixes) {
        if (prefix.index != removed.index || prefix.length != removed.prefix ||
            !removed.address.matches(prefix.prefix, prefix.length))
            continue;
        if (prefix.owner == owner && prefix.address == removed.address) {
            prefix.owner = 0;
            prefix.pending = false;
        }
        if ((removed.flags & 0x200) || !prefix.route)
            continue;
        bool shared = false, retained = false;
        uint64_t expires = ticks;
        for (unsigned n = 0; auto entry = ipv6_address(n); n++) {
            if (entry->index != prefix.index || entry->prefix != prefix.length ||
                !entry->address.matches(prefix.prefix, prefix.length))
                continue;
            shared = true;
            auto deadline = address_deadline(*entry);
            if ((entry->flags & (0x80 | 0x200)) || !deadline) {
                retained = true;
                break;
            }
            expires = max(expires, deadline);
        }
        Ipv6Route route{prefix.prefix, {}, prefix.index, 256, prefix.length, 2};
        if (!shared) {
            // Exhausting the final automatic address retires only this
            // prefix's learned route. Other addresses and route owners
            // retain their independent objects.
            learned_route(route, prefix.route, true);
        } else if (!retained && !prefix.route_expires && learned_route_present(prefix.route)) {
            route.expires = expires;
            if (!learned_route(route, prefix.route))
                prefix.route_expires = expires;
        }
    }
}

void router_poll() {
    for (auto& router : routers)
        if (router.index && (ticks >= router.expires || !learned_route_present(router.route))) {
            Ipv6Route route{{}, router.source, router.index, 1024, 0, 9};
            learned_route(route, router.route, true);
            router = {};
        }
    for (auto& prefix : prefixes) {
        if (!prefix.index)
            continue;
        if (prefix.route && !learned_route_present(prefix.route))
            prefix.route = 0;
        if (prefix.route && prefix.route_expires && ticks >= prefix.route_expires) {
            Ipv6Route route{prefix.prefix, {}, prefix.index, 256, prefix.length, 2};
            learned_route(route, prefix.route, true);
        }
        if (prefix.owner) {
            auto current = owned_address(prefix);
            if (!current) {
                prefix.owner = 0;
                prefix.pending = false;
            }
        }
        if (prefix.pending && usable(prefix.index))
            generate(prefix);
        if (!prefix.route && !prefix.owner && !prefix.pending)
            prefix = {};
    }
    for (unsigned index = 1; index <= max_net_devices; index++) {
        auto& link = links[index - 1];
        if (!usable(index)) {
            link.ready = link.active = link.answered = false;
            link.source = {};
            continue;
        }
        if (!link.ready) {
            link.ready = true;
            link.active = false;
        }
        if (link.randomize_due && ticks >= link.randomize_due)
            randomize(link);
        if (link.answered && !has_router(index)) {
            link.answered = false;
            link.active = false;
        }
        int32_t maximum = -1;
        configuration_read(index, ConfigurationKey::router_solicitations, maximum);
        if (!maximum || !enabled(index, ConfigurationKey::accept_ra)) {
            link.active = false;
            continue;
        }
        if (link.answered)
            continue;
        Address source;
        for (unsigned n = 0; auto entry = ipv6_address(n); n++)
            if (entry->index == index && entry->address.link_local() &&
                ipv6_owned(index, entry->address)) {
                source = entry->address;
                break;
            }
        if (source.unspecified()) {
            link.active = false;
            continue;
        }
        if (!link.active || !(link.source == source)) {
            uint32_t random;
            if (random_read(&random, sizeof(random)))
                continue;
            link.active = true;
            link.source = source;
            link.sent = 0;
            link.interval = 0;
            link.due = ticks + random % 101;
        }
        if ((maximum > 0 && link.sent >= unsigned(maximum)) || ticks < link.due)
            continue;
        uint32_t random;
        if (random_read(&random, sizeof(random)))
            continue;
        if (router_probe(index, source)) {
            link.due = ticks + 100;
            continue;
        }
        link.sent++;
        int64_t variation = int64_t(random % 201) - 100;
        int64_t next = link.interval ? 2 * link.interval + int64_t(link.interval) * variation / 1000
                                     : 400 + 400 * variation / 1000;
        if (next > 360000)
            next = 360000 + 360000 * variation / 1000;
        link.interval = uint64_t(next);
        link.due = ticks + link.interval;
    }
}

void router_link_reset(unsigned index) {
    if (!index || index > max_net_devices)
        return;
    links[index - 1] = {};
    for (auto& router : routers)
        if (router.index == index)
            router = {};
    for (auto& prefix : prefixes)
        if (prefix.index == index)
            prefix = {};
}

void router_reset() {
    for (auto& link : links)
        link = {};
    for (auto& router : routers)
        router = {};
    for (auto& prefix : prefixes)
        prefix = {};
}
} // namespace ax::ip6
