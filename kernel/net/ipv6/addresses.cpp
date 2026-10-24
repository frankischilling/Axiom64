// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/reassembly.hpp"
#include "net/ipv6/configuration.hpp"
#include "core/random.hpp"
#include "net/ipv6/router.hpp"

namespace ax {
ip6::PathMtuCache ip6::path_mtu_cache;

namespace {
struct AddressSlot {
    Ipv6Address value;
    Ipv6AddressLifetimes lifetime;
    uint64_t created = 0, updated = 0;
    uint64_t due = 0;
    uint64_t owner = 0;
    bool sent = false, regenerated = false, failure_handled = false;
    unsigned probes = 0, required = 1, stable_counter = 0;
    uint8_t nonce[6]{};
    bool nonce_valid = false;
    bool prefix_route = true;
};

AddressSlot addresses[ipv6_address_capacity];
unsigned address_count;
uint64_t next_address_owner;

bool ready(const Ipv6Address& entry) {
    return !(entry.flags & (0x40 | 8)) && ipv6_address_cache(entry).valid;
}

uint32_t remaining(uint32_t lifetime, uint64_t age) {
    return lifetime == UINT32_MAX ? UINT32_MAX : age >= lifetime ? 0 : lifetime - age;
}

enum class AddressKind : uint8_t { configured, automatic, regenerated };

uint16_t configured_flags(const Ipv6Address& value, Ipv6AddressLifetimes lifetime,
                          AddressKind kind) {
    uint16_t permanent = kind == AddressKind::regenerated ? value.flags & 0x80
                         : kind == AddressKind::configured && lifetime.valid == UINT32_MAX ? 0x80
                                                                                           : 0;
    return (value.flags & (2 | 0x100 | 0x200 | 0x800)) | permanent |
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
        if (!ready(*entry) ||
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
    if (!ip6::configuration_disabled(ipv6_loopback)) {
        if (!position)
            return &loopback();
        position--;
    }
    return position < address_count ? &addresses[position].value : nullptr;
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

static int address_add(const Ipv6Address& value, Ipv6AddressLifetimes lifetime, bool replace,
                       bool prefix_route, AddressKind kind = AddressKind::configured,
                       unsigned stable_counter = 0) {
    if (!lifetime.valid || lifetime.preferred > lifetime.valid)
        return -22;
    if (!net_info(value.index))
        return -19;
    if (ip6::configuration_disabled(value.index))
        return -13;
    if (value.prefix > 128 || value.address.unspecified() || value.address.multicast() ||
        value.address.loopback() || value.address.mapped())
        return -22;
    if (value.flags & ~uint16_t(0x80 | 2 | 0x100 | 0x200 | 0x800))
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
        // A PIO refresh changes lifetimes and deprecation, retaining address
        // metadata and any connected prefix installed through netlink.
        updated.flags =
            prefix_route
                ? (entry.value.flags & (0x40 | 8 | 0x800)) | configured_flags(value, lifetime, kind)
                : (entry.value.flags & ~uint16_t(0x20)) | (lifetime.preferred ? 0 : 0x20);
        if (prefix_route) {
            if (!(updated.flags & 0x200)) {
                int error = ip6::prefix_add(updated, lifetime.valid,
                                            entry.prefix_route && (entry.value.flags & 0x80) &&
                                                !(entry.value.flags & 0x200));
                if (error)
                    return error;
            } else if (entry.prefix_route && (entry.value.flags & 0x80) &&
                       !(entry.value.flags & 0x200))
                ip6::prefix_remove(entry.value);
            entry.prefix_route = true;
        }
        entry.value = updated;
        entry.lifetime = lifetime;
        entry.updated = ticks;
        return 0;
    }
    if (address_count == ipv6_address_capacity)
        return -105;
    int error = prefix_route && kind != AddressKind::regenerated
                    ? ip6::prefix_add(value, lifetime.valid)
                    : 0;
    if (error)
        return error;
    auto& entry = addresses[address_count++];
    entry = {};
    entry.value = value;
    entry.prefix_route = prefix_route;
    entry.value.flags = configured_flags(value, lifetime, kind);
    entry.lifetime = lifetime;
    entry.created = entry.updated = ticks;
    if (!++next_address_owner)
        ++next_address_owner;
    entry.owner = next_address_owner;
    entry.stable_counter = stable_counter;
    entry.regenerated = stable_counter != 0;
    int32_t probes = 1;
    ip6::configuration_read(value.index, ip6::ConfigurationKey::dad_transmits, probes);
    entry.required = uint8_t(probes);
    if (!(value.flags & 2) && probes)
        entry.value.flags |= 0x40;
    return 0;
}

int ipv6_address_add(const Ipv6Address& value, Ipv6AddressLifetimes lifetime, bool replace) {
    return address_add(value, lifetime, replace, true);
}

int ipv6_address_remove(unsigned index, const ip6::Address& address) {
    for (unsigned n = 0; n < address_count; n++)
        if (addresses[n].value.index == index && addresses[n].value.address == address) {
            auto removed = addresses[n].value;
            auto owner = addresses[n].owner;
            if (addresses[n].prefix_route)
                ip6::prefix_remove(addresses[n].value);
            for (unsigned next = n + 1; next < address_count; next++)
                addresses[next - 1] = addresses[next];
            addresses[--address_count] = {};
            if (removed.address.link_local() || !ipv6_owned(0, removed.address)) {
                ip6::reassembly_discard(&removed.address, index);
                ip6::path_mtu_cache.discard_source(removed.address,
                                                   removed.address.link_local() ? index : 0);
            }
            ip6::router_address_removed(removed, owner);
            ip6::configuration_address_removed(index, removed.address);
            return 0;
        }
    return -99;
}

bool ipv6_owned(unsigned index, const ip6::Address& address, bool tentative) {
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if ((!index || entry->index == index) && entry->address == address && !(entry->flags & 8) &&
            (tentative || ready(*entry)) && ipv6_address_cache(*entry).valid)
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
    if (destination.loopback())
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
            (candidate.prefix == best->prefix &&
             (candidate.metric < best->metric ||
              (candidate.metric == best->metric && candidate.preference > best->preference))))
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
            best->index, ip6::link_mtu(best->index),
            best->owner, best->prefix};
    if (!interface_mtu)
        path.mtu = ip6::path_mtu_cache.lookup(ip6::path_key(path, destination), path.mtu, ticks);
    return 0;
}

void ipv6_mtu_changed(unsigned index, uint32_t previous) {
    if (net_info(index))
        ip6::path_mtu_cache.update_mtu(index, previous, ip6::link_mtu(index));
}

namespace ip6 {
int automatic_address(const Ipv6Address& value, Ipv6AddressLifetimes lifetime, bool replace,
                      unsigned stable_counter) {
    bool link_local = value.address.link_local();
    return address_add(value, lifetime, replace, link_local,
                       link_local ? AddressKind::configured : AddressKind::automatic,
                       stable_counter);
}

// Clone the exact failed owner, retaining configured flags and raw lifetimes.
// A successful handoff publishes its replacement before retiring a nonpermanent owner.
static int regenerate_address(unsigned position, const Address& replacement, unsigned counter) {
    const auto original = addresses[position];
    if (!original.owner || (original.value.flags & 0x48) != 0x48)
        return -99;
    if (replacement == original.value.address ||
        !replacement.matches(original.value.address, original.value.prefix))
        return -22;
    if (!configuration_autoconf_allowed(original.value.index))
        return -105;
    auto value = original.value;
    value.address = replacement;
    value.flags &= ~uint16_t(0x40 | 8 | 0x20);
    int error = address_add(value, original.lifetime, false, original.prefix_route,
                            AddressKind::regenerated, counter);
    if (error)
        return error;
    auto& created = addresses[address_count - 1];
    created.value.flags |= 0x40;
    if (value.flags & 2)
        created.required = 0;
    created.regenerated = true;
    router_address_regenerated(original.value, original.owner, created.value, created.owner,
                               counter);
    configuration_address_regenerated(original.value.index, original.value.address,
                                      created.value.address);
    if (!(original.value.flags & 0x80))
        ipv6_address_remove(original.value.index, original.value.address);
    return 0;
}

static bool retire_failed_address(unsigned position) {
    const auto original = addresses[position];
    if (original.failure_handled)
        return false;
    if ((original.value.flags & 0x800) && original.stable_counter < 3) {
        auto replacement = original.value.address;
        memset(replacement.bytes + 8, 0, 8);
        unsigned counter = original.stable_counter + 1;
        int error = configuration_stable_identifier(original.value.index, replacement, counter);
        if (error == -11)
            return false;
        addresses[position].failure_handled = true;
        if (!error && !regenerate_address(position, replacement, counter))
            return !(original.value.flags & 0x80);
    } else
        addresses[position].failure_handled = true;
    if (!(original.value.flags & 0x80)) {
        ipv6_address_remove(original.value.index, original.value.address);
        return true;
    }
    return false;
}

uint64_t address_owner(unsigned index, const Address& address) {
    for (unsigned n = 0; n < address_count; n++)
        if (addresses[n].value.index == index && addresses[n].value.address == address)
            return addresses[n].owner;
    return 0;
}

Ipv6AddressLifetimes address_lifetimes(unsigned index, const Address& address, uint64_t owner) {
    for (unsigned n = 0; n < address_count; n++) {
        const auto& entry = addresses[n];
        if (owner && entry.owner == owner && entry.value.index == index &&
            entry.value.address == address)
            return entry.lifetime;
    }
    return {0, 0};
}

bool address_manages_prefix(unsigned index, const Address& address) {
    for (unsigned n = 0; n < address_count; n++)
        if (addresses[n].value.index == index && addresses[n].value.address == address)
            return addresses[n].prefix_route;
    return false;
}

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
    if (configuration_disabled(index))
        return false;
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
        if ((entry.value.flags & 0x48) == 0x48 && retire_failed_address(n))
            continue;
        n++;
        if (!(entry.value.flags & 0x40) || (entry.value.flags & 8))
            continue;
        if (!configuration_dad_ready(entry.value.index)) {
            entry.sent = false;
            entry.probes = 0;
            entry.nonce_valid = false;
            if (!entry.regenerated)
                entry.due = 0;
            continue;
        }
        // A stable retry defers DAD only for the newly generated address owner.
        if (entry.regenerated && !entry.due) {
            uint32_t random;
            if (random_read(&random, sizeof(random)))
                continue;
            // Round past the sampled tick so a conflict just before the
            // next tick still waits a complete second, plus bounded jitter.
            entry.due = ticks + 101 + random % 101;
        }
        if (ticks < entry.due)
            continue;
        if (!entry.required || (entry.sent && entry.probes >= entry.required)) {
            entry.value.flags &= ~uint16_t(0x40);
            continue;
        }
        int32_t enhanced = 1;
        int32_t global_enhanced = 1;
        configuration_read(entry.value.index, ConfigurationKey::enhanced_dad, enhanced);
        configuration_read(configuration_all, ConfigurationKey::enhanced_dad, global_enhanced);
        enhanced = enhanced || global_enhanced;
        if (enhanced && !entry.nonce_valid) {
            if (random_read(entry.nonce, sizeof(entry.nonce)))
                continue;
            entry.nonce_valid = true;
        }
        int error = dad_probe(entry.value, enhanced ? entry.nonce : nullptr);
        // Linux consumes scheduled DAD attempts while carrier is unavailable.
        // Other output failures retain the existing admission retry behavior.
        if ((!error || error == -100) && (entry.value.flags & 0x40)) {
            entry.regenerated = false;
            entry.sent = true;
            entry.probes++;
            // A transmitted frame follows the sampled 10 ms tick. Round past
            // that tick to retain a complete retransmit interval on the wire.
            entry.due = ticks + link_retransmit(entry.value.index) + 1;
        }
    }
}

void address_duplicate(unsigned index, const Address& address, const uint8_t* nonce) {
    for (unsigned n = 0; n < address_count; n++) {
        auto& slot = addresses[n];
        auto& entry = slot.value;
        if (entry.index == index && entry.address == address && (entry.flags & 0x40)) {
            if (nonce && slot.nonce_valid && !memcmp(nonce, slot.nonce, sizeof(slot.nonce)))
                continue;
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
