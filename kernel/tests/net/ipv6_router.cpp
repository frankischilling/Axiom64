// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/router.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"
#include "../../net/ipv6/socket.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;
const std::vector<std::vector<uint8_t>>& ipv6_emitted(unsigned lane);
void ipv6_test_budget(unsigned value);
void ipv6_test_carrier(unsigned lane, bool up);
void ipv6_test_dad_jitter(int value);

namespace {
ip6::Address local(unsigned host = 1) {
    ip6::Address value;
    value.bytes[0] = 0xfe;
    value.bytes[1] = 0x80;
    value.bytes[15] = host;
    return value;
}

ip6::Address network(unsigned number = 1) {
    ip6::Address value;
    value.bytes[0] = 0x20;
    value.bytes[1] = 1;
    value.bytes[2] = 0x0d;
    value.bytes[3] = 0xb8;
    value.bytes[7] = number;
    return value;
}

ip6::Address generated() {
    auto value = network();
    const auto* mac = net_info(1)->mac;
    std::copy(mac, mac + 3, value.bytes + 8);
    value.bytes[8] ^= 2;
    value.bytes[11] = 0xff;
    value.bytes[12] = 0xfe;
    std::copy(mac + 3, mac + 6, value.bytes + 13);
    return value;
}

void put(std::vector<uint8_t>& data, unsigned at, uint32_t value) {
    for (unsigned n = 0; n < 4; n++)
        data[at + n] = value >> (24 - 8 * n);
}

std::vector<uint8_t> advertisement(uint16_t lifetime = 30) {
    std::vector<uint8_t> data(24);
    data[0] = 134;
    data[4] = 48;
    data[6] = lifetime >> 8;
    data[7] = lifetime;
    data[16] = data[17] = 1;
    data[18] = 2;
    data[23] = 0x80;
    return data;
}

void prefix(std::vector<uint8_t>& data, uint8_t flags, uint32_t valid, uint32_t preferred,
            unsigned number = 1, uint8_t length = 64) {
    unsigned at = data.size();
    data.resize(at + 32);
    data[at] = 3;
    data[at + 1] = 4;
    data[at + 2] = length;
    data[at + 3] = flags;
    put(data, at + 4, valid);
    put(data, at + 8, preferred);
    auto address = network(number);
    std::copy(address.bytes, address.bytes + 16, data.begin() + at + 16);
}

std::vector<uint8_t> frame(std::vector<uint8_t> data, ip6::Address source = local(0x80),
                           unsigned hops = 255, bool checksum = true) {
    auto destination = ip6::all_nodes();
    std::vector<uint8_t> bytes(54 + data.size());
    ip6::multicast_mac(destination, bytes.data());
    bytes[6] = 2;
    bytes[11] = 0x80;
    bytes[12] = 0x86;
    bytes[13] = 0xdd;
    ip6::Header header{source, destination, 0, uint16_t(data.size()), 0, 58, uint8_t(hops)};
    assert(ip6::encode(bytes.data() + 14, 40, header));
    data[2] = data[3] = 0;
    uint16_t check = ip6::checksum(source, destination, 58, data.data(), data.size());
    data[2] = check >> 8;
    data[3] = check;
    if (!checksum)
        data[2] ^= 1;
    std::copy(data.begin(), data.end(), bytes.begin() + 54);
    return bytes;
}

void receive(const std::vector<uint8_t>& bytes) {
    ipv6_receive(*net_info(1), bytes.data(), bytes.size());
}

void send(const std::vector<uint8_t>& data, ip6::Address source = local(0x80)) {
    receive(frame(data, source));
}

const Ipv6Address* find(const ip6::Address& address) {
    for (unsigned at = 0; auto entry = ipv6_address(at); at++)
        if (entry->index == 1 && entry->address == address)
            return entry;
    return nullptr;
}

std::vector<Ipv6Route> routes() {
    Ipv6Route inventory[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(inventory, std::size(inventory));
    return {inventory, inventory + count};
}

unsigned learned() {
    unsigned count = 0;
    for (const auto& route : routes())
        count += route.learned;
    return count;
}

void prepare(void (*reset)()) {
    reset();
    assert(!ipv6_address_add({local(), 1, 2, 64}));
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::accept_ra, 1));
}

void admission(void (*reset)()) {
    for (unsigned kind = 0; kind < 9; kind++) {
        prepare(reset);
        auto data = advertisement();
        prefix(data, 0xc0, 100, 60);
        unsigned at = data.size();
        data.resize(at + 8);
        data[at] = 5;
        data[at + 1] = 1;
        put(data, at + 4, 1400);
        auto source = kind == 0 ? network() : local(0x80);
        if (kind == 2)
            data[1] = 1;
        if (kind == 4)
            data.push_back(1);
        if (kind == 5)
            data[25] = 0;
        if (kind == 6)
            data[17] = 2;
        if (kind == 7)
            data[18] = 1;
        auto bytes = frame(data, source, kind == 1 ? 254 : 255, kind != 3);
        if (kind == 8) {
            // Atomic fragments remain forbidden for Neighbor Discovery.
            bytes.insert(bytes.begin() + 54, 8, 0);
            bytes[20] = 44;
            bytes[54] = 58;
            unsigned length = bytes.size() - 54;
            bytes[18] = length >> 8;
            bytes[19] = length;
        }
        receive(bytes);
        assert(!learned() && !find(generated()));
        assert(ip6::link_mtu(1) == 1500 && ip6::link_hop_limit(1) == 64);
    }
}

void flags_and_dad(void (*reset)()) {
    for (unsigned flags : {0u, 0x40u, 0x80u, 0xc0u}) {
        prepare(reset);
        auto data = advertisement();
        prefix(data, flags, 100, 60);
        send(data);
        assert(learned() == 1 + bool(flags & 0x80));
        for (const auto& route : routes())
            if (route.learned && route.prefix == 64)
                assert(route.protocol == 2 && route.metric == 256);
        assert(bool(find(generated())) == bool(flags & 0x40));
        if (!(flags & 0x40))
            continue;
        assert(find(generated())->flags & 0x40);
        assert(!ip6::address_manages_prefix(1, generated()));
        ipv6_poll();
        ticks = 100;
        ipv6_poll();
        assert(ipv6_owned(1, generated()));
        assert(ipv6_address_cache(*find(generated())).valid == 99);
        auto target = network();
        target.bytes[15] = 0x90;
        Ipv6Path path;
        assert(!ipv6_path({}, target, 1, path));
        assert(path.next_hop == ((flags & 0x80) ? target : local(0x80)));
    }
    prepare(reset);
    auto data = advertisement();
    prefix(data, 0xc0, 100, 101);
    send(data);
    assert(learned() == 1 && !find(generated()));
    prepare(reset);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::accept_ra, 0));
    data = advertisement();
    prefix(data, 0xc0, 100, 60);
    send(data);
    assert(!learned() && !find(generated()));
    uint8_t mac[6];
    assert(ip6::neighbor_resolve(1, local(), local(0x80), mac));
    assert(mac[0] == 2 && mac[5] == 0x80);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::accept_ra, 1));
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::autoconf, 0));
    send(data);
    assert(learned() == 2 && !find(generated()));
}

void lifetimes(void (*reset)()) {
    for (uint32_t initial : {100u, 10000u}) {
        prepare(reset);
        auto data = advertisement();
        prefix(data, 0xc0, initial, initial / 2);
        send(data);
        assert(find(generated()));
        auto owner = ip6::address_owner(1, generated());
        data = advertisement(0);
        prefix(data, 0xc0, 0, 0);
        send(data);
        auto entry = find(generated());
        assert(entry && (entry->flags & 0x20) && !learned());
        auto cache = ipv6_address_cache(*entry);
        auto expected = std::min(initial, 7200u);
        assert(cache.valid == expected && !cache.preferred);
        assert(ip6::address_owner(1, generated()) == owner);
        ticks = uint64_t(expected) * 100;
        ipv6_poll();
        assert(!find(generated()));
    }
    prepare(reset);
    auto data = advertisement();
    prefix(data, 0xc0, 100, 60);
    send(data);
    assert(!ipv6_address_remove(1, generated()));
    assert(!ipv6_address_add({generated(), 1, 2, 64}));
    auto owner = ip6::address_owner(1, generated());
    data = advertisement(0);
    prefix(data, 0xc0, 0, 0);
    send(data);
    assert(find(generated()) && (find(generated())->flags & 0x80));
    assert(ip6::address_owner(1, generated()) == owner);
    bool connected = false;
    for (const auto& route : routes())
        connected |= !route.learned && route.prefix == 64 && route.destination == network();
    assert(connected && !learned());
}

void replacement(void (*reset)()) {
    prepare(reset);
    auto data = advertisement(0);
    prefix(data, 0xc0, 10000, 6000);
    send(data);
    ipv6_poll();
    ticks = 100;
    ipv6_poll();
    assert(ipv6_owned(1, generated()));
    auto owner = ip6::address_owner(1, generated());
    assert(!ipv6_address_add({generated(), 1, 2, 64}, {}, true));
    auto connected = [] {
        unsigned count = 0;
        bool permanent = false;
        for (const auto& route : routes())
            if (route.prefix == 64 && route.destination == network()) {
                count++;
                permanent |= !route.expires && route.protocol == 2 && route.metric == 256;
            }
        return count == 1 && permanent;
    };
    bool promoted = connected() && ip6::address_manages_prefix(1, generated());
    data = advertisement(0);
    prefix(data, 0xc0, 0, 0);
    send(data);
    auto entry = find(generated());
    assert(entry);
    auto cache = ipv6_address_cache(*entry);
    bool zero = entry->flags == 0xa2 && !cache.preferred && cache.valid == 7200 && connected();
    data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    entry = find(generated());
    assert(entry);
    cache = ipv6_address_cache(*entry);
    bool finite = entry->flags == 0x82 && cache.preferred == 60 && cache.valid == 7200 &&
                  connected() && ip6::address_owner(1, generated()) == owner;
    ticks += 720000;
    bool expired = !ipv6_owned(1, generated()) && !ipv6_owned(1, generated(), true);
    ipv6_poll();
    bool removed = !find(generated());
    std::printf("IPV6_ROUTER_REPLACEMENT promoted=%u zero=%u finite=%u expired=%u removed=%u\n",
                promoted, zero, finite, expired, removed);
    std::fflush(stdout);
    assert(promoted && zero && finite && expired && removed);

    // Removing the configured address exposes the independently retained
    // advertised prefix; withdrawing that advertisement then removes it.
    prepare(reset);
    data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    auto advertised = routes();
    auto learned_owner = std::find_if(advertised.begin(), advertised.end(), [](const auto& route) {
                             return route.learned && route.destination == network();
                         })->owner;
    assert(!ipv6_address_add({generated(), 1, 2, 64}, {}, true) && connected());
    assert(ip6::learned_route_present(learned_owner));
    assert(!ipv6_address_remove(1, generated()));
    unsigned visible = 0;
    for (const auto& route : routes())
        if (route.destination == network()) {
            assert(route.learned && route.owner == learned_owner && route.expires == 10000);
            visible++;
        }
    assert(visible == 1);
    data = advertisement(0);
    prefix(data, 0x80, 0, 0);
    send(data);
    assert(!ip6::learned_route_present(learned_owner) && !learned());

    prepare(reset);
    data = advertisement(0);
    prefix(data, 0xc0, UINT32_MAX, UINT32_MAX);
    send(data);
    auto infinite = find(generated());
    assert(infinite && !(infinite->flags & 0x80));
    assert(ipv6_address_cache(*infinite).valid == UINT32_MAX);
}

void renewed_ownership(void (*reset)()) {
    prepare(reset);
    auto data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    assert(!ipv6_address_remove(1, generated()));
    assert(!ipv6_address_add({generated(), 1, 2, 64}));
    auto owner = ip6::address_owner(1, generated());
    ticks = 1;
    ipv6_poll();
    bool cached = find(generated()) && ipv6_address_cache(*find(generated())).valid == UINT32_MAX;
    data = advertisement(0);
    prefix(data, 0xc0, 0, 0);
    send(data);
    auto entry = find(generated());
    assert(entry);
    auto cache = ipv6_address_cache(*entry);
    bool zero = entry->flags == 0xa2 && cache.preferred == 0 && cache.valid == 7200 &&
                ip6::address_owner(1, generated()) == owner;
    data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    entry = find(generated());
    assert(entry);
    cache = ipv6_address_cache(*entry);
    bool finite = entry->flags == 0x82 && cache.preferred == 60 && cache.valid == 7200;

    prepare(reset);
    data = advertisement(0);
    prefix(data, 0xc0, UINT32_MAX, UINT32_MAX);
    send(data);
    assert(!ipv6_address_add({generated(), 1, 2, 64}, {}, true));
    uint64_t manual_owner = 0;
    for (const auto& route : routes())
        if (route.destination == network() && !route.learned)
            manual_owner = route.owner;
    data = advertisement(0);
    prefix(data, 0x80, 0, 0);
    send(data);
    uint64_t retained = 0;
    for (const auto& route : routes())
        if (route.destination == network() && !route.learned)
            retained = route.owner;
    bool identity = manual_owner && manual_owner == retained;
    std::printf("IPV6_ROUTER_RECREATE cached_preserved=%u zero=%u finite=%u prefix_identity=%u\n",
                cached, zero, finite, identity);
    std::fflush(stdout);
    assert(cached && zero && finite && identity);
}

void initial_zero(void (*reset)()) {
    bool all = true;
    unsigned cases = 0;
    for (unsigned flags : {0x40u, 0xc0u})
        for (uint32_t initial : {UINT32_MAX, 100u, 10000u}) {
            prepare(reset);
            Ipv6AddressLifetimes lifetime{initial == UINT32_MAX ? initial : initial / 2, initial};
            assert(!ipv6_address_add({generated(), 1, 2, 64}, lifetime));
            auto owner = ip6::address_owner(1, generated());
            uint64_t route_owner = 0, route_expires = 0;
            for (const auto& route : routes())
                if (route.destination == network() && route.prefix == 64 && !route.learned) {
                    route_owner = route.owner;
                    route_expires = route.expires;
                }
            assert(route_owner && !learned());
            ticks = 200;
            auto remaining = initial == UINT32_MAX ? initial : initial - 2;
            auto expected = std::min(remaining, 7200u);
            auto data = advertisement(0);
            prefix(data, flags, 0, 0);
            send(data);
            auto entry = find(generated());
            assert(entry);
            auto cache = ipv6_address_cache(*entry);
            unsigned observed_routes = 0;
            bool route_identity = false;
            for (const auto& route : routes())
                if (route.destination == network() && route.prefix == 64) {
                    observed_routes++;
                    route_identity = !route.learned && route.owner == route_owner &&
                                     route.expires == route_expires;
                }
            auto expected_flags = initial == UINT32_MAX ? 0xa2 : 0x22;
            bool matched = cache.preferred == 0 && cache.valid == expected &&
                           entry->flags == expected_flags && cache.created == 0 &&
                           cache.updated == 200 && ip6::address_owner(1, generated()) == owner &&
                           ip6::address_manages_prefix(1, generated()) && !learned() &&
                           observed_routes == 1 && route_identity;
            std::printf("IPV6_ROUTER_FIRST_ZERO flags=%x initial=%u observed_flags=%x "
                        "preferred=%u valid=%u expected=%u owner=%u prefix=%u matched=%u\n",
                        flags, initial, entry->flags, cache.preferred, cache.valid, expected,
                        ip6::address_owner(1, generated()) == owner, route_identity, matched);
            std::fflush(stdout);
            all &= matched;
            cases++;
            if (matched) {
                ticks += uint64_t(expected) * 100;
                assert(!ipv6_owned(1, generated()) && !ipv6_owned(1, generated(), true));
                ipv6_poll();
                assert(!find(generated()));
            }
        }
    assert(cases == 6 && all);

    // A matching manual address is untouched when A, /64, or autoconf
    // eligibility is absent, or when only the prefix (not the IID) matches.
    for (unsigned kind = 0; kind < 6; kind++) {
        prepare(reset);
        auto address = generated();
        if (kind == 5)
            address.bytes[15] ^= 1;
        assert(!ipv6_address_add({address, 1, 2, 64}));
        if (kind == 3)
            assert(!ip6::configuration_write(1, ip6::ConfigurationKey::autoconf, 0));
        if (kind == 4)
            assert(!ip6::configuration_write(1, ip6::ConfigurationKey::accept_ra, 0));
        auto data = advertisement(0);
        prefix(data, kind == 0 ? 0 : kind == 1 ? 0x80 : 0xc0, 0, 0, 1, kind == 2 ? 63 : 64);
        send(data);
        auto entry = find(address);
        assert(entry && entry->flags == 0x82);
        auto cache = ipv6_address_cache(*entry);
        assert(cache.preferred == UINT32_MAX && cache.valid == UINT32_MAX && !learned());
    }

    // More distinct zero PIOs than the bounded prefix capacity cannot
    // consume the slots required by a later useful advertisement.
    for (unsigned flags : {0x40u, 0xc0u}) {
        prepare(reset);
        for (unsigned n = 0; n < ipv6_address_capacity * 2; n++) {
            auto data = advertisement(0);
            prefix(data, flags, 0, 0, 10 + n);
            send(data);
        }
        assert(!learned() && !find(generated()));
        auto data = advertisement(0);
        prefix(data, flags, 100, 60);
        send(data);
        assert(find(generated()) && learned() == bool(flags & 0x80));
    }
    std::puts("IPV6_ROUTER_FIRST_ZERO_PASS refreshed=6 ignored=6 capacity=2");
}

const Ipv6Address* prefix_address() {
    auto destination = network();
    for (unsigned at = 0; auto entry = ipv6_address(at); at++)
        if (entry->index == 1 && !memcmp(entry->address.bytes, destination.bytes, 8))
            return entry;
    return nullptr;
}

unsigned dad_probes(const ip6::Address& address) {
    unsigned count = 0;
    for (const auto& bytes : ipv6_emitted(0)) {
        auto packet = ip6::decode(bytes.data() + 14, bytes.size() - 14);
        count += packet.protocol == 58 && packet.length >= 24 && packet.payload[0] == 135 &&
                 !memcmp(packet.payload + 8, address.bytes, 16);
    }
    return count;
}

void conflict(const ip6::Address& address) {
    std::vector<uint8_t> data(32);
    data[0] = 136;
    data[4] = 0x20;
    std::copy(address.bytes, address.bytes + 16, data.begin() + 8);
    data[24] = 2;
    data[25] = 1;
    data[26] = 2;
    data[31] = 0x80;
    send(data);
}

void stable_conflicts(void (*reset)()) {
    unsigned rounded_holds = 0;
    for (int jitter : {0, 100}) {
        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        auto data = advertisement(0);
        prefix(data, 0xc0, 100, 60);
        send(data);
        auto original = prefix_address()->address;
        ipv6_poll();
        assert(dad_probes(original) == 1);
        ticks = 50;
        conflict(original);
        ipv6_poll();
        assert(!find(original) && prefix_address());
        auto replacement = prefix_address()->address;
        ipv6_test_dad_jitter(jitter);
        ipv6_poll();
        // A conflict late in tick 50 has not waited a full second at tick 150.
        // Check both endpoints of the unchanged zero-to-one-second jitter.
        ticks = 150 + jitter;
        ipv6_poll();
        unsigned before_full_interval = dad_probes(replacement);
        ticks++;
        ipv6_poll();
        unsigned after_full_interval = dad_probes(replacement);
        bool matched = !before_full_interval && after_full_interval == 1;
        rounded_holds += matched;
        std::printf("IPV6_ROUTER_DAD_TICK_BOUNDARY jitter=%d before=%u after=%u matched=%u\n",
                    jitter, before_full_interval, after_full_interval, matched);
        std::fflush(stdout);
    }
    assert(rounded_holds == 2);

    unsigned delayed = 0, stable_removed = 0, plain_removed = 0, inherited = 0;
    unsigned cleaned_prefixes = 0, protected_routes = 0;
    for (unsigned flags : {0x40u, 0xc0u}) {
        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        auto data = advertisement(0);
        prefix(data, flags, 100, 60);
        send(data);
        assert(prefix_address() && (prefix_address()->flags & 0x800));
        auto original = prefix_address()->address;
        auto owner = ip6::address_owner(1, original);
        ipv6_poll();
        assert(dad_probes(original) == 1);
        ticks = 50;
        conflict(original);
        ipv6_poll();
        ipv6_poll();
        assert(!find(original) && prefix_address());
        auto replacement = prefix_address()->address;
        assert(!(replacement == original) && ip6::address_owner(1, replacement) != owner);
        unsigned early = dad_probes(replacement);
        ticks = 149;
        ipv6_poll();
        unsigned before_minimum = dad_probes(replacement);
        ticks = 251;
        ipv6_poll();
        unsigned at_maximum = dad_probes(replacement);
        bool matched = !early && !before_minimum && at_maximum == 1;
        delayed += matched;
        std::printf("IPV6_ROUTER_STABLE_DELAY flags=%x early=%u before_minimum=%u "
                    "at_maximum=%u matched=%u\n",
                    flags, early, before_minimum, at_maximum, matched);
        std::fflush(stdout);

        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        data = advertisement(0);
        prefix(data, flags, 100, 60);
        send(data);
        std::vector<ip6::Address> attempted;
        for (unsigned trial = 0; trial < 4; trial++) {
            assert(prefix_address() && (prefix_address()->flags & 0x840) == 0x840);
            auto address = prefix_address()->address;
            assert(std::find(attempted.begin(), attempted.end(), address) == attempted.end());
            attempted.push_back(address);
            conflict(address);
            ipv6_poll();
        }
        bool removed = !prefix_address();
        stable_removed += removed;
        cleaned_prefixes += !learned();
        std::printf("IPV6_ROUTER_STABLE_LIMIT flags=%x attempts=%zu failed_visible=%u "
                    "prefix_route=%u matched=%u\n",
                    flags, attempted.size(), !removed, learned(), removed);
        std::fflush(stdout);

        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        assert(!ip6::configuration_write(1, ip6::ConfigurationKey::dad_transmits, 3));
        data = advertisement(0);
        prefix(data, flags, 100, 60);
        send(data);
        original = prefix_address()->address;
        ipv6_poll();
        ticks = 100;
        ipv6_poll();
        ticks = 200;
        ipv6_poll();
        assert(dad_probes(original) == 3 && (prefix_address()->flags & 0x40));
        ticks = 250;
        conflict(original);
        ipv6_poll();
        assert(!find(original) && prefix_address());
        auto cache = ipv6_address_cache(*prefix_address());
        matched = cache.preferred == 60 && cache.valid == 100 && cache.created == 250 &&
                  cache.updated == 250;
        inherited += matched;
        for (const auto& route : routes())
            if (route.learned && route.prefix == 64)
                assert(route.expires == 10000);
        std::printf("IPV6_ROUTER_STABLE_LIFETIMES flags=%x preferred=%u valid=%u created=%u "
                    "updated=%u matched=%u\n",
                    flags, cache.preferred, cache.valid, cache.created, cache.updated, matched);
        std::fflush(stdout);

        prepare(reset);
        data = advertisement(0);
        prefix(data, flags, 100, 60);
        send(data);
        assert(prefix_address() && !(prefix_address()->flags & 0x880));
        original = prefix_address()->address;
        conflict(original);
        ipv6_poll();
        removed = !find(original);
        plain_removed += removed;
        cleaned_prefixes += !learned();
        std::printf("IPV6_ROUTER_PLAIN_CONFLICT flags=%x failed_visible=%u prefix_route=%u "
                    "matched=%u\n",
                    flags, !removed, learned(), removed);
        std::fflush(stdout);
    }

    for (bool stale : {false, true}) {
        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        auto data = advertisement(0);
        prefix(data, 0xc0, 100, 60);
        prefix(data, 0x80, 100, 60, 2);
        send(data);
        auto initial = routes();
        auto advertised = std::find_if(initial.begin(), initial.end(), [](const auto& route) {
            return route.learned && route.destination == network();
        });
        auto unrelated = std::find_if(initial.begin(), initial.end(), [](const auto& route) {
            return route.learned && route.destination == network(2);
        });
        assert(advertised != initial.end() && unrelated != initial.end());
        uint64_t unrelated_owner = unrelated->owner;
        if (stale)
            assert(!ipv6_route_control(*advertised, true, false));
        Ipv6Route manual{network(), {}, 1, stale ? 256u : 10u, 64, 3};
        assert(!ipv6_route_control(manual, false, true));
        auto with_manual = routes();
        auto configured =
            std::find_if(with_manual.begin(), with_manual.end(), [&](const auto& route) {
                return !route.learned && route.destination == network() &&
                       route.metric == manual.metric;
            });
        assert(configured != with_manual.end());
        uint64_t manual_owner = configured->owner;
        for (unsigned trial = 0; trial < 4; trial++) {
            assert(prefix_address());
            auto address = prefix_address()->address;
            conflict(address);
            ipv6_poll();
        }
        bool manual_present = false, unrelated_present = false;
        for (const auto& route : routes()) {
            manual_present |= route.owner == manual_owner && !route.learned &&
                              route.destination == network() && route.metric == manual.metric &&
                              route.protocol == 3 && !route.expires;
            unrelated_present |= route.owner == unrelated_owner && route.learned &&
                                 route.destination == network(2) && route.expires == 10000;
        }
        bool matched = !prefix_address() && manual_present && unrelated_present;
        protected_routes += matched;
        std::printf("IPV6_ROUTER_EXHAUSTED_OWNER stale=%u manual=%u unrelated=%u matched=%u\n",
                    stale, manual_present, unrelated_present, matched);
        std::fflush(stdout);
    }

    for (unsigned kind : {0u, 1u, 2u}) {
        prepare(reset);
        assert(!ip6::configuration_secret(1, network(99)));
        auto data = advertisement(0);
        prefix(data, 0xc0, 100, 60);
        send(data);
        auto initial = routes();
        auto advertised = std::find_if(initial.begin(), initial.end(), [](const auto& route) {
            return route.learned && route.destination == network();
        });
        assert(advertised != initial.end());
        uint64_t route_owner = advertised->owner;
        auto configured = network();
        configured.bytes[15] = 0x77;
        assert(!(configured == prefix_address()->address));
        uint16_t flags = kind == 1 ? 0x202 : 2;
        Ipv6AddressLifetimes lifetime{kind == 2 ? 60u : UINT32_MAX, kind == 2 ? 100u : UINT32_MAX};
        assert(!ipv6_address_add({configured, 1, flags, 64}, lifetime));
        uint64_t configured_owner = ip6::address_owner(1, configured);
        for (unsigned trial = 0; trial < 4; trial++) {
            const Ipv6Address* candidate = nullptr;
            for (unsigned n = 0; auto entry = ipv6_address(n); n++)
                if (entry->index == 1 && (entry->flags & 0x800) &&
                    entry->address.matches(network(), 64))
                    candidate = entry;
            assert(candidate);
            auto address = candidate->address;
            conflict(address);
            ipv6_poll();
        }
        auto current = find(configured);
        bool matched = current && ip6::address_owner(1, configured) == configured_owner &&
                       ipv6_address_cache(*current).valid == lifetime.valid &&
                       ip6::learned_route_present(route_owner);
        protected_routes += matched;
        std::printf("IPV6_ROUTER_SHARED_PREFIX kind=%u retained=%u\n", kind, matched);
        std::fflush(stdout);
    }

    prepare(reset);
    auto carrier_data = advertisement(0);
    prefix(carrier_data, 0x40, 100, 60);
    send(carrier_data);
    auto first = prefix_address()->address;
    ipv6_poll();
    assert(dad_probes(first) == 1);
    ticks = 50;
    ipv6_test_carrier(0, false);
    ipv6_poll();
    ticks = 60;
    ipv6_test_carrier(0, true);
    ipv6_poll();
    bool initial_restart = dad_probes(first) == 2;

    prepare(reset);
    assert(!ip6::configuration_secret(1, network(99)));
    carrier_data = advertisement(0);
    prefix(carrier_data, 0x40, 100, 60);
    send(carrier_data);
    first = prefix_address()->address;
    ipv6_poll();
    ticks = 10;
    conflict(first);
    ipv6_poll();
    ipv6_poll();
    assert(prefix_address() && !find(first));
    auto retried = prefix_address()->address;
    ticks = 20;
    ipv6_test_carrier(0, false);
    ipv6_poll();
    ticks = 30;
    ipv6_test_carrier(0, true);
    ipv6_poll();
    ticks = 109;
    ipv6_poll();
    bool stable_hold = !dad_probes(retried);
    ticks = 211;
    ipv6_poll();
    stable_hold &= dad_probes(retried) == 1;
    ticks = 220;
    ipv6_test_carrier(0, false);
    ipv6_poll();
    ticks = 230;
    ipv6_test_carrier(0, true);
    ipv6_poll();
    bool retry_restart = dad_probes(retried) == 2;
    std::printf("IPV6_ROUTER_DAD_CARRIER initial_restart=%u stable_hold=%u retry_restart=%u\n",
                initial_restart, stable_hold, retry_restart);
    std::fflush(stdout);

    // A failed configured permanent object remains visible; exhausting an
    // automatic address must not delete that independent userspace object.
    prepare(reset);
    assert(!ipv6_address_add({generated(), 1, 0x80, 64}));
    auto owner = ip6::address_owner(1, generated());
    auto data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    conflict(generated());
    ipv6_poll();
    auto current = find(generated());
    bool permanent =
        current && (current->flags & 0x88) == 0x88 && ip6::address_owner(1, generated()) == owner;
    std::printf("IPV6_ROUTER_PREFIX_CLEANUP cleaned=%u protected=%u expected=4,5\n",
                cleaned_prefixes, protected_routes);
    std::fflush(stdout);
    assert(cleaned_prefixes == 4 && protected_routes == 5);
    std::printf("IPV6_ROUTER_CONFLICT_SUMMARY delayed=%u stable_removed=%u plain_removed=%u "
                "configured_permanent=%u inherited=%u carrier=%u\n",
                delayed, stable_removed, plain_removed, permanent, inherited,
                initial_restart && stable_hold && retry_restart);
    std::fflush(stdout);
    assert(delayed == 2 && stable_removed == 2 && plain_removed == 2 && permanent &&
           inherited == 2 && initial_restart && stable_hold && retry_restart);
}

void coalesced_withdrawal(void (*reset)()) {
    prepare(reset);
    auto data = advertisement(0);
    prefix(data, 0xc0, 100, 60);
    send(data);
    assert(!ipv6_address_add({generated(), 1, 2, 64}, {}, true));
    auto companion = generated();
    companion.bytes[15] ^= 1;
    assert(!ipv6_address_add({companion, 1, 0x202, 64}));
    auto other = network(9);
    assert(!ipv6_address_add({other, 2, 2, 64}));
    auto other_owner = ip6::address_owner(2, other);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::disabled, 1));
    unsigned remaining = 0;
    bool other_route = false;
    for (const auto& route : routes()) {
        remaining += route.index == 1;
        other_route |= route.index == 2 && route.destination == network(9);
    }
    bool isolated =
        ipv6_owned(2, other) && ip6::address_owner(2, other) == other_owner && other_route;
    std::printf("IPV6_ROUTER_WITHDRAWAL remaining_routes=%u other_interface=%u\n", remaining,
                isolated);
    std::fflush(stdout);
    assert(!remaining && isolated);
}

void retransmission(void (*reset)()) {
    prepare(reset);
    assert(!ipv6_address_add({local(2), 2, 2, 64}));
    assert(!ip6::configuration_write(2, ip6::ConfigurationKey::accept_ra, 1));
    auto data = advertisement(0);
    put(data, 12, 2000);
    send(data);
    put(data, 12, 3000);
    auto bytes = frame(data);
    ipv6_receive(*net_info(2), bytes.data(), bytes.size());
    uint8_t mac[6];
    auto target = local(0x90);
    assert(!ip6::neighbor_resolve(1, local(), target, mac));
    assert(!ip6::neighbor_resolve(2, local(2), target, mac));
    auto probes = [&](unsigned lane) {
        unsigned count = 0;
        for (const auto& emitted : ipv6_emitted(lane)) {
            auto packet = ip6::decode(emitted.data() + 14, emitted.size() - 14);
            if (packet.protocol == 58 && packet.length >= 24 && packet.payload[0] == 135 &&
                !memcmp(packet.payload + 8, target.bytes, 16))
                count++;
        }
        return count;
    };

    struct Sample {
        uint64_t at;
        unsigned first, second;
    } samples[]{{0, 1, 1},   {100, 1, 1}, {199, 1, 1}, {200, 2, 1}, {299, 2, 1},
                {300, 2, 2}, {399, 2, 2}, {400, 3, 2}, {599, 3, 2}, {600, 3, 3}};

    bool timeline = true;
    unsigned first[2]{};
    for (const auto& sample : samples) {
        ticks = sample.at;
        ipv6_poll();
        auto one = probes(0), two = probes(1);
        timeline &= one == sample.first && two == sample.second;
        if (one > 1 && !first[0])
            first[0] = ticks;
        if (two > 1 && !first[1])
            first[1] = ticks;
    }
    std::printf("IPV6_ROUTER_RETRANS lane0_first_ticks=%u lane1_first_ticks=%u timeline=%u\n",
                first[0], first[1], timeline);
    std::fflush(stdout);
    assert(timeline && first[0] == 200 && first[1] == 300);
}

void routers_and_parameters(void (*reset)()) {
    prepare(reset);
    assert(!ipv6_address_add({network(5), 1, 2, 64}));
    Ipv6Route manual{{}, local(0x80), 1, 1024, 0, 9};
    assert(!ipv6_route_control(manual, false, true));
    send(advertisement(30));
    auto data = advertisement(30);
    data[5] = 8;
    send(data, local(0x81));
    Ipv6Path path;
    assert(!ipv6_path({}, network(6), 1, path) && path.next_hop == local(0x81));
    send(advertisement(0), local(0x81));
    assert(!ipv6_path({}, network(6), 1, path) && path.next_hop == local(0x80));
    data = advertisement(1);
    unsigned at = data.size();
    data.resize(at + 8);
    data[at] = 5;
    data[at + 1] = 1;
    put(data, at + 4, 1400);
    put(data, 12, 2000);
    put(data, 8, 40000);
    send(data);
    assert(ip6::link_mtu(1) == 1400 && net_info(1)->mtu == 1500);
    assert(ip6::link_retransmit(1) == 200);
    assert(ip6::link_reachable(1) >= 2000 && ip6::link_reachable(1) <= 6000);
    assert(!ipv6_path({}, network(6), 1, path) && path.mtu == 1400);
    ticks = 100;
    ipv6_poll();
    assert(!learned());
    bool preserved = false;
    for (const auto& route : routes())
        preserved |= !route.learned && !route.prefix && route.gateway == local(0x80);
    assert(preserved);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::disabled, 1));
    assert(ip6::link_mtu(1) == 1500 && ip6::link_hop_limit(1) == 64);
}

unsigned solicitations() {
    unsigned count = 0;
    for (const auto& bytes : ipv6_emitted(0)) {
        auto packet = ip6::decode(bytes.data() + 14, bytes.size() - 14);
        if (packet.protocol != 58 || packet.length != 16 || packet.payload[0] != 133)
            continue;
        auto destination = ip6::all_nodes();
        destination.bytes[15] = 2;
        assert(packet.header.source == local() && packet.header.destination == destination);
        assert(packet.header.hop_limit == 255);
        assert(!ip6::checksum(local(), destination, 58, packet.payload, packet.length));
        assert(packet.payload[8] == 1 && packet.payload[9] == 1);
        count++;
    }
    return count;
}

void solicit(void (*reset)()) {
    prepare(reset);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::router_solicitations, 2));
    unsigned first = 0, second = 0;
    for (ticks = 0; ticks <= 1000; ticks++) {
        ipv6_poll();
        auto count = solicitations();
        if (count && !first)
            first = ticks + 1;
        if (count == 2 && !second)
            second = ticks + 1;
    }
    assert(first && first <= 101 && second > first);
    assert(second - first >= 360 && second - first <= 440 && solicitations() == 2);
    prepare(reset);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::router_solicitations, -1));
    ipv6_poll();
    ticks = 100;
    ipv6_poll();
    assert(solicitations() == 1);
    send(advertisement(0));
    for (ticks = 101; ticks <= 600; ticks++)
        ipv6_poll();
    assert(solicitations() == 2);
    send(advertisement(30));
    for (ticks = 601; ticks <= 2000; ticks++)
        ipv6_poll();
    assert(solicitations() == 2);

    prepare(reset);
    ipv6_test_budget(0);
    assert(!ip6::configuration_write(1, ip6::ConfigurationKey::router_solicitations, 1));
    for (ticks = 0; ticks <= 1000; ticks++)
        ipv6_poll();
    assert(!solicitations());
    ipv6_test_budget(UINT32_MAX);
    for (ticks = 1001; ticks <= 2000; ticks++)
        ipv6_poll();
    assert(solicitations() == 1);
}

void output_parameters(void (*reset)()) {
    prepare(reset);
    assert(!ipv6_address_add({network(5), 1, 2, 64}));
    auto data = advertisement();
    unsigned at = data.size();
    data.resize(at + 8);
    data[at] = 5;
    data[at + 1] = 1;
    put(data, at + 4, 1400);
    send(data);
    auto socket = inet6_allocate(2);
    assert(socket);
    socket->protocol = 17;
    socket->index = 1;
    socket->dont_fragment = true;
    Inet6Address target;
    target.address = network(6);
    target.port = 0x1234;
    std::vector<uint8_t> large(1360);
    auto large_result = inet6_send(socket, target, large.data(), large.size(), true);
    assert(large_result == -90);
    const uint8_t payload[]{1, 2, 3, 4};
    ipv6_test_budget(0);
    assert(inet6_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
    // An admitted packet retains its selected hop limit through a later RA.
    data[4] = 80;
    send(data);
    ipv6_test_budget(UINT32_MAX);
    ipv6_poll();
    auto observed_hops = [] {
        unsigned result = 0;
        for (const auto& bytes : ipv6_emitted(0)) {
            auto packet = ip6::decode(bytes.data() + 14, bytes.size() - 14);
            if (packet.protocol == 17)
                result = packet.header.hop_limit;
        }
        return result;
    };
    assert(observed_hops() == 48);
    assert(inet6_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv6_poll();
    assert(observed_hops() == 80);
    socket->hops = 19;
    assert(inet6_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv6_poll();
    assert(observed_hops() == 19);
    inet6_close(socket);
}
} // namespace

void ipv6_router_tests(void (*reset)()) {
    admission(reset);
    flags_and_dad(reset);
    renewed_ownership(reset);
    initial_zero(reset);
    stable_conflicts(reset);
    coalesced_withdrawal(reset);
    retransmission(reset);
    lifetimes(reset);
    replacement(reset);
    routers_and_parameters(reset);
    solicit(reset);
    output_parameters(reset);
    std::puts("IPV6_ROUTER_MODEL_PASS admission=9 flags=4 lifetimes=1 ownership=1 routers=1 RS=1");
}
