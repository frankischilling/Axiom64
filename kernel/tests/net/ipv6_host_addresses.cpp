// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/net/ipv6_host_addresses.cpp
 * @brief   IPv6 host address and route lifetime tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Covers source selection, lifetime expiry, local routes, and link configuration.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "ipv6_host_fixture.hpp"
#include "net/netlink.hpp"
#include "net/ipv6/reassembly.hpp"
#include "net/ipv6/configuration.hpp"
#include "fs/proc/ipv6.hpp"
#include "../../net/ipv6/socket.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <unordered_set>
#include <vector>

#include "net/ipv6/icmp.hpp"
#include "core/time.hpp"

namespace ipv6_fixture {
using namespace ax;

static bool route_present(const Ipv6Route& value) {
    Ipv6Route entries[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(entries, sizeof(entries) / sizeof(*entries));
    for (size_t n = 0; n < count; n++)
        if (entries[n].index == value.index && entries[n].prefix == value.prefix &&
            entries[n].metric == value.metric && entries[n].protocol == value.protocol &&
            entries[n].gateway == value.gateway && entries[n].destination == value.destination)
            return true;
    return false;
}

static bool prefix_present(unsigned index, const ip6::Address& destination, uint8_t prefix) {
    return route_present({destination, {}, index, 256, prefix, 2});
}

void prefix_route_order() {
    reset();
    auto local = address(0, 2), network = address(0, 0);
    Ipv6Route manual{network, {}, 1, 256, 64, 99};
    assert(!route(manual, false) && !change(1, local));
    assert(route_present(manual) && !prefix_present(1, network, 64));
    assert(!change(1, local, true, true) && !route_present(manual));

    reset();
    manual.metric = 5;
    assert(!route(manual, false) && !change(1, local));
    assert(route_present(manual) && prefix_present(1, network, 64));
    assert(!change(1, local, true, true));
    assert(!route_present(manual) && prefix_present(1, network, 64));
    Ipv6Route wildcard{network, {}, 1, 0, 64, 0};
    assert(!route(wildcard, true) && !prefix_present(1, network, 64));

    reset();
    manual.metric = 512;
    assert(!route(manual, false) && !change(1, local));
    assert(!route(wildcard, true));
    assert(!prefix_present(1, network, 64) && route_present(manual));
    assert(!change(1, local, true, true) && !route_present(manual));

    reset();
    Ipv6Route gateway{network, address(0, 1, true), 1, 5, 64, 99};
    assert(!change(1, local) && !route(manual, false) && !route(gateway, false));
    assert(!change(1, local, true, true));
    assert(!prefix_present(1, network, 64) && route_present(manual) && route_present(gateway));
    wildcard.protocol = 98;
    assert(route(wildcard, true) == -3);
    wildcard.protocol = 99;
    assert(!route(wildcard, true) && !route_present(gateway) && route_present(manual));
    wildcard.metric = 256;
    assert(route(wildcard, true) == -3);
    wildcard.metric = 512;
    assert(!route(wildcard, true) && !route_present(manual));
}

void prefix_lifetimes() {
    reset();
    auto local = address(0, 2), network = address(0, 0);
    assert(!change(1, local, false));
    Ipv6Route collision{network, {}, 1, 256, 64, 3};
    assert(!ipv6_owned(1, local) && prefix_present(1, network, 64));
    assert(route(collision, false) == -17);
    deliver(0, advertisement(0, local, ip6::all_nodes()));
    assert(!ipv6_owned(1, local, true) && prefix_present(1, network, 64));
    assert(route(collision, false) == -17);
    assert(!change(1, local, true, true) && !prefix_present(1, network, 64));
    Ipv6Address other{address(0, 3), 1, 0x282, 64};
    assert(!ipv6_address_add(other) && !prefix_present(1, network, 64));
    assert(!change(1, local) && prefix_present(1, network, 64));
    assert(!change(1, local, true, true) && prefix_present(1, network, 64));
    assert(!ipv6_address_remove(1, other.address) && prefix_present(1, network, 64));
    collision.metric = 0;
    collision.protocol = 2;
    assert(!route(collision, true) && !prefix_present(1, network, 64));
    reset();
    for (unsigned n = 0; n < ipv6_address_capacity; n++) {
        assert(!change(1, address(n, 2)));
        assert(!ipv6_address_add({address(n, 3), 1, 0x282, 64}));
        assert(!change(1, address(n, 2), true, true));
        assert(!ipv6_address_remove(1, address(n, 3)));
    }
    assert(change(1, address(31, 2)) == -105 && !ipv6_owned(1, address(31, 2), true));
}

static int configure_lifetime(unsigned index, const ip6::Address& value, uint32_t preferred,
                              uint32_t valid, uint16_t flags = 0x605, uint8_t prefix = 64,
                              uint32_t address_flags = 2, bool privileged = true) {
    uint8_t input[72]{};
    NetlinkHeader header{sizeof(input), 20, flags, 17, 0};
    memcpy(input, &header, 16);
    input[16] = 10;
    input[17] = prefix;
    input[18] = address_flags;
    memcpy(input + 20, &index, 4);
    input[24] = 20;
    input[26] = 1;
    memcpy(input + 28, value.bytes, 16);
    input[44] = 8;
    input[46] = 8;
    memcpy(input + 48, &address_flags, 4);
    input[52] = 20;
    input[54] = 6;
    uint32_t lifetime[4] = {preferred, valid, 0x12345678, 0x87654321};
    memcpy(input + 56, lifetime, sizeof(lifetime));
    std::vector<uint8_t> output(routing_capacity(header) + 16, 0xa7);
    size_t size = routing_reply(input, 100, false, output.data(), privileged);
    assert(size >= 36 && size <= routing_capacity(header));
    assert(std::all_of(output.begin() + routing_capacity(header), output.end(),
                       [](auto byte) { return byte == 0xa7; }));
    int error;
    memcpy(&error, output.data() + 16, 4);
    return error;
}

struct AddressObservation {
    bool present = false;
    uint8_t prefix = 0;
    uint32_t flags = 0;
    std::array<uint32_t, 4> cache{};
};

static AddressObservation address_observation(unsigned index, const ip6::Address& value) {
    uint8_t input[24]{};
    NetlinkHeader header{sizeof(input), 22, 0x301, 18, 0};
    memcpy(input, &header, 16);
    input[16] = 10;
    std::vector<uint8_t> output(routing_capacity(header) + 16, 0xa7);
    size_t size = routing_reply(input, 100, false, output.data(), true);
    assert(size <= routing_capacity(header));
    assert(std::all_of(output.begin() + routing_capacity(header), output.end(),
                       [](auto byte) { return byte == 0xa7; }));
    for (size_t at = 0; at < size;) {
        NetlinkHeader row;
        memcpy(&row, output.data() + at, sizeof(row));
        assert(row.length >= 20 && row.length <= size - at);
        if (row.type == 20) {
            uint32_t actual_index;
            memcpy(&actual_index, output.data() + at + 20, 4);
            AddressObservation result;
            result.prefix = output[at + 17];
            for (size_t field = at + 24; field < at + row.length;) {
                uint16_t length, type;
                memcpy(&length, output.data() + field, 2);
                memcpy(&type, output.data() + field + 2, 2);
                assert(length >= 4 && length <= at + row.length - field);
                if (type == 1 && length == 20)
                    result.present = actual_index == index &&
                                     !memcmp(output.data() + field + 4, value.bytes, 16);
                if (type == 8 && length == 8)
                    memcpy(&result.flags, output.data() + field + 4, 4);
                if (type == 6 && length == 20)
                    memcpy(result.cache.data(), output.data() + field + 4, 16);
                field += (length + 3) & ~size_t(3);
            }
            if (result.present)
                return result;
        }
        at += (row.length + 3) & ~size_t(3);
    }
    return {};
}

void finite_address_lifetimes() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        auto permanent = address(lane, 2), finite = address(lane, 3), remote = address(lane, 9);
        assert(!change(lane + 1, permanent));
        ticks = 1000;
        assert(!configure_lifetime(lane + 1, finite, 2, 8, 0x605, 96));
        auto initial = address_observation(lane + 1, finite);
        assert(initial.present && initial.prefix == 96 && initial.flags == 2);
        assert((initial.cache == std::array<uint32_t, 4>{2, 8, 1000, 1000}));
        Ipv6Path path;
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == finite);
        auto key = ip6::path_key(path, remote);
        assert(ip6::path_mtu_cache.learn(key, 1500, 1400, ticks) == 1400);
        auto held = ip6::path_mtu_cache.retain(key, ticks);
        assert(held);
        ticks = 1199;
        ipv6_poll();
        auto before = address_observation(lane + 1, finite);
        assert(before.flags == 2 && before.cache[0] == 1 && before.cache[1] == 7);
        ticks = 1200;
        ipv6_poll();
        auto deprecated = address_observation(lane + 1, finite);
        assert(deprecated.present && deprecated.flags == 0x22 && deprecated.cache[0] == 0 &&
               deprecated.cache[1] == 6 && ipv6_owned(lane + 1, finite));
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == permanent);
        assert(!ipv6_path(finite, remote, lane + 1, path) && path.source == finite);
        ticks = 1799;
        ipv6_poll();
        assert(ipv6_owned(lane + 1, finite) && address_observation(lane + 1, finite).cache[1] == 1);
        ticks = 1800;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, finite, true) &&
               !address_observation(lane + 1, finite).present);
        auto network = address(lane, 0);
        assert(!prefix_present(lane + 1, network, 96) && prefix_present(lane + 1, network, 64));
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == permanent);
        assert(!ip6::path_mtu_cache.active(held, key, ticks));
        assert(ip6::path_mtu_cache.lookup(key, 1500, ticks) == 1500);
        assert(ip6::path_mtu_cache.metric(held) == 1400);
        ip6::path_mtu_cache.release(held);

        reset();
        ticks = 1000;
        assert(!configure_lifetime(lane + 1, finite, 2, 8));
        ticks = 1500;
        assert(configure_lifetime(lane + 1, finite, 6, 5, 0x105, 64, 2, false) == -1);
        auto protected_address = address_observation(lane + 1, finite);
        assert(protected_address.flags == 2 && protected_address.cache[3] == 1000);
        assert(configure_lifetime(lane + 1, finite, 0, 5) == -17);
        assert(configure_lifetime(lane + 1, finite, 6, 5, 0x105) == -22);
        assert(!configure_lifetime(lane + 1, finite, 0, 5, 0x105, 96));
        auto replaced = address_observation(lane + 1, finite);
        assert(replaced.present && replaced.prefix == 64 && replaced.flags == 0x22);
        assert((replaced.cache == std::array<uint32_t, 4>{0, 5, 1000, 1500}));
        ticks = 1999;
        ipv6_poll();
        assert(ipv6_owned(lane + 1, finite));
        ticks = 2000;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, finite, true));
        assert(configure_lifetime(lane + 1, finite, 0, 0) == -22);
        assert(!configure_lifetime(lane + 1, finite, 0, UINT32_MAX, 5));
        auto forever = address_observation(lane + 1, finite);
        assert(forever.flags == 0xa2 && forever.cache[1] == UINT32_MAX);
        reset();
    }
}

void finite_address_dad() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        ticks = 1000;
        auto local = address(lane, 2), remote = address(lane, 9);
        assert(!configure_lifetime(lane + 1, local, 2, 4, 0x605, 64, 0));
        ipv6_poll();
        assert(address_observation(lane + 1, local).flags == 0x40);
        Ipv6Path path;
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source.loopback());
        ticks = 1050;
        assert(!configure_lifetime(lane + 1, local, 2, 8, 0x105, 96, 0));
        auto refreshed = address_observation(lane + 1, local);
        assert(refreshed.prefix == 64 && refreshed.cache[2] == 1000 && refreshed.cache[3] == 1050);
        ticks = 1099;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, local));
        ticks = 1100;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, local));
        ticks = 1101;
        ipv6_poll();
        assert(ipv6_owned(lane + 1, local) && address_observation(lane + 1, local).flags == 0);
        ticks = 1250;
        ipv6_poll();
        assert(address_observation(lane + 1, local).flags == 0x20);
        ticks = 1850;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, local, true));

        reset();
        ticks = 1000;
        assert(!configure_lifetime(lane + 1, local, 1, 1, 0x605, 64, 0));
        ipv6_poll();
        ticks = 1100;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, local, true) && ipv6_path({}, remote, lane + 1, path) == -101);

        // Retain the original NODAD recreation input alongside ordinary DAD.
        for (unsigned requested_flags : {0u, 2u}) {
            reset();
            ticks = 1000;
            assert(!configure_lifetime(lane + 1, local, 2, 8, 0x605, 64, 0));
            ipv6_poll();
            auto failed_owner = ip6::address_owner(lane + 1, local);
            assert(failed_owner);
            deliver(lane, advertisement(lane, local, ip6::all_nodes()));
            // Linux removes a failed finite configured owner before its lifetime expires.
            // A later successful RTM_NEWADDR starts DAD for a new address owner.
            assert(!address_observation(lane + 1, local).present &&
                   !ip6::address_owner(lane + 1, local));
            assert(!configure_lifetime(lane + 1, local, 2, 8, 0x105, 64, requested_flags));
            auto replacement = address_observation(lane + 1, local);
            assert(replacement.present && replacement.flags == (requested_flags ? 2u : 0x40u) &&
                   replacement.cache[0] == 2 && replacement.cache[1] == 8);
            assert(ip6::address_owner(lane + 1, local) &&
                   ip6::address_owner(lane + 1, local) != failed_owner);
            assert(ipv6_owned(lane + 1, local) == bool(requested_flags) &&
                   ipv6_owned(lane + 1, local, true));
        }
        reset();
    }
}

static Ipv6Route prefix_observation(unsigned index, const ip6::Address& address) {
    Ipv6Route entries[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(entries, sizeof(entries) / sizeof(*entries));
    for (size_t n = 0; n < count; n++)
        if (entries[n].index == index && entries[n].prefix == 64 &&
            address.matches(entries[n].destination, 64))
            return entries[n];
    return {};
}

void source_lifetime_preferences() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        auto first = address(lane, 2), second = address(lane, 3), remote = address(lane, 9);
        assert(!configure_lifetime(lane + 1, first, 8, 8));
        assert(!configure_lifetime(lane + 1, second, 8, 8));
        Ipv6Path path;
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == second);
        assert(!configure_lifetime(lane + 1, second, 0, 8, 0x105));
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == first);
        assert(!configure_lifetime(lane + 1, first, 0, 8, 0x105));
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == second);
        assert(!ipv6_address_remove(lane + 1, first));
        assert(!configure_lifetime(lane + 1, first, 0, 8));
        assert(!ipv6_path({}, remote, lane + 1, path) && path.source == first);
        reset();
    }
}

void finite_prefix_lifetimes() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        ticks = 1000;
        auto first = address(lane, 2), second = address(lane, 3), remote = address(lane, 9);
        assert(!configure_lifetime(lane + 1, first, 8, 8));
        auto initial = prefix_observation(lane + 1, first);
        assert(initial.owner);
        ticks = 1100;
        assert(!configure_lifetime(lane + 1, second, 4, 4));
        Ipv6Path path;
        assert(!ipv6_path(first, remote, lane + 1, path));
        auto key = ip6::path_key(path, remote);
        assert(ip6::path_mtu_cache.learn(key, 1500, 1400, ticks) == 1400);
        auto held = ip6::path_mtu_cache.retain(key, ticks);
        assert(held && prefix_observation(lane + 1, first).owner == initial.owner);
        assert(!ipv6_address_remove(lane + 1, second));
        ticks = 1499;
        ipv6_poll();
        assert(!ipv6_path(first, remote, lane + 1, path) && path.route_owner == initial.owner);
        ticks = 1500;
        ipv6_poll();
        assert(ipv6_owned(lane + 1, first));
        assert(ipv6_path(first, remote, lane + 1, path) == -101);
        assert(!ip6::path_mtu_cache.active(held, key, ticks));
        assert(ip6::path_mtu_cache.metric(held) == 1400);
        ip6::path_mtu_cache.release(held);

        reset();
        ticks = 1000;
        assert(!change(lane + 1, first));
        assert(!configure_lifetime(lane + 1, second, 8, 8));
        initial = prefix_observation(lane + 1, first);
        ticks = 1100;
        assert(!ipv6_address_remove(lane + 1, first));
        assert(prefix_observation(lane + 1, second).owner == initial.owner);
        ticks = 1799;
        ipv6_poll();
        assert(!ipv6_path(second, remote, lane + 1, path));
        ticks = 1800;
        ipv6_poll();
        assert(!prefix_observation(lane + 1, second).owner);

        reset();
        ticks = 1000;
        assert(!configure_lifetime(lane + 1, first, 4, 4));
        assert(!configure_lifetime(lane + 1, second, UINT32_MAX, UINT32_MAX, 0x605, 64, 0x202));
        initial = prefix_observation(lane + 1, first);
        assert(!ipv6_address_remove(lane + 1, first));
        ticks = 1400;
        ipv6_poll();
        assert(ipv6_owned(lane + 1, second) &&
               prefix_observation(lane + 1, second).owner == initial.owner);
        assert(ipv6_path(second, remote, lane + 1, path) == -101);
        ticks = 7400;
        ipv6_poll();
        assert(!prefix_observation(lane + 1, second).owner);
        reset();
    }
}

void retained_address_expiry() {
    for (bool bound : {false, true}) {
        reset();
        auto finite = address(0, 2), permanent = address(0, 3), remote = address(0, 1);
        assert(!change(1, permanent));
        assert(!ipv6_address_add({finite, 1, 2, 96}, {2, 8}));
        deliver(0, solicitation(0, finite));
        deliver(0, advertisement(0, remote, finite));
        auto socket = inet6_allocate(2);
        assert(socket);
        socket->local = finite;
        socket->peer = remote;
        socket->peer_port = __builtin_bswap16(uint16_t(55123));
        socket->connected = true;
        socket->bound = bound;
        assert(!inet6_bind_port(socket, finite, 59000));
        Inet6Address peer{10, socket->peer_port, 0, remote, 0};
        const uint8_t payload[16] = {'L', 'I', 'F', '6'};
        assert(inet6_send(socket, peer, payload, sizeof(payload)) == sizeof(payload));
        ipv6_poll();
        ticks = 200;
        ipv6_poll();
        assert(ipv6_owned(1, finite));
        assert(inet6_send(socket, peer, payload, sizeof(payload)) == sizeof(payload));
        ipv6_poll();
        ticks = 800;
        ipv6_poll();
        assert(!ipv6_owned(1, finite));
        Ipv6Path fresh;
        assert(!ipv6_path({}, remote, 1, fresh) && fresh.source == permanent);
        assert(ipv6_path(finite, remote, 1, fresh) == -99);
        emitted[0].clear();
        blocked = 1;
        assert(inet6_send(socket, peer, payload, sizeof(payload)) == sizeof(payload));
        inet6_close(socket);
        auto reused = inet6_allocate(2);
        assert(reused == socket);
        reused->local = permanent;
        blocked = 0;
        ipv6_poll();
        assert(emitted[0].size() == 1 && emitted[0][0].size() == 78);
        const auto& frame = emitted[0][0];
        assert(!memcmp(frame.data() + 22, finite.bytes, 16));
        assert(!memcmp(frame.data() + 62, payload, sizeof(payload)));
        assert(!ip6::checksum(finite, remote, 17, frame.data() + 54, 24));
        assert(!reused->transmitted && !reused->error);
        inet6_close(reused);
        reset();
    }
}

static std::vector<Ipv6Address> local_route_inventory(unsigned index = 0, uint8_t protocol = 2,
                                                      uint8_t table = 255, bool extended = false) {
    std::vector<uint8_t> input(28);
    input[16] = 10;
    input[20] = extended ? 0 : table;
    input[21] = protocol;
    input[23] = 2;
    auto attribute = [&](uint16_t type, uint32_t value) {
        uint16_t header[2] = {8, type};
        input.insert(input.end(), reinterpret_cast<uint8_t*>(header),
                     reinterpret_cast<uint8_t*>(header) + 4);
        input.insert(input.end(), reinterpret_cast<uint8_t*>(&value),
                     reinterpret_cast<uint8_t*>(&value) + 4);
    };
    if (index)
        attribute(4, index);
    if (extended)
        attribute(15, table);
    NetlinkHeader request{uint32_t(input.size()), 26, 0x301, 99, 0};
    memcpy(input.data(), &request, sizeof(request));
    size_t capacity = routing_capacity(request, input.data());
    std::vector<uint8_t> output(capacity + 16, 0xa7);
    size_t size = routing_reply(input.data(), 77, false, output.data(), true, true);
    assert(size >= 20 && size <= capacity);
    assert(std::all_of(output.begin() + capacity, output.end(),
                       [](auto byte) { return byte == 0xa7; }));
    std::vector<Ipv6Address> result;
    for (size_t at = 0; at < size;) {
        NetlinkHeader row;
        memcpy(&row, output.data() + at, sizeof(row));
        assert(row.length >= 20 && row.length <= size - at && row.sequence == 99 && row.port == 77);
        if (row.type == 3) {
            assert(row.length == 20 && at + row.length == size);
            int status;
            memcpy(&status, output.data() + at + 16, 4);
            assert(!status);
        } else {
            assert(row.type == 24 && row.length == 116);
            const auto body = output.data() + at;
            assert(body[16] == 10 && body[17] == 128 && body[18] == 0 && body[19] == 0 &&
                   body[20] == 255 && body[21] == 2 && body[22] == 0 && body[23] == 2);
            Ipv6Address value;
            value.prefix = 128;
            unsigned fields = 0;
            for (size_t field = at + 28; field < at + row.length;) {
                uint16_t length, type;
                memcpy(&length, output.data() + field, 2);
                memcpy(&type, output.data() + field + 2, 2);
                assert(length >= 4 && length <= at + row.length - field && type < 32);
                assert(!(fields & (1u << type)));
                fields |= 1u << type;
                const auto data = output.data() + field + 4;
                if (type == 1) {
                    assert(length == 20);
                    memcpy(value.address.bytes, data, 16);
                } else if (type == 4) {
                    assert(length == 8);
                    memcpy(&value.index, data, 4);
                } else if (type == 15) {
                    uint32_t actual;
                    assert(length == 8);
                    memcpy(&actual, data, 4);
                    assert(actual == 255);
                } else if (type == 6 || type == 12 || type == 20) {
                    assert(length == (type == 6 ? 8 : type == 12 ? 36 : 5));
                    assert(
                        std::all_of(data, data + length - 4, [](auto byte) { return byte == 0; }));
                } else
                    assert(false);
                field += (length + 3) & ~size_t(3);
            }
            assert(fields ==
                   ((1u << 1) | (1u << 4) | (1u << 6) | (1u << 12) | (1u << 15) | (1u << 20)));
            assert(!index || value.index == index);
            result.push_back(value);
        }
        at += (row.length + 3) & ~size_t(3);
    }
    return result;
}

void legacy_route_inventory() {
    reset();
    assert(!change(1, address(0, 2)));
    uint8_t input[36]{};
    NetlinkHeader request{sizeof(input), 26, 0x301, 101, 0};
    memcpy(input, &request, sizeof(request));
    input[16] = 10;
    input[20] = 255;
    input[21] = 99;
    input[23] = 2;
    uint32_t field[2] = {uint32_t(4 << 16 | 8), 2};
    memcpy(input + 28, field, sizeof(field));
    size_t capacity = routing_capacity(request, input);
    for (bool strict : {true, false}) {
        std::vector<uint8_t> output(capacity + 16, 0xa7);
        size_t length = routing_reply(input, 79, false, output.data(), true, strict);
        assert(length <= capacity && length >= 20);
        unsigned main = 0, local = 0;
        for (size_t at = 0; at < length;) {
            NetlinkHeader row;
            memcpy(&row, output.data() + at, sizeof(row));
            assert(row.length >= 20 && row.length <= length - at);
            if (row.type != 3) {
                assert(row.type == 24 && row.flags == 2 && !strict);
                main += output[at + 20] == 254 && output[at + 23] == 1;
                local += output[at + 20] == 255 && output[at + 23] == 2;
            }
            at += (row.length + 3) & ~size_t(3);
        }
        assert(main == (strict ? 0 : 1) && local == (strict ? 0 : 2));
        assert(std::all_of(output.begin() + capacity, output.end(),
                           [](auto byte) { return byte == 0xa7; }));
    }
}

void local_route_visibility() {
    reset();
    auto initial = local_route_inventory();
    assert(initial.size() == 1 && initial[0].index == ipv6_loopback &&
           initial[0].address.loopback());
    assert(!change(1, address(0, 2)));
    assert(!configure_lifetime(1, address(0, 8), 1, 2));
    assert(!change(2, address(1, 3), false));
    assert(local_route_inventory().size() == 3 && local_route_inventory(1).size() == 2 &&
           local_route_inventory(2).empty() && local_route_inventory(1, 99).empty());
    auto extended = local_route_inventory(1, 2, 255, true);
    assert(extended.size() == 2);
    assert(local_route_inventory(1, 2, 254).empty() && local_route_inventory(1, 2, 0).size() == 2);
    net_poll();
    ticks = 100;
    net_poll();
    assert(local_route_inventory(2).empty());
    ticks = 101;
    net_poll();
    assert(local_route_inventory(2).size() == 1);
    ticks = 200;
    assert(local_route_inventory(1).size() == 1);
    assert(!change(1, address(0, 10), false));
    net_poll();
    deliver(0, advertisement(0, address(0, 10), ip6::all_nodes()));
    assert(local_route_inventory(1).size() == 1);
    assert(!change(1, address(0, 2), true, true));
    assert(local_route_inventory(1).empty());
    assert(!change(2, address(1, 3), true, true));
    assert(local_route_inventory().size() == 1);
}

void queued_automatic_source_removal() {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (bool remove : {false, true}) {
            for (bool close : {false, true}) {
                reset();
                unsigned index = lane + 1;
                auto permanent = address(lane, 3), selected = address(lane, 2),
                     remote = address(lane, 1);
                assert(!change(index, permanent));
                assert(!configure_lifetime(index, selected, 1, 2));
                auto socket = inet6_allocate(2);
                assert(socket && socket->local.unspecified());
                assert(!inet6_bind_port(socket, {}, 59400));
                Inet6Address peer{10, __builtin_bswap16(uint16_t(55124)), 0, remote, 0};
                uint8_t payload[16] = {'Q', 'S', 'R', 'C'};
                const auto original = std::array<uint8_t, 16>{'Q', 'S', 'R', 'C'};
                assert(inet6_send(socket, peer, payload, sizeof(payload), true) == sizeof(payload));
                memset(payload, 0xa5, sizeof(payload));
                net_poll();
                assert(last(lane, 135).header.source == selected);
                if (remove)
                    assert(!change(index, selected, true, true));
                else
                    ticks = 200;
                assert(!ipv6_owned(index, selected));
                Ipv6Path fresh;
                assert(!ipv6_path({}, remote, index, fresh) && fresh.source == permanent);
                net_poll();
                assert(socket->transmitted == 64 && !socket->error);
                Inet6Socket* replacement = nullptr;
                if (close) {
                    inet6_close(socket);
                    replacement = inet6_allocate(2);
                    assert(replacement == socket);
                    replacement->local = permanent;
                }
                emitted[lane].clear();
                deliver(lane, advertisement(lane, remote, permanent));
                net_poll();
                unsigned datagrams = 0;
                for (const auto& frame : emitted[lane]) {
                    if (frame.size() != 78 || frame[20] != 17)
                        continue;
                    assert(!memcmp(frame.data() + 22, selected.bytes, 16));
                    assert(!memcmp(frame.data() + 62, original.data(), original.size()));
                    assert(!ip6::checksum(selected, remote, 17, frame.data() + 54, 24));
                    datagrams++;
                }
                assert(datagrams == 1);
                assert(!socket->error && !socket->transmitted);
                inet6_close(replacement ? replacement : socket);
                reset();
            }
        }
    }
}

void retired_neighbor_source() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        unsigned index = lane + 1;
        auto local = address(lane, 2), remote = address(lane, 1);
        assert(!change(index, local));
        auto socket = inet6_allocate(2);
        assert(socket);
        socket->index = index;
        assert(!inet6_bind_port(socket, {}, 59402));
        Inet6Address target{10, __builtin_bswap16(uint16_t(8080)), 0, remote, 0};
        uint8_t payload[16]{};
        assert(inet6_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
        net_poll();
        assert(last(lane, 135).header.source == local);
        assert(!change(index, local, true, true));
        net_poll();
        assert(!socket->transmitted);
        emitted[lane].clear();
        // An unrelated source and route must not revive an orphaned query.
        assert(!change(index, address(9, 2)));
        assert(!ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true));
        ticks = 100;
        net_poll();
        assert(emitted[lane].empty());
        inet6_close(socket);
    }
    reset();
}

void cross_interface_source_output() {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (bool link : {true, false}) {
            reset();
            unsigned index = lane + 1;
            auto selected = address(9, 2), remote = address(9, 1);
            auto probe_source = address(lane, 2, true);
            assert(!ipv6_address_add({selected, 2 - lane, 0x282, 64}));
            if (link)
                assert(!ipv6_address_add({probe_source, index, 0x282, 64}));
            else
                assert(!ipv6_address_add({address(lane, 2), index, 0x282, 64}, {0, UINT32_MAX}));
            assert(!ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true));
            auto socket = inet6_allocate(2);
            assert(socket);
            socket->index = index;
            assert(!inet6_bind_port(socket, {}, 59401));
            Inet6Address target{10, __builtin_bswap16(uint16_t(8080)), 0, remote, 0};
            uint8_t payload[16] = {'S', 'P', 'O', 'L'};
            assert(inet6_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
            memset(payload, 0xa5, sizeof(payload));
            net_poll();
            if (link) {
                assert(last(lane, 135).header.source == probe_source);
                emitted[lane].clear();
                deliver(lane, advertisement(lane, remote, probe_source));
                assert(emitted[lane].size() == 1);
                const auto& frame = emitted[lane][0];
                auto packet = ip6::decode(frame.data() + 14, frame.size() - 14);
                assert(packet.protocol == 17 && packet.header.source == selected &&
                       packet.header.destination == remote && packet.length == 24);
                assert(!memcmp(packet.payload + 8, "SPOL", 4) &&
                       std::all_of(packet.payload + 12, packet.payload + 24,
                                   [](auto byte) { return !byte; }));
                assert(!ip6::checksum(selected, remote, 17, packet.payload, packet.length));
                assert(!socket->transmitted && !socket->error);
            } else {
                for (unsigned at = 1; at <= 3; at++) {
                    ticks = at * 100;
                    net_poll();
                }
                assert(emitted[lane].empty() && socket->transmitted);
                ticks = 400;
                net_poll();
                assert(!socket->transmitted);
            }
            inet6_close(socket);
        }
    }
    reset();
}

static ip6::Address policy_address(const char* text) {
    ip6::Address result;
    assert(inet_pton(AF_INET6, text, result.bytes) == 1);
    return result;
}

void manual_source_policy() {
    struct Candidate {
        const char* address = nullptr;
        uint8_t prefix = 0;
        bool deprecated = false, other = false;
    };

    struct Case {
        const char* name;
        const char* destination;
        Candidate candidates[3];
        const char* selected;
        int error;
    };

    // Actual UDP connect/getsockname observations on Linux, with the default
    // label table and both automatic routing and SO_BINDTODEVICE.
    const Case cases[] = {
        {"no-address-unicast", "2001:db8:99::2", {}, "::1", 0},
        {"no-address-site", "fec0:1::2", {}, "::1", 0},
        {"outgoing-before-prefix",
         "2001:db8:99::2",
         {{"2001:db8:10::1", 64, false, false}, {"2001:db8:99::1", 128, false, true}},
         "2001:db8:10::1",
         0},
        {"other-interface-fallback",
         "2001:db8:99::2",
         {{"fe80::10", 64, false, false}, {"2001:db8:99::1", 64, false, true}},
         "2001:db8:99::1",
         0},
        {"deprecated-before-interface",
         "2001:db8:99::2",
         {{"2001:db8:10::1", 64, true, false}, {"2001:db8:99::1", 64, false, true}},
         "2001:db8:99::1",
         0},
        {"outgoing-before-label",
         "fd42::2",
         {{"2001:db8:10::1", 64, false, false}, {"fd42::1", 64, false, true}},
         "2001:db8:10::1",
         0},
        {"label-ula",
         "fd42::2",
         {{"fd42::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "fd42::1",
         0},
        {"label-global",
         "2001:db8:99::2",
         {{"2001:db8:10::1", 0, false, false}, {"fd42::1", 128, false, false}},
         "2001:db8:10::1",
         0},
        {"label-6to4",
         "2002:1234::2",
         {{"2002:1234::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "2002:1234::1",
         0},
        {"label-teredo",
         "2001:0:abcd::2",
         {{"2001:0:1234::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "2001:0:1234::1",
         0},
        {"label-6bone",
         "3ffe:1234::2",
         {{"3ffe:1234::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "3ffe:1234::1",
         0},
        {"label-orchid",
         "2001:10::2",
         {{"2001:10::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "2001:10::1",
         0},
        {"label-orchid2",
         "2001:20::2",
         {{"2001:20::1", 0, false, false}, {"2001:db8:10::1", 128, false, false}},
         "2001:db8:10::1",
         0},
        {"scope-link",
         "fe80::2",
         {{"fe80::1", 64, false, false}, {"2001:db8:10::1", 64, false, false}},
         "fe80::1",
         0},
        {"scope-link-global-only",
         "fe80::2",
         {{"2001:db8:10::1", 64, false, false}},
         "2001:db8:10::1",
         0},
        {"scope-global-link-only", "2001:db8:99::2", {{"fe80::1", 64, false, false}}, "fe80::1", 0},
        {"scope-site",
         "fec0:1::2",
         {{"fec0:1::1", 64, false, false}, {"2001:db8:10::1", 64, false, false}},
         "fec0:1::1",
         0},
        {"scope-before-deprecated",
         "fec0:1::2",
         {{"fec0:1::1", 64, true, false}, {"2001:db8:10::1", 64, false, false}},
         "fec0:1::1",
         0},
        {"scope-site-undersized",
         "2001:db8:99::2",
         {{"fe80::1", 64, false, false}, {"fec0:1::1", 64, false, false}},
         "fec0:1::1",
         0},
        {"link-no-cross-interface",
         "fe80::2",
         {{"fe80::1", 64, false, true}, {"2001:db8:10::1", 64, false, true}},
         "::",
         99},
        {"multicast-link",
         "ff02::123",
         {{"fe80::1", 64, false, false}, {"2001:db8:10::1", 64, false, false}},
         "fe80::1",
         0},
        {"multicast-site",
         "ff05::123",
         {{"fe80::1", 64, false, false}, {"2001:db8:10::1", 64, false, false}},
         "2001:db8:10::1",
         0},
        {"multicast-global",
         "ff0e::123",
         {{"fe80::1", 64, false, false}, {"2001:db8:10::1", 64, false, false}},
         "2001:db8:10::1",
         0},
        {"prefix-cap",
         "2001:db8:99::2",
         {{"2001:db8:99::1", 16, false, false}, {"2001:db8:10::1", 64, false, false}},
         "2001:db8:10::1",
         0},
        {"equal-newest",
         "2001:db8:99::2",
         {{"2001:db8:10::1", 64, false, false}, {"2001:db8:11::1", 64, false, false}},
         "2001:db8:11::1",
         0},
        {"deprecated-before-label",
         "fd42::2",
         {{"fd42::1", 64, true, false}, {"2001:db8:10::1", 64, false, false}},
         "2001:db8:10::1",
         0},
    };
    for (unsigned lane = 0; lane < 2; lane++) {
        for (const auto& test : cases) {
            reset();
            unsigned index = lane + 1;
            assert(!ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true));
            for (const auto& candidate : test.candidates) {
                if (!candidate.address)
                    continue;
                Ipv6Address value{policy_address(candidate.address),
                                  candidate.other ? 2 - lane : index, 0x282, candidate.prefix};
                assert(
                    !ipv6_address_add(value, {candidate.deprecated ? 0u : UINT32_MAX, UINT32_MAX}));
            }
            auto destination = policy_address(test.destination);
            for (unsigned bound : {0u, index}) {
                if (!bound && (destination.link_local() || destination.multicast()))
                    continue;
                Ipv6Path path;
                int result = ipv6_path({}, destination, bound, path);
                if (result != -test.error ||
                    (!result && !(path.source == policy_address(test.selected)))) {
                    std::fprintf(stderr, "SOURCE_POLICY_FAIL case=%s lane=%u bound=%u error=%d\n",
                                 test.name, lane, bound, result);
                    std::abort();
                }
                if (!result)
                    assert(path.index == index);
            }
        }
    }
    reset();
}

void loopback_source_output() {
    const auto loopback = policy_address("::1");
    const uint8_t mac[6] = {0x52, 0x55, 0, 0x85, 0x40, 1};
    for (unsigned lane = 0; lane < 2; lane++) {
        const auto remote = address(lane, 7);
        const unsigned index = lane + 1;
        for (unsigned bound : {0u, index}) {
            for (unsigned type : {2u, 3u}) {
                for (bool resolved : {false, true}) {
                    for (bool closed : {false, true}) {
                        for (size_t length : {size_t(32), size_t(4000)}) {
                            reset();
                            assert(!ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true));
                            if (resolved)
                                ip6::neighbor_solicitation(index, remote, mac);
                            auto socket = inet6_allocate(type);
                            assert(socket);
                            socket->local = loopback;
                            socket->peer = remote;
                            socket->peer_port = type == 2 ? 8080 : 0;
                            socket->index = bound;
                            socket->connected = true;
                            std::vector<uint8_t> payload(length, 0x54);
                            payload[0] = 128;
                            payload[1] = 0;
                            assert(inet6_send(socket, inet6_peer(socket), payload.data(), length) ==
                                   int64_t(length));
                            assert(socket->transmitted);
                            if (closed) {
                                inet6_close(socket);
                                socket = inet6_allocate(type);
                                assert(socket && !socket->transmitted && !inet6_error(socket));
                            }
                            net_poll();
                            // RFC 4291 keeps loopback sources inside the node, including
                            // cached neighbors, fragments and finally closed owners.
                            assert(emitted[0].empty() && emitted[1].empty());
                            assert(!socket->transmitted && !inet6_error(socket));
                            inet6_close(socket);
                            assert(allocations.empty());
                        }
                    }
                }
            }
        }
    }
    reset();
    auto receiver = inet6_allocate(2);
    assert(receiver);
    receiver->local = loopback;
    assert(!inet6_bind_port(receiver, loopback, 8080));
    auto sender = inet6_allocate(2);
    assert(sender);
    sender->local = loopback;
    const uint8_t payload[] = {1, 2, 3, 4};
    Inet6Address target{10, htons(8080), 0, loopback, 0};
    assert(inet6_send(sender, target, payload, sizeof(payload), true) == sizeof(payload));
    net_poll();
    assert(inet6_available(receiver) == sizeof(payload) && !sender->transmitted);
    assert(emitted[0].empty() && emitted[1].empty());
    inet6_close(sender);
    inet6_close(receiver);
    assert(allocations.empty());
    reset();
}

void loopback_source_mtu() {
    const auto loopback = policy_address("::1");
    const uint8_t mac[6] = {0x52, 0x55, 0, 0x85, 0x40, 1};
    for (unsigned lane = 0; lane < 2; lane++) {
        const auto remote = address(lane, 7);
        const unsigned index = lane + 1;
        for (unsigned bound : {0u, index}) {
            for (unsigned type : {2u, 3u}) {
                for (bool resolved : {false, true}) {
                    reset();
                    assert(!ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true));
                    if (resolved)
                        ip6::neighbor_solicitation(index, remote, mac);
                    auto socket = inet6_allocate(type);
                    assert(socket);
                    socket->local = loopback;
                    socket->peer = remote;
                    socket->peer_port = type == 2 ? 8080 : 0;
                    socket->index = bound;
                    socket->connected = true;
                    socket->pmtu_mode = 2;
                    std::vector<uint8_t> payload(1600, 0x54);
                    payload[0] = 128;
                    payload[1] = 0;
                    assert(inet6_send(socket, inet6_peer(socket), payload.data(), payload.size()) ==
                           -90);
                    assert(!socket->transmitted && !inet6_error(socket));
                    assert(inet6_send(socket, inet6_peer(socket), payload.data(), 1400) == 1400);
                    assert(socket->transmitted);
                    // Admission used 1500; completion must observe the reduced MTU.
                    assert(!net_configure(index, true, 1280));
                    net_poll();
                    assert(!socket->transmitted && inet6_error(socket, true) == 90);
                    assert(emitted[0].empty() && emitted[1].empty());
                    inet6_close(socket);
                    assert(allocations.empty());
                }
            }
        }
    }
    reset();
}

void reviewed_source_edges() {
    reset();
    static NetAdapter third;
    third.info.live = third.info.carrier = third.info.writable = true;
    third.info.maximum_mtu = 1500;
    third.info.mac[0] = 0x52;
    third.info.mac[5] = 0x12;
    third.poll = [](NetAdapter&) {};
    third.stop = [](NetAdapter&) {};
    third.send = [](NetAdapter&, const void*, size_t) { return -11; };
    assert(net_register(third) == 3);
    assert(!net_configure(3, true, 1500));
    auto first = policy_address("2001:db8:10::1"), second = policy_address("2001:db8:11::1");
    auto remote = policy_address("2001:db8:99::2");
    for (bool reverse : {false, true}) {
        reset();
        assert(!ipv6_address_add({reverse ? second : first, reverse ? 3u : 2u, 0x282, 64}));
        assert(!ipv6_address_add({reverse ? first : second, reverse ? 2u : 3u, 0x282, 64}));
        assert(!ipv6_route_control({{}, {}, 1, 1024, 0, 3}, false, true));
        Ipv6Path path;
        assert(!ipv6_path({}, remote, 1, path) && path.source == first);
        auto newest = policy_address("2001:db8:12::1");
        assert(!ipv6_address_add({newest, 2, 0x282, 64}));
        assert(!ipv6_path({}, remote, 1, path) && path.source == newest);
    }
    reset();
    auto compatible = policy_address("::192.0.2.1");
    assert(!ipv6_address_add({compatible, 1, 0x282, 64}, {0, UINT32_MAX}));
    assert(!ipv6_address_add({first, 1, 0x282, 128}));
    assert(!ipv6_route_control({{}, {}, 1, 1024, 0, 3}, false, true));
    Ipv6Path path;
    assert(!ipv6_path({}, policy_address("::192.0.2.2"), 1, path) && path.source == compatible);
    reset();
}

void fresh_link_dad_cycles() {
    using Key = ip6::ConfigurationKey;
    for (unsigned lane = 0; lane < 2; lane++) {
        for (bool administrative : {false, true}) {
            reset();
            unsigned index = lane + 1;
            assert(!ip6::configuration_secret(index, policy_address("2001:db8::1234")));
            assert(!ip6::configuration_write(index, Key::disabled, 1));
            assert(!ip6::configuration_write(index, Key::disabled, 0));
            auto candidate = [&]() {
                ip6::Address result;
                unsigned count = 0;
                for (unsigned at = 0; auto value = ipv6_address(at); at++)
                    if (value->index == index && value->address.link_local() &&
                        (value->flags & 0x848) == 0x840) {
                        result = value->address;
                        count++;
                    }
                assert(count == 1);
                return result;
            };
            const auto original = candidate();
            const auto original_owner = ip6::address_owner(index, original);
            ipv6_poll();
            deliver(lane, advertisement(lane, original, ip6::all_nodes()));
            ipv6_poll();
            auto retry = candidate();
            assert(!(retry == original));
            if (administrative) {
                assert(!net_configure(index, false, 1500));
                assert(!net_configure(index, true, 1500));
            } else {
                assert(!ip6::configuration_write(index, Key::disabled, 1));
                assert(!ip6::configuration_write(index, Key::disabled, 0));
            }
            auto fresh = candidate();
            std::printf("IPV6_FRESH_DAD lane=%u administrative=%u original_identity=%u\n", lane,
                        administrative, fresh == original);
            std::fflush(stdout);
            assert(fresh == original);
            assert(ip6::address_owner(index, fresh) != original_owner);
            for (unsigned trial = 0; trial < 4; trial++) {
                auto selected = candidate();
                // The model advances to the maximum existing retry deadline;
                // real packet-clock bounds remain covered by wire tests.
                ticks += 210;
                ipv6_poll();
                auto probe = last(lane, 135);
                assert(!memcmp(probe.payload + 8, selected.bytes, 16));
                deliver(lane, advertisement(lane, selected, ip6::all_nodes()));
                ipv6_poll();
            }
            unsigned failed = 0;
            for (unsigned at = 0; auto value = ipv6_address(at); at++)
                if (value->index == index && value->address.link_local()) {
                    assert(value->flags == 0x8c8);
                    failed++;
                }
            assert(failed == 4);
        }
    }
}

void automatic_link_configuration() {
    using Key = ip6::ConfigurationKey;
    auto setting = [](unsigned index, Key key) {
        int32_t value = -999;
        assert(!ip6::configuration_read(index, key, value));
        return value;
    };
    auto automatic = [](unsigned index, bool privacy) {
        for (unsigned n = 0; auto entry = ipv6_address(n); n++)
            if (entry->index == index && entry->address.link_local() &&
                bool(entry->flags & 0x800) == privacy)
                return entry->address;
        return ip6::Address{};
    };
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        unsigned index = lane + 1;
        assert(ip6::configuration_write(index, Key::generation_mode, 4) == -22);
        assert(ip6::configuration_write(index, Key::generation_mode, 2) == -22);
        assert(ip6::configuration_write(999, Key::generation_mode, 0) == -19);
        assert(!ip6::configuration_write(index, Key::generation_mode, 0,
                                         ip6::ConfigurationWrite::netlink));
        assert(automatic(index, false).unspecified());
        ipv6_poll();
        assert(automatic(index, false).unspecified() && emitted[lane].empty());
        assert(!net_configure(index, false, 1500));
        assert(!net_configure(index, true, 1500));
        auto eui = automatic(index, false);
        assert(eui.link_local() && eui.bytes[8] == (adapters[lane].info.mac[0] ^ 2) &&
               eui.bytes[11] == 0xff && eui.bytes[12] == 0xfe &&
               eui.bytes[15] == adapters[lane].info.mac[5]);
        assert(ipv6_owned(index, eui, true) && !ipv6_owned(index, eui));
        ipv6_poll();
        assert(emitted[lane].size() == 1 && emitted[lane].back().size() == 78);
        ticks += 100;
        ipv6_poll();
        assert(!ipv6_owned(index, eui));
        ticks++;
        ipv6_poll();
        assert(ipv6_owned(index, eui));
        assert(!ip6::configuration_write(index, Key::generation_mode, 1));
        assert(ipv6_owned(index, eui));
        assert(!ipv6_address_remove(index, eui));
        assert(!ip6::configuration_write(index, Key::generation_mode, 0,
                                         ip6::ConfigurationWrite::netlink));
        assert(!ip6::configuration_write(index, Key::generation_mode, 0));
        ipv6_poll();
        assert(automatic(index, false).unspecified());
        assert(!ip6::configuration_write(index, Key::generation_mode, 1));
        assert(!ip6::configuration_write(index, Key::generation_mode, 0));
        assert(automatic(index, false) == eui);
        assert(!ip6::configuration_write(index, Key::disabled, 1));
        assert(automatic(index, false).unspecified() && !ip6::usable(index));
        assert(ipv6_address_add({address(lane, 1), index, 0x82, 64}) == -13);
        assert(ipv6_route_control({{}, {}, index, 1024, 0, 3}, false, true) == -13);
        assert(!ip6::configuration_write(index, Key::generation_mode, 0,
                                         ip6::ConfigurationWrite::netlink));
        assert(!ip6::configuration_write(index, Key::disabled, 0));
        assert(automatic(index, false) == eui);
        entropy_available = false;
        assert(!ip6::configuration_write(index, Key::generation_mode, 3));
        assert(automatic(index, true).unspecified());
        assert(ip6::configuration_write(index, Key::generation_mode, 2) == -22);
        entropy_available = true;
        ipv6_poll();
        auto privacy = automatic(index, true);
        assert(privacy.link_local() && !(privacy == eui));
        assert(!net_configure(index, false, 1500));
        assert(automatic(index, false).unspecified() && automatic(index, true).unspecified());
        assert(!net_configure(index, true, 1500));
        assert(automatic(index, true) == privacy);
        assert(!ip6::configuration_write(index, Key::generation_mode, 2,
                                         ip6::ConfigurationWrite::netlink));
        assert(!net_configure(index, false, 1500));
        assert(!net_configure(index, true, 1500));
        assert(automatic(index, true) == privacy);
        assert(setting(index, Key::generation_mode) == 2);
        assert(setting(2 - lane, Key::generation_mode) == 1);
        assert(!ip6::configuration_write(ip6::configuration_default, Key::generation_mode, 0));
        assert(setting(index, Key::generation_mode) == 2);
        assert(!ip6::configuration_write(ip6::configuration_all, Key::generation_mode, 1));
        assert(setting(ip6::configuration_default, Key::generation_mode) == 1);
        assert(setting(index, Key::generation_mode) == 1);
        assert(setting(2 - lane, Key::generation_mode) == 1);
    }
    reset();
    auto secret = policy_address("2001:db8::1234"), retrieved = policy_address("::dead");
    const auto unchanged = retrieved;
    assert(ip6::configuration_secret_read(ip6::configuration_all, retrieved) == -5);
    assert(ip6::configuration_secret_read(ip6::configuration_default, retrieved) == -5);
    assert(ip6::configuration_secret_read(1, retrieved) == -5 && retrieved == unchanged);
    assert(ip6::configuration_secret(999, secret) == -19);
    assert(ip6::configuration_secret(ip6::configuration_all, secret) == -5);
    assert(!ip6::configuration_secret(1, secret));
    assert(!ip6::configuration_secret_read(1, retrieved) && retrieved == secret);
    assert(setting(1, Key::generation_mode) == 2 && setting(2, Key::generation_mode) == 1);
    ipv6_poll();
    assert(automatic(1, true).unspecified() && emitted[0].empty());
    assert(!net_configure(1, false, 1500));
    assert(!net_configure(1, true, 1500));
    auto first_private = automatic(1, true);
    assert(first_private.link_local());
    auto replacement = policy_address("2001:db8::5678");
    assert(!ip6::configuration_secret(1, replacement));
    ipv6_poll();
    assert(automatic(1, true) == first_private);
    assert(!ip6::configuration_secret_read(1, retrieved) && retrieved == replacement);
    assert(!ip6::configuration_secret(ip6::configuration_default, secret));
    assert(setting(ip6::configuration_default, Key::generation_mode) == 1);
    assert(setting(ip6::configuration_all, Key::generation_mode) == 1);
    assert(setting(1, Key::generation_mode) == 2 && setting(2, Key::generation_mode) == 2 &&
           setting(ipv6_loopback, Key::generation_mode) == 2);
    assert(ip6::configuration_secret_read(2, retrieved) == -5);
    assert(!ip6::configuration_secret_read(ip6::configuration_default, retrieved) &&
           retrieved == secret);
    ipv6_poll();
    assert(automatic(2, true).unspecified() && automatic(1, true) == first_private);
    assert(!net_configure(2, false, 1500));
    assert(!net_configure(2, true, 1500));
    assert(automatic(2, true).link_local());
    assert(!ip6::configuration_secret_read(1, retrieved) && retrieved == replacement);
    reset();
    assert(ip6::configuration_secret_read(1, retrieved) == -5);
    assert(ip6::configuration_secret_read(ip6::configuration_default, retrieved) == -5);
    assert(ip6::configuration_write(1, Key::router_solicitations, -2) == -22);
    assert(!ip6::configuration_write(ip6::configuration_all, Key::autoconf, 0));
    assert(setting(1, Key::autoconf) == 1 && setting(2, Key::autoconf) == 1 &&
           setting(ip6::configuration_default, Key::autoconf) == 1);
    assert(!ip6::configuration_write(1, Key::enhanced_dad, 1));
    assert(!ip6::configuration_write(1, Key::generation_mode, 0));
    auto eui = automatic(1, false);
    ipv6_poll();
    assert(emitted[0].size() == 1 && emitted[0][0].size() == 86);
    auto packet = ip6::decode(emitted[0][0].data() + 14, emitted[0][0].size() - 14);
    assert(packet.length == 32 && packet.payload[24] == 14 && packet.payload[25] == 1);
    std::vector<uint8_t> solicitation(packet.payload, packet.payload + packet.length);
    auto destination = ip6::solicited_node(eui);
    auto looped = incoming(0, {}, destination, solicitation);
    ipv6_receive(adapters[0].info, looped.data(), looped.size());
    assert(ipv6_owned(1, eui, true));
    solicitation[26] ^= 1;
    auto duplicate = incoming(0, {}, destination, solicitation);
    ipv6_receive(adapters[0].info, duplicate.data(), duplicate.size());
    assert(!ipv6_owned(1, eui, true));
    reset();
    assert(!ip6::configuration_write(1, Key::dad_transmits, 2));
    assert(!ip6::configuration_write(1, Key::generation_mode, 0));
    eui = automatic(1, false);
    ipv6_poll();
    ticks = 100;
    ipv6_poll();
    assert(emitted[0].size() == 1 && !ipv6_owned(1, eui));
    ticks = 101;
    ipv6_poll();
    assert(emitted[0].size() == 2 && !ipv6_owned(1, eui));
    ticks = 201;
    ipv6_poll();
    assert(!ipv6_owned(1, eui));
    ticks = 202;
    ipv6_poll();
    assert(ipv6_owned(1, eui));
    reset();
    assert(!ip6::configuration_write(ip6::configuration_all, Key::enhanced_dad, 1));
    assert(setting(1, Key::enhanced_dad) == 0);
    assert(!ip6::configuration_write(1, Key::generation_mode, 0));
    ipv6_poll();
    assert(emitted[0].size() == 1 && emitted[0][0].size() == 86);
    reset();
    assert(!ip6::configuration_write(1, Key::dad_transmits, 256));
    assert(!ip6::configuration_write(1, Key::generation_mode, 0));
    eui = automatic(1, false);
    ipv6_poll();
    assert(emitted[0].empty() && ipv6_owned(1, eui));
    reset();
    auto loopback = policy_address("::1");
    assert(ipv6_owned(ipv6_loopback, loopback));
    assert(!ip6::configuration_write(ipv6_loopback, Key::disabled, 1));
    assert(!ipv6_owned(ipv6_loopback, loopback) && !ip6::usable(ipv6_loopback));
    Ipv6Route inventory[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(inventory, sizeof(inventory) / sizeof(*inventory));
    for (size_t n = 0; n < count; n++)
        assert(inventory[n].index != ipv6_loopback);
    assert(!ip6::configuration_write(ipv6_loopback, Key::disabled, 0));
    assert(ipv6_owned(ipv6_loopback, loopback));
    reset();
    assert(!ip6::configuration_write(1, Key::generation_mode, 3));
    auto reused = automatic(1, true);
    assert(!ipv6_address_remove(1, reused));
    assert(!ipv6_address_add({reused, 1, 0x880, 64}));
    ip6::address_duplicate(1, reused);
    ipv6_poll();
    assert(automatic(1, true) == reused && !ipv6_owned(1, reused, true));
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        unsigned index = lane + 1;
        assert(!ip6::configuration_write(index, Key::generation_mode, 3));
        auto current = automatic(index, true);
        std::vector<ip6::Address> failed;
        std::vector<uint64_t> owners;
        for (unsigned attempt = 0; attempt < 4; attempt++) {
            if (attempt)
                ticks += 201;
            ipv6_poll();
            bool probed = false;
            for (const auto& bytes : emitted[lane]) {
                auto packet = ip6::decode(bytes.data() + 14, bytes.size() - 14);
                probed |= packet.protocol == 58 && packet.length == 24 &&
                          packet.payload[0] == 135 &&
                          !memcmp(packet.payload + 8, current.bytes, 16);
            }
            assert(probed && ipv6_owned(index, current, true));
            failed.push_back(current);
            owners.push_back(ip6::address_owner(index, current));
            std::vector<uint8_t> data(24);
            data[0] = 135;
            memcpy(data.data() + 8, current.bytes, 16);
            auto conflict = incoming(lane, {}, ip6::solicited_node(current), data);
            ipv6_receive(adapters[lane].info, conflict.data(), conflict.size());
            assert(!ipv6_owned(index, current, true));
            ipv6_poll();
            // Linux retains all four permanent failures after exhausting retries.
            // The next candidate must be selected independently of those owners.
            for (unsigned at = 0; at < failed.size(); at++) {
                auto retained = address_observation(index, failed[at]);
                assert(retained.present && retained.flags == 0x8c8 &&
                       retained.cache[0] == UINT32_MAX && retained.cache[1] == UINT32_MAX &&
                       ip6::address_owner(index, failed[at]) == owners[at]);
            }
            ip6::Address next;
            unsigned candidates = 0;
            for (unsigned at = 0; auto entry = ipv6_address(at); at++)
                if (entry->index == index && entry->address.link_local() && entry->flags == 0x8c0) {
                    next = entry->address;
                    candidates++;
                }
            if (attempt < 3) {
                assert(candidates == 1 && !next.unspecified() && !(next == current));
                current = next;
            } else {
                assert(!candidates);
                auto probe_count = emitted[lane].size();
                ticks += 410;
                ipv6_poll();
                assert(emitted[lane].size() == probe_count);
            }
        }
    }
    reset();
}

void configuration_files() {
    using Key = ip6::ConfigurationKey;
    reset();
    auto value = [](unsigned property) {
        char bytes[64]{};
        uint64_t offset = 0;
        auto count = proc6::read(1, property, offset, bytes, sizeof(bytes) - 1);
        assert(count > 0 && offset == uint64_t(count));
        return std::strtol(bytes, nullptr, 10);
    };

    struct Numeric {
        const char* text;
        int result, value;
    };

    const Numeric cases[] = {{" 1 \n", 4, 1},
                             {"+1\n", -22, 1},
                             {"0x1\n", 4, 1},
                             {"00\n", 3, 0},
                             {"1junk\n", -22, 0},
                             {"1 0\n", 4, 1},
                             {"", 0, 1},
                             {"\n", -22, 1},
                             {"4294967296\n", -22, 1},
                             {"-0\n", -22, 1},
                             {"4\n", -22, 1},
                             {"08\n", -22, 1},
                             {"000000000000000000001\n", -22, 1}};
    for (const auto& item : cases) {
        uint64_t offset = 0;
        assert(proc6::write(1, 0, offset, item.text, strlen(item.text)) == item.result);
        assert(offset == 0 && value(0) == item.value);
    }
    uint64_t offset = 0;
    char bytes[64]{};
    assert(proc6::read(1, 0, offset, bytes, 1) == 1 && bytes[0] == '1');
    assert(proc6::read(1, 0, offset, bytes, 1) == 0 && offset == 1);
    assert(proc6::write(1, 0, offset, "0\n", 2) == 2 && offset == 3 && value(0) == 1);
    offset = 0;
    assert(proc6::write(1, 2, offset, "1 2\n", 4) == 2 && offset == 2 && value(2) == 1);
    assert(proc6::write(1, 2, offset, "bad", 3) == 3 && offset == 5 && value(2) == 1);
    for (unsigned property = 1; property < proc6::secret_property; property++) {
        offset = 0;
        assert(proc6::write(1, property, offset, "-1\n", 3) == 3);
        assert(offset == 3 && value(property) == -1);
    }
    offset = 0;
    assert(proc6::write(1, 6, offset, "-2\n", 3) == -22 && offset == 0 && value(6) == -1);
    assert(proc6::write(1, 3, offset, "-2147483648\n", 12) == 12 && offset == 12);
    assert(value(3) == INT32_MIN);
    offset = 0;
    assert(proc6::write(1, 3, offset, "2147483648\n", 11) == -22 && offset == 0);
    assert(value(3) == INT32_MIN);
    reset();
    offset = 0;
    assert(proc6::read(1, proc6::secret_property, offset, bytes, 0) == -5);
    assert(proc6::write(1, proc6::secret_property, offset, nullptr, 0) == 0);
    assert(proc6::read(1, proc6::secret_property, offset, bytes, sizeof(bytes)) == 40);
    assert(!memcmp(bytes, "0000:0000:0000:0000:0000:0000:0000:0000\n", 40));
    const char* valid[] = {"2001:db8::1234\n", "::\n", "::ffff:192.0.2.7\n", "1:2:3:4:5:6:7:8\n",
                           "1:2:3:4:5:6:192.0.2.7\n"};
    for (auto text : valid) {
        offset = 0;
        size_t length = strlen(text);
        assert(proc6::write(1, proc6::secret_property, offset, text, length) == int64_t(length));
        assert(offset == length);
        ip6::Address expected;
        char address[48]{};
        memcpy(address, text, length - 1);
        assert(inet_pton(AF_INET6, address, expected.bytes) == 1);
        ip6::Address actual;
        assert(!ip6::configuration_secret_read(1, actual) && actual == expected);
        offset = 0;
        assert(proc6::read(1, proc6::secret_property, offset, bytes, 4) == 4);
        assert(proc6::read(1, proc6::secret_property, offset, bytes + 4, sizeof(bytes) - 4) == 36);
        assert(offset == 40 && bytes[39] == '\n');
        assert(proc6::read(1, proc6::secret_property, offset, bytes, 1) == 0);
    }
    ip6::Address preserved;
    assert(!ip6::configuration_secret_read(1, preserved));
    const char* invalid[] = {
        "bad\n",     "1:2:3:4:5:6:7\n",     "1:2:3:4:5:6:7:8:9\n", "1:2:3:4:5:6:7:8:g\n",
        "1::2::3\n", "::ffff:192.0.2.256\n"};
    for (auto text : invalid) {
        offset = 0;
        assert(proc6::write(1, proc6::secret_property, offset, text, strlen(text)) == -5);
        ip6::Address actual;
        assert(!ip6::configuration_secret_read(1, actual) && actual == preserved && offset == 0);
    }
    offset = 0;
    assert(proc6::write(ip6::configuration_all, proc6::secret_property, offset, "::", 2) == -5);
    assert(proc6::read(ip6::configuration_all, proc6::secret_property, offset, bytes, 1) == -5);
    unsigned index;
    assert(proc6::scope_index("all", index) && index == ip6::configuration_all);
    assert(proc6::scope_index("default", index) && index == ip6::configuration_default);
    assert(proc6::scope_index("lo", index) && index == ipv6_loopback);
    assert(proc6::scope_index(net_info(1)->name, index) && index == 1);
    assert(!proc6::scope_index("missing", index));
    assert(!strcmp(proc6::property_name(6), "router_solicitations"));
    assert(!strcmp(proc6::property_name(7), "max_addresses"));
    assert(!proc6::property_name(proc6::property_count));
    int32_t mode;
    assert(!ip6::configuration_read(1, Key::generation_mode, mode) && mode == 2);
    reset();
}
} // namespace ipv6_fixture
