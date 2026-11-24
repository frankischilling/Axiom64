// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/net/ipv6_host.cpp
 * @brief   IPv6 host test runner.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Runs the host-side IPv6 packet and address cases using controlled interfaces.
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

namespace ipv6_fixture {
std::unordered_set<void*> allocations;
std::vector<std::vector<uint8_t>> emitted[2];
ax::NetAdapter adapters[2];
unsigned blocked;
unsigned send_budget = UINT32_MAX;
unsigned fail_allocations, shutdown_after_polls, remove_after_polls, shrink_after_polls;
static unsigned cancel_after_polls;
static void* cancelled_owner;
static void (*cancel_probe)(void*);
unsigned callback_index = 1;
unsigned inject_after_polls;
std::vector<uint8_t> injected_frame;
bool entropy_available = true;
static int forced_dad_jitter = -1;
} // namespace ipv6_fixture

using namespace ipv6_fixture;

#include "net/ipv6/icmp.hpp"

namespace ax {
void tcp6_icmp_error(unsigned, const ip6::ErrorQuote&) {
}

void tcp_receive(unsigned, const ip6::Address&, const ip6::Address&, const void*, size_t) {
}

uint64_t ticks;

int random_read(void* output, size_t size, bool insecure) {
    static uint32_t next = 0x89abcdef;
    assert((size == sizeof(next) || size == 6 || size == 16) && !insecure);
    if (!entropy_available)
        return -11;
    if (size == sizeof(uint32_t) && forced_dad_jitter >= 0) {
        uint32_t value = forced_dad_jitter;
        memcpy(output, &value, sizeof(value));
        return 0;
    }
    auto bytes = static_cast<uint8_t*>(output);
    for (size_t at = 0; at < size;) {
        size_t count = std::min(size - at, sizeof(next));
        memcpy(bytes + at, &next, count);
        next++;
        at += count;
    }
    return 0;
}

void* alloc(size_t length) {
    if (fail_allocations) {
        fail_allocations--;
        return nullptr;
    }
    auto result = std::malloc(length);
    assert(result && allocations.insert(result).second);
    return result;
}

void release(void* value) {
    if (value) {
        assert(allocations.erase(value) == 1);
        std::free(value);
    }
}

void log(const char*, ...) {
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}

void ipv4_poll() {
}

void ipv4_shutdown() {
}

void ipv4_mtu_changed(unsigned, uint32_t) {
}

int ipv4_administrative_changed(unsigned) {
    return 0;
}

void ipv4_receive(const NetInfo&, const void*, size_t) {
}

int ipv4_route_control(const Ipv4Route&, bool, bool, bool) {
    return -95;
}

size_t ipv4_routes(Ipv4Route*, size_t) {
    return 0;
}

const Ipv4Address* ipv4_address(unsigned) {
    return nullptr;
}

Ipv4AddressCacheInfo ipv4_address_cache(const Ipv4Address&) {
    return {};
}

int ipv4_address_add(unsigned, const char*, const Ipv4Config&, Ipv4AddressLifetimes, bool, bool) {
    return -95;
}

int ipv4_address_remove(unsigned, uint32_t, uint32_t) {
    return -95;
}
} // namespace ax

using namespace ax;

void ipv6_link_configuration_tests(void (*reset)());

void ipv6_output_owner_tests(void (*reset)());

void ipv6_router_tests(void (*reset)());

void ipv6_address_lifecycle_tests(void (*reset)());

const std::vector<std::vector<uint8_t>>& ipv6_emitted(unsigned lane) {
    return emitted[lane];
}

void ipv6_test_carrier(unsigned lane, bool up) {
    assert(lane < 2);
    adapters[lane].info.carrier = up;
}

void ipv6_test_cancel_on_poll(void* identity, unsigned polls, void (*probe)(void*)) {
    cancelled_owner = identity;
    cancel_after_polls = polls;
    cancel_probe = probe;
}

void ipv6_test_budget(unsigned value) {
    send_budget = value;
}

void ipv6_test_dad_jitter(int value) {
    assert(value >= -1 && value <= 100);
    forced_dad_jitter = value;
}

ip6::Address ipv6_fixture::address(unsigned lane, unsigned host, bool link) {
    ip6::Address result;
    if (link) {
        result.bytes[0] = 0xfe;
        result.bytes[1] = 0x80;
    } else {
        result.bytes[0] = 0x20;
        result.bytes[1] = 1;
        result.bytes[2] = 0x0d;
        result.bytes[3] = 0xb8;
        result.bytes[5] = lane + 1;
    }
    result.bytes[15] = host;
    return result;
}

int ipv6_fixture::change(unsigned index, const ip6::Address& value, bool nodad, bool remove,
                         uint8_t prefix) {
    uint8_t input[44]{};
    NetlinkHeader header{sizeof(input), uint16_t(remove ? 21 : 20), uint16_t(remove ? 5 : 0x605),
                         17, 0};
    memcpy(input, &header, 16);
    input[16] = 10;
    input[17] = prefix;
    input[18] = nodad ? 2 : 0;
    memcpy(input + 20, &index, 4);
    input[24] = 20;
    input[26] = 1;
    memcpy(input + 28, value.bytes, 16);
    std::vector<uint8_t> output(routing_capacity(header) + 16, 0xa7);
    size_t size = routing_reply(input, 100, false, output.data(), true);
    assert(size >= 36 && size <= routing_capacity(header));
    assert(std::all_of(output.begin() + routing_capacity(header), output.end(),
                       [](auto byte) { return byte == 0xa7; }));
    int error;
    memcpy(&error, output.data() + 16, 4);
    return error;
}

void ipv6_fixture::reset() {
    ipv6_shutdown();
    assert(!ip6::configuration_write(ip6::configuration_default,
                                     ip6::ConfigurationKey::enhanced_dad, 0));
    assert(
        !ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::enhanced_dad, 0));
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
    assert(allocations.empty());
    emitted[0].clear();
    emitted[1].clear();
    ticks = 0;
    blocked = 0;
    send_budget = UINT32_MAX;
    fail_allocations = shutdown_after_polls = remove_after_polls = shrink_after_polls = 0;
    cancel_after_polls = 0;
    cancelled_owner = nullptr;
    cancel_probe = nullptr;
    entropy_available = true;
    forced_dad_jitter = -1;
    callback_index = 1;
    inject_after_polls = 0;
    injected_frame.clear();
    for (auto& adapter : adapters) {
        adapter.info.live = adapter.info.carrier = true;
        assert(!net_configure(adapter.info.index, true, 1500));
        assert(!ip6::configuration_write(adapter.info.index,
                                         ip6::ConfigurationKey::router_solicitations, 0));
    }
}

std::vector<uint8_t> ipv6_fixture::incoming(unsigned lane, const ip6::Address& source,
                                            const ip6::Address& destination,
                                            std::vector<uint8_t> data, unsigned hop,
                                            uint8_t protocol) {
    std::vector<uint8_t> frame(54 + data.size());
    const auto& info = adapters[lane].info;
    if (destination.multicast())
        ip6::multicast_mac(destination, frame.data());
    else
        memcpy(frame.data(), info.mac, 6);
    uint8_t peer[6] = {2, 0x49, 0x50, 0x36, uint8_t(lane), 1};
    memcpy(frame.data() + 6, peer, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    ip6::Header header{source, destination, 0, uint16_t(data.size()), 0, protocol, uint8_t(hop)};
    assert(ip6::encode(frame.data() + 14, 40, header));
    unsigned check_at = protocol == 17 ? 6 : 2;
    data[check_at] = data[check_at + 1] = 0;
    uint16_t checksum = ip6::checksum(source, destination, protocol, data.data(), data.size());
    data[check_at] = checksum >> 8;
    data[check_at + 1] = checksum;
    memcpy(frame.data() + 54, data.data(), data.size());
    return frame;
}

std::vector<uint8_t> ipv6_fixture::solicitation(unsigned lane, const ip6::Address& target, bool dad,
                                                unsigned hop) {
    std::vector<uint8_t> data(dad ? 24 : 32);
    data[0] = 135;
    memcpy(data.data() + 8, target.bytes, 16);
    if (!dad) {
        data[24] = data[25] = 1;
        const uint8_t peer[6] = {2, 0x49, 0x50, 0x36, uint8_t(lane), 1};
        memcpy(data.data() + 26, peer, 6);
    }
    return incoming(lane, dad ? ip6::Address{} : address(lane, 1), ip6::solicited_node(target),
                    data, hop);
}

std::vector<uint8_t> ipv6_fixture::advertisement(unsigned lane, const ip6::Address& target,
                                                 const ip6::Address& destination) {
    std::vector<uint8_t> data(32);
    data[0] = 136;
    data[4] = destination.multicast() ? 0x20 : 0x60;
    memcpy(data.data() + 8, target.bytes, 16);
    data[24] = 2;
    data[25] = 1;
    const uint8_t peer[6] = {2, 0x49, 0x50, 0x36, uint8_t(lane), 1};
    memcpy(data.data() + 26, peer, 6);
    return incoming(lane, target, destination, data);
}

void ipv6_fixture::deliver(unsigned lane, const std::vector<uint8_t>& frame) {
    net_receive(adapters[lane], frame.data(), frame.size());
    net_poll();
}

ip6::Packet ipv6_fixture::last(unsigned lane, uint8_t type) {
    assert(!emitted[lane].empty());
    const auto& frame = emitted[lane].back();
    auto packet = ip6::decode(frame.data() + 14, frame.size() - 14);
    assert(packet.input == ip6::Input::payload && packet.protocol == 58 &&
           packet.payload[0] == type);
    assert(ip6::checksum(packet.header.source, packet.header.destination, 58, packet.payload,
                         packet.length) == 0);
    return packet;
}

static void dad() {
    reset();
    auto local = address(0, 2);
    assert(change(1, local, false) == 0 && !ipv6_owned(1, local));
    net_poll();
    auto probe = last(0, 135);
    assert(probe.header.source.unspecified() && probe.length == 24 &&
           probe.header.hop_limit == 255);
    assert(probe.header.destination == ip6::solicited_node(local));
    ticks = 99;
    net_poll();
    assert(!ipv6_owned(1, local));
    ticks = 100;
    net_poll();
    assert(!ipv6_owned(1, local));
    ticks = 101;
    net_poll();
    assert(ipv6_owned(1, local));
    assert(change(1, local, true, true, 63) == -99 && ipv6_owned(1, local));
    assert(change(1, local) == -17 && change(1, local, true, true) == 0);
    assert(change(1, local, false) == 0);
    net_poll();
    auto invalid = advertisement(0, local, ip6::all_nodes());
    invalid[21] = 254;
    deliver(0, invalid);
    assert(ipv6_owned(1, local, true));
    deliver(0, advertisement(0, local, ip6::all_nodes()));
    ticks += 100;
    net_poll();
    assert(!ipv6_owned(1, local, true));
    assert((ipv6_address(1)->flags & 0x48) == 0x48);
}

static void address_notifications() {
    struct Notification {
        uint16_t type;
        uint32_t flags;
        Ipv6AddressCacheInfo lifetime;
    };

    static std::vector<Notification> received;
    reset();
    ipv6_observe_addresses([](const Ipv6Address& entry, const Ipv6AddressCacheInfo& cache,
                              bool removed) {
        uint8_t bytes[72];
        assert(netlink_format_ipv6_address_event(entry, cache, removed, bytes, sizeof(bytes)) ==
               sizeof(bytes));
        NetlinkHeader header;
        uint32_t index, flags;
        Ipv6AddressCacheInfo lifetime;
        memcpy(&header, bytes, sizeof(header));
        memcpy(&index, bytes + 20, sizeof(index));
        memcpy(&flags, bytes + 48, sizeof(flags));
        memcpy(&lifetime, bytes + 56, sizeof(lifetime));
        assert(!header.flags && !header.sequence && !header.port && header.length == sizeof(bytes));
        assert(bytes[16] == 10 && bytes[17] == 64 && bytes[18] == uint8_t(flags) && !bytes[19]);
        assert(index == 1 && !memcmp(bytes + 28, entry.address.bytes, 16));
        received.push_back({header.type, flags, lifetime});
    });
    const Ipv6Address local{address(0, 2), 1, 0x200, 64};
    assert(!ipv6_address_add(local, {2, 4}) && received.empty());
    net_poll();
    ticks = 100;
    net_poll();
    assert(received.empty());
    ticks = 101;
    net_poll();
    assert(received.size() == 1 && received[0].type == 20 && received[0].flags == 0x200);
    assert(received[0].lifetime.preferred == 1 && received[0].lifetime.valid == 3);
    ticks = 200;
    net_poll();
    net_poll();
    assert(received.size() == 2 && received[1].type == 20 && received[1].flags == 0x220);
    assert(!ipv6_address_add(local, {1, 2}, true));
    assert(received.size() == 3 && received[2].type == 20 && received[2].flags == 0x200);
    ticks = 400;
    net_poll();
    assert(received.size() == 4 && received[3].type == 21 && !received[3].lifetime.valid);
    assert(!ipv6_address_add({local.address, 1, 0x202, 64}));
    assert(received.size() == 5 && received[4].type == 20 && received[4].flags == 0x282);
    assert(!ipv6_address_remove(1, local.address));
    assert(received.size() == 6 && received[5].type == 21 &&
           received[5].lifetime.valid == UINT32_MAX);
    ipv6_observe_addresses(nullptr);
    received.clear();
}

int ipv6_fixture::route(const Ipv6Route& value, bool remove, bool privileged, unsigned flags) {
    std::vector<uint8_t> bytes(28);
    NetlinkHeader header{0, uint16_t(remove ? 25 : 24), uint16_t(remove ? 5 : flags), 29, 0};
    bytes[16] = 10;
    bytes[17] = value.prefix;
    bytes[20] = 254;
    bytes[21] = value.protocol;
    bytes[23] = 1;
    auto attribute = [&](uint16_t type, const void* data, size_t length) {
        uint16_t field[2] = {uint16_t(length + 4), type};
        bytes.insert(bytes.end(), reinterpret_cast<uint8_t*>(field),
                     reinterpret_cast<uint8_t*>(field) + 4);
        const auto input = static_cast<const uint8_t*>(data);
        bytes.insert(bytes.end(), input, input + length);
    };
    attribute(1, value.destination.bytes, 16);
    attribute(5, value.gateway.bytes, 16);
    attribute(4, &value.index, 4);
    attribute(6, &value.metric, 4);
    header.length = bytes.size();
    memcpy(bytes.data(), &header, sizeof(header));
    uint8_t response[256];
    assert(routing_reply(bytes.data(), 77, false, response, privileged) >= 36);
    int error;
    memcpy(&error, response + 16, 4);
    return error;
}

static void routes_and_deadlines() {
    reset();
    for (unsigned lane = 0; lane < 2; lane++) {
        assert(!change(lane + 1, address(lane, 2)));
        assert(!change(lane + 1, address(lane, 2, true)));
    }
    Ipv6Route desired{address(2, 0), address(0, 1, true), 2, 5, 64, 3};
    assert(route(desired, false, false) == -1);
    assert(!route(desired, false) && route(desired, false) == -17);
    auto other_device = desired;
    other_device.index = 1;
    assert(route(other_device, false) == -17);
    assert(route({address(0, 0), {}, 2, 256, 64, 3}, false) == -17);
    assert(route(desired, false, true, 5) == -95);
    auto invalid = desired;
    invalid.destination = address(3, 0);
    invalid.gateway = address(0, 2);
    assert(route(invalid, false) == -22);
    invalid.gateway = address(63, 1);
    assert(route(invalid, false) == -113);
    Ipv6Path path;
    assert(!ipv6_path(address(0, 2), address(2, 1), 0, path) && path.index == 2 &&
           path.next_hop == desired.gateway);
    std::vector<uint8_t> data(101, 0xa7);
    data[0] = 128;
    data[1] = 0;
    deliver(0, incoming(0, address(2, 1), address(0, 2), data, 64));
    auto request = last(1, 135);
    assert(request.header.source == address(1, 2, true));
    assert(!memcmp(request.payload + 8, desired.gateway.bytes, 16));
    deliver(1, advertisement(1, desired.gateway, address(1, 2, true)));
    auto reply = last(1, 129);
    assert(reply.header.source == address(0, 2) && reply.header.destination == address(2, 1));
    assert(!memcmp(reply.payload + 4, data.data() + 4, data.size() - 4));
    auto wildcard = desired;
    wildcard.metric = 0;
    assert(!route(wildcard, true) && route(wildcard, true) == -3);
    assert(ipv6_path(address(0, 2), address(2, 1), 0, path) == -101);
    reset();
    assert(!change(1, address(0, 2)));
    deliver(0, incoming(0, address(0, 77), address(0, 2), data, 64));
    for (ticks = 100; ticks <= 400; ticks += 100)
        net_poll();
    assert(emitted[0].size() == 3 && allocations.empty());
    reset();
    blocked = 1;
    assert(!change(1, address(0, 2), false));
    net_poll();
    ticks = 500;
    net_poll();
    assert(!ipv6_owned(1, address(0, 2)) && emitted[0].empty());
    blocked = 0;
    net_poll();
    ticks = 599;
    net_poll();
    assert(!ipv6_owned(1, address(0, 2)));
    ticks = 600;
    net_poll();
    assert(!ipv6_owned(1, address(0, 2)));
    ticks = 601;
    net_poll();
    assert(ipv6_owned(1, address(0, 2)));
}

static void inventories_and_bounds() {
    reset();
    for (unsigned n = 0; n < ipv6_address_capacity; n++)
        assert(!change(n % 2 + 1, address(n, 2)));
    assert(change(1, address(31, 2)) == -105);
    for (unsigned n = 0; n < ipv6_route_capacity; n++) {
        Ipv6Route value{address(n + 32, 0), {}, n % 2 + 1, 5, 64, 3};
        assert(!route(value, false));
    }
    assert(route({address(63, 0), {}, 1, 5, 64, 3}, false) == -105);
    for (auto type : {22, 26}) {
        for (auto family : {0, 10}) {
            uint8_t input[28]{};
            NetlinkHeader request{uint32_t(type == 22 ? 24 : 28), uint16_t(type), 0x301, 83, 0};
            memcpy(input, &request, sizeof(request));
            input[16] = family;
            size_t capacity = routing_capacity(request, input);
            assert(capacity == (type == 26 ? family ? netlink_ipv6_route_reply : netlink_max_reply
                                : family   ? netlink_family_reply
                                           : netlink_address_reply));
            std::vector<uint8_t> output(capacity + 16, 0xa7);
            size_t length = routing_reply(input, 91, false, output.data(), true, true);
            assert(length <= capacity && length >= 20);
            assert(std::all_of(output.begin() + capacity, output.end(),
                               [](auto byte) { return byte == 0xa7; }));
            unsigned count = 0;
            for (size_t at = 0; at < length;) {
                NetlinkHeader record;
                memcpy(&record, output.data() + at, sizeof(record));
                assert(record.length >= 20 && record.length <= length - at);
                assert(record.sequence == 83 && record.port == 91);
                if (record.type == 3)
                    assert(at + record.length == length);
                else {
                    assert(record.type == (type == 22 ? 20 : 24) && output[at + 16] == 10);
                    count++;
                }
                at += (record.length + 3) & ~size_t(3);
            }
            assert(count == (type == 22 ? ipv6_address_capacity + 1
                                        : 2 * ipv6_address_capacity + ipv6_route_capacity + 1));
        }
    }
}

static void echo_and_ownership() {
    reset();
    for (unsigned lane = 0; lane < 2; lane++) {
        assert(change(lane + 1, address(lane, 2)) == 0);
        deliver(lane, solicitation(lane, address(lane, 2)));
        auto reply = last(lane, 136);
        assert(reply.header.source == address(lane, 2) &&
               reply.header.destination == address(lane, 1));
        assert(reply.payload[4] == 0x60 && reply.payload[24] == 2);
        std::vector<uint8_t> data(101);
        data[0] = 128;
        for (unsigned n = 4; n < data.size(); n++)
            data[n] = n * 17 + lane;
        deliver(lane, incoming(lane, address(lane, 1), address(lane, 2), data, 64));
        reply = last(lane, 129);
        assert(reply.length == data.size() && reply.header.hop_limit == 64);
        assert(!memcmp(reply.payload + 4, data.data() + 4, data.size() - 4));
        std::vector<uint8_t> bare(24);
        bare[0] = 135;
        memcpy(bare.data() + 8, address(lane, 2).bytes, 16);
        auto bare_source = address(lane, 88);
        deliver(lane, incoming(lane, bare_source, address(lane, 2), bare));
        auto resolution = last(lane, 135);
        assert(!memcmp(resolution.payload + 8, bare_source.bytes, 16));
        deliver(lane, advertisement(lane, bare_source, address(lane, 2)));
        auto resolved = last(lane, 136);
        assert(resolved.header.destination == bare_source && resolved.payload[4] == 0x40 &&
               resolved.length == 24);
        size_t count = emitted[lane].size();
        auto bad = solicitation(lane, address(lane, 2), false, 254);
        deliver(lane, bad);
        assert(emitted[lane].size() == count);
        auto unknown = address(lane, 77);
        blocked = 1;
        auto frame = incoming(lane, unknown, address(lane, 2), data, 64);
        deliver(lane, frame);
        std::fill(frame.begin(), frame.end(), 0xa7);
        assert(emitted[lane].size() == count);
        blocked = 0;
        net_poll();
        auto ns = last(lane, 135);
        assert(!memcmp(ns.payload + 8, unknown.bytes, 16));
        deliver(lane, advertisement(lane, unknown, address(lane, 2)));
        reply = last(lane, 129);
        assert(reply.header.destination == unknown && reply.length == data.size());
        assert(!memcmp(reply.payload + 4, data.data() + 4, data.size() - 4));
    }
}

static void routed_reply_hops() {
    auto learn = [](unsigned lane, unsigned hops) {
        std::vector<uint8_t> data(24);
        data[0] = 134;
        data[4] = hops;
        data[16] = data[17] = 1;
        const uint8_t peer[6] = {2, 0x49, 0x50, 0x36, uint8_t(lane), 1};
        memcpy(data.data() + 18, peer, 6);
        deliver(lane, incoming(lane, address(lane, 0x80, true), ip6::all_nodes(), data));
    };
    bool matched = true;
    for (bool deferred : {false, true})
        for (unsigned incoming_lane = 0; incoming_lane < 2; incoming_lane++)
            for (bool error : {false, true}) {
                reset();
                unsigned outgoing_lane = 1 - incoming_lane;
                for (unsigned lane = 0; lane < 2; lane++) {
                    assert(!change(lane + 1, address(lane, 2)));
                    assert(
                        !ip6::configuration_write(lane + 1, ip6::ConfigurationKey::accept_ra, 1));
                    learn(lane, 41 + lane * 10);
                    deliver(lane, solicitation(lane, address(lane, 2)));
                }
                std::vector<uint8_t> data(24);
                if (error) {
                    data[0] = 0x12;
                    data[1] = 0x34;
                    data[2] = 0xab;
                    data[3] = 0xcd;
                    data[5] = data.size();
                } else
                    data[0] = 128;
                for (unsigned at = 8; at < data.size(); at++)
                    data[at] = at * 7 + incoming_lane;
                auto original = incoming(incoming_lane, address(outgoing_lane, 1),
                                         address(incoming_lane, 2), data, 64, error ? 17 : 58);
                blocked = deferred;
                deliver(incoming_lane, original);
                if (deferred) {
                    // A later advertisement cannot change an admitted reply.
                    learn(0, 141);
                    learn(1, 151);
                    blocked = 0;
                    net_poll();
                }
                auto reply = last(outgoing_lane, error ? 1 : 129);
                assert(reply.header.source == address(incoming_lane, 2) &&
                       reply.header.destination == address(outgoing_lane, 1));
                if (error)
                    assert(reply.payload[1] == 4 && reply.length == original.size() - 14 + 8 &&
                           !memcmp(reply.payload + 8, original.data() + 14, original.size() - 14));
                else
                    assert(reply.length == data.size() &&
                           !memcmp(reply.payload + 4, data.data() + 4, data.size() - 4));
                unsigned expected = 41 + outgoing_lane * 10;
                std::printf("IPV6_REPLY_HOPS incoming=%u outgoing=%u error=%u deferred=%u "
                            "observed=%u expected=%u\n",
                            incoming_lane, outgoing_lane, error, deferred, reply.header.hop_limit,
                            expected);
                std::fflush(stdout);
                matched &= reply.header.hop_limit == expected;
            }
    assert(matched);
}

static void direct_neighbor_replies() {
    reset();
    assert(!change(1, address(0, 2), true, false, 128));
    Ipv6Path path;
    assert(ipv6_path({}, address(0, 1), 1, path) == -101);
    deliver(0, solicitation(0, address(0, 2)));
    assert(last(0, 136).header.destination == address(0, 1));
    assert(!route({address(0, 1), address(0, 1, true), 1, 5, 128, 3}, false));
    deliver(0, solicitation(0, address(0, 2)));
    assert(last(0, 136).header.destination == address(0, 1));
}

static void route_append() {
    reset();
    const auto local = address(0, 2);
    assert(!change(1, local));
    const Ipv6Route first{{}, address(0, 1, true), 1, 100, 0, 9};
    auto second = first;
    second.gateway = address(0, 3, true);
    constexpr unsigned append = 0xc05;
    assert(route(first, false, true, 0x805) == -95);
    assert(!route(first, false, true, append) && route(first, false, true, append) == -17);
    assert(route(second, false) == -17);
    assert(!route(second, false, true, append));
    auto duplicate = second;
    duplicate.protocol = 3;
    assert(route(duplicate, false, true, append) == -17);

    Ipv6Path path;
    const auto remote = address(2, 1);
    assert(!ipv6_path(local, remote, 0, path) && path.next_hop == first.gateway);
    assert(!route(first, true));
    assert(!ipv6_path(local, remote, 0, path) && path.next_hop == second.gateway);
}

static void scoped_multicast_output() {
    reset();
    auto local = address(1, 3, true);
    assert(!change(2, local));
    assert(!change(1, address(0, 2, true)));
    ip6::Address group{};
    group.bytes[0] = 0xff;
    group.bytes[1] = 2;
    group.bytes[15] = 2;
    auto socket = inet6_allocate(3);
    assert(socket);
    const Inet6Address destination{10, 0, 0, group, 2};
    const uint8_t solicitation[8] = {133};
    const uint8_t multicast_mac[6] = {0x33, 0x33, 0, 0, 0, 2};
    auto verify = [&](unsigned expected, const Inet6SendControl* selected) {
        const auto count = emitted[1].size();
        assert(inet6_send(socket, destination, solicitation, sizeof(solicitation), true,
                          selected) == sizeof(solicitation));
        ipv6_poll();
        assert(emitted[0].empty() && emitted[1].size() == count + 1);
        auto packet = last(1, 133);
        assert(packet.header.source == local && packet.header.destination == group &&
               packet.header.hop_limit == expected &&
               !memcmp(emitted[1].back().data(), multicast_mac, sizeof(multicast_mac)) &&
               !ip6::checksum(local, group, 58, packet.payload, packet.length));
    };

    socket->hops = 41;
    verify(1, nullptr);
    socket->multicast_hops = 255;
    verify(255, nullptr);

    struct {
        uint64_t length;
        uint32_t level, type;
        int value;
    } message{20, 41, 52, 37};

    Inet6SendControl control;
    assert(!inet6_parse_send_control(socket, destination,
                                     reinterpret_cast<const uint8_t*>(&message), sizeof(message),
                                     control, true));
    verify(37, &control);
    message.value = -1;
    assert(!inet6_parse_send_control(socket, destination,
                                     reinterpret_cast<const uint8_t*>(&message), sizeof(message),
                                     control, true));
    verify(255, &control);
    inet6_close(socket);
}

int main() {
    for (unsigned n = 0; n < 2; n++) {
        auto& adapter = adapters[n];
        adapter.info.live = adapter.info.carrier = adapter.info.writable = true;
        adapter.info.maximum_mtu = 1500;
        adapter.info.mac[0] = 0x52;
        adapter.info.mac[1] = 0x54;
        adapter.info.mac[5] = 0x10 + n;
        adapter.poll = [](NetAdapter& device) {
            if (device.info.index != callback_index)
                return;
            if (inject_after_polls && !--inject_after_polls)
                net_receive(device, injected_frame.data(), injected_frame.size());
            if (shrink_after_polls && !--shrink_after_polls)
                assert(!net_configure(1, true, 1280));
            if (remove_after_polls && !--remove_after_polls)
                assert(!change(1, address(0, 2), true, true));
            if (cancel_after_polls && !--cancel_after_polls) {
                ipv6_discard_oversized(cancelled_owner, 1280);
                if (cancel_probe)
                    cancel_probe(cancelled_owner);
            }
            if (shutdown_after_polls && !--shutdown_after_polls)
                net_shutdown();
        };
        adapter.stop = [](NetAdapter&) {};
        adapter.send = [](NetAdapter& device, const void* data, size_t length) {
            if (blocked || !send_budget)
                return -11;
            if (send_budget != UINT32_MAX)
                send_budget--;
            const auto bytes = static_cast<const uint8_t*>(data);
            emitted[device.info.index - 1].emplace_back(bytes, bytes + length);
            return 0;
        };
        assert(net_register(adapter) == n + 1);
        assert(net_configure(n + 1, true, 1500) == 0);
    }
    ipv6_output_owner_tests(reset);
    route_append();
    scoped_multicast_output();
    dad();
    address_notifications();
    echo_and_ownership();
    routed_reply_hops();
    routes_and_deadlines();
    legacy_route_inventory();
    local_route_visibility();
    inventories_and_bounds();
    direct_neighbor_replies();
    prefix_lifetimes();
    finite_address_lifetimes();
    finite_address_dad();
    source_lifetime_preferences();
    manual_source_policy();
    loopback_source_output();
    loopback_source_mtu();
    cross_interface_source_output();
    retired_neighbor_source();
    finite_prefix_lifetimes();
    retained_address_expiry();
    queued_automatic_source_removal();
    prefix_route_order();
    socket_ownership();
    fragmented_delivery();
    raw_header_bounds();
    per_message_controls();
    copied_extension_output();
    copied_routing_output();
    sticky_extension_controls();
    for (unsigned mode = 0; mode < 4; mode++)
        copied_sticky_output(mode);
    receive_extension_policy();
    source_fragmentation();
    path_mtu_errors();
    cached_routing_output();
    for (unsigned mode = 0; mode < 3; mode++)
        routed_error_destinations(mode);
    copied_error_queues();
    reviewed_source_edges();
    automatic_link_configuration();
    fresh_link_dad_cycles();
    ipv6_address_lifecycle_tests(reset);
    configuration_files();
    ipv6_link_configuration_tests(reset);
    ipv6_router_tests(reset);
    reset();
    std::puts("IPV6_HOST_PASS adapters=2 DAD=1 duplicate=1 NS=1 NA=1 echo=1 owned_copy=1");
}
