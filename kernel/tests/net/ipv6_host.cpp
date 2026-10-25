// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
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

namespace {
std::unordered_set<void*> allocations;
std::vector<std::vector<uint8_t>> emitted[2];
ax::NetAdapter adapters[2];
unsigned blocked;
unsigned send_budget = UINT32_MAX;
unsigned fail_allocations, shutdown_after_polls, remove_after_polls, shrink_after_polls;
unsigned callback_index = 1;
unsigned inject_after_polls;
std::vector<uint8_t> injected_frame;
bool entropy_available = true;
int forced_dad_jitter = -1;
} // namespace

namespace ax {
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

void ipv4_receive(const NetInfo&, const void*, size_t) {
}

int ipv4_route_control(const Ipv4Route&, bool, bool) {
    return -95;
}

size_t ipv4_routes(Ipv4Route*, size_t) {
    return 0;
}

const Ipv4Address* ipv4_address(unsigned) {
    return nullptr;
}

int ipv4_address_add(unsigned, const char*, const Ipv4Config&) {
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

void ipv6_test_budget(unsigned value) {
    send_budget = value;
}

void ipv6_test_dad_jitter(int value) {
    assert(value >= -1 && value <= 100);
    forced_dad_jitter = value;
}

static ip6::Address address(unsigned lane, unsigned host, bool link = false) {
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

static int change(unsigned index, const ip6::Address& value, bool nodad = true, bool remove = false,
                  uint8_t prefix = 64) {
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

static void reset() {
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

static std::vector<uint8_t> incoming(unsigned lane, const ip6::Address& source,
                                     const ip6::Address& destination, std::vector<uint8_t> data,
                                     unsigned hop = 255, uint8_t protocol = 58) {
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

static std::vector<uint8_t> solicitation(unsigned lane, const ip6::Address& target,
                                         bool dad = false, unsigned hop = 255) {
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

static std::vector<uint8_t> advertisement(unsigned lane, const ip6::Address& target,
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

static void deliver(unsigned lane, const std::vector<uint8_t>& frame) {
    net_receive(adapters[lane], frame.data(), frame.size());
    net_poll();
}

static ip6::Packet last(unsigned lane, uint8_t type) {
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

static int route(const Ipv6Route& value, bool remove, bool privileged = true,
                 unsigned flags = 0x605) {
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
                                           : netlink_family_reply));
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

static void prefix_route_order() {
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

static void prefix_lifetimes() {
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

static void finite_address_lifetimes() {
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

static void finite_address_dad() {
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

static void source_lifetime_preferences() {
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

static void finite_prefix_lifetimes() {
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

static std::vector<uint8_t> fragment_frame(const std::vector<uint8_t>& whole, size_t offset,
                                           size_t length, bool more, uint32_t id = 7,
                                           size_t prefix = 0) {
    assert(offset + length <= whole.size() - 54 && prefix % 8 == 0 && prefix <= 2048);
    std::vector<uint8_t> result(62 + prefix + length);
    memcpy(result.data(), whole.data(), 54);
    result[18] = (8 + prefix + length) >> 8;
    result[19] = 8 + prefix + length;
    result[20] = prefix ? 60 : 44;
    if (prefix) {
        result[54] = 44;
        result[55] = prefix / 8 - 1;
        if (prefix == 16) {
            // Retain the different-length prefix used by the reassembly case,
            // with the same valid skip-action option as the real wire fixture.
            result[56] = 0x1e;
            result[57] = 10;
        }
    }
    auto header = result.data() + 54 + prefix;
    header[0] = whole[20];
    header[2] = offset >> 8;
    header[3] = offset | unsigned(more);
    for (unsigned n = 0; n < 4; n++)
        header[4 + n] = id >> (24 - n * 8);
    memcpy(header + 8, whole.data() + 54 + offset, length);
    return result;
}

static void fragmented_delivery() {
    reset();
    auto local = address(0, 2), remote = address(0, 1);
    assert(!change(1, local));
    auto udp = inet6_allocate(2);
    assert(udp);
    udp->local = local;
    assert(!inet6_bind_port(udp, local, 7001));
    std::vector<uint8_t> body(49, 0x5b);
    body[0] = body[2] = 0x1b;
    body[1] = 0x58;
    body[3] = 0x59;
    body[4] = 0;
    body[5] = body.size();
    auto whole = incoming(0, remote, local, body, 64, 17);
    auto first = fragment_frame(whole, 0, 16, true, 7, 8);
    auto middle = fragment_frame(whole, 16, 16, true, 7, 16);
    auto last_piece = fragment_frame(whole, 32, 17, false);
    deliver(0, last_piece);
    deliver(0, first);
    first.back() ^= 1;
    assert(!udp->count);
    deliver(0, middle);
    assert(udp->count == 1 && inet6_front(udp)->length == 41);
    assert(!memcmp(inet6_bytes(inet6_front(udp)), body.data() + 8, 41));
    inet6_consume(udp);
    first = fragment_frame(whole, 0, 16, true);
    deliver(0, first);
    deliver(0, first);
    deliver(0, fragment_frame(whole, 0, 49, false));
    assert(udp->count == 1);
    deliver(0, middle);
    deliver(0, last_piece);
    assert(udp->count == 2);
    inet6_consume(udp);
    inet6_consume(udp);
    deliver(0, first);
    deliver(0, fragment_frame(whole, 8, 16, true));
    deliver(0, middle);
    deliver(0, last_piece);
    assert(!udp->count);
    ip6::reassembly_discard();
    Inet6Address peer{10, __builtin_bswap16(uint16_t(7000)), 0, remote, 0};
    assert(inet6_send(udp, peer, nullptr, 0, true) == 0);
    net_poll();
    deliver(0, advertisement(0, remote, local));
    auto solicitation_frame = solicitation(0, local);
    size_t before = emitted[0].size();
    deliver(0, fragment_frame(solicitation_frame, 0, 24, true, 8));
    deliver(0, fragment_frame(solicitation_frame, 24, 8, false, 8));
    assert(emitted[0].size() == before);
    deliver(0, first);
    ticks = 5999;
    net_poll();
    assert(emitted[0].size() == before);
    ticks = 6000;
    net_poll();
    auto error = last(0, 3);
    assert(error.payload[1] == 1 && error.length == 8 + first.size() - 14);
    assert(!memcmp(error.payload + 8, first.data() + 14, first.size() - 14));
    auto bad_first = fragment_frame(whole, 0, 16, true, 99);
    bad_first[54] = 6; // No complete TCP header in this first fragment.
    deliver(0, bad_first);
    error = last(0, 4);
    assert(error.payload[1] == 3 && !error.payload[4] && !error.payload[5] && !error.payload[6] &&
           !error.payload[7]);
    deliver(0, advertisement(0, remote, local));
    for (uint8_t protocol : {17, 58}) {
        auto overflow = fragment_frame(whole, 0, 16, false, 120 + protocol);
        overflow[54] = protocol;
        overflow[56] = 0xff;
        overflow[57] = 0xf8;
        overflow[62] = 1; // Later-fragment bytes cannot identify an ICMP error.
        size_t prior = emitted[0].size();
        deliver(0, overflow);
        assert(emitted[0].size() == prior + 1);
        error = last(0, 4);
        assert(error.payload[1] == 0 && error.payload[4] == 0 && error.payload[5] == 0 &&
               error.payload[6] == 0 && error.payload[7] == 42);
        assert(error.length == 8 + overflow.size() - 14 &&
               !memcmp(error.payload + 8, overflow.data() + 14, overflow.size() - 14));
    }
    before = emitted[0].size();
    auto icmp_error = incoming(0, remote, local, std::vector<uint8_t>(16), 64, 58);
    deliver(0, fragment_frame(icmp_error, 0, 8, true, 111));
    ticks += 6000;
    net_poll();
    assert(emitted[0].size() == before); // Never report an error about an ICMP error.
    inet6_close(udp);
    reset();
}

static void socket_ownership() {
    reset();
    auto local = address(0, 2), remote = address(0, 1);
    assert(!change(1, local));
    auto raw = inet6_allocate(3);
    assert(raw && raw->reuse);
    raw->local = local;
    for (auto& bits : raw->filter)
        bits = UINT32_MAX;
    raw->filter[129 / 32] &= ~(uint32_t(1) << (129 % 32));
    std::vector<uint8_t> message(19, 0x5b);
    message[0] = 128;
    message[1] = 0;
    auto original = message;
    Inet6Address target{10, 0, 0, remote, 0};
    assert(inet6_send(raw, target, message.data(), message.size(), true) == 19);
    assert(raw->transmitted == 59);
    message.back() ^= 1;
    net_poll();
    deliver(0, advertisement(0, remote, local));
    net_poll();
    auto packet = last(0, 128);
    assert(packet.length == 19 && !memcmp(packet.payload + 4, original.data() + 4, 15));
    assert(!ip6::checksum(local, remote, 58, packet.payload, packet.length) && !raw->transmitted);
    original[0] = 129;
    auto frame = incoming(0, remote, local, original, 64);
    auto bad = frame;
    bad.back() ^= 1;
    deliver(0, bad);
    assert(!raw->count);
    deliver(0, frame);
    assert(raw->count == 1 && inet6_front(raw)->length == 19);
    assert(!memcmp(inet6_bytes(inet6_front(raw)) + 4, original.data() + 4, 15));
    inet6_consume(raw);
    inet6_close(raw);

    auto udp = inet6_allocate(2);
    assert(udp && !udp->reuse);
    udp->local = local;
    assert(!inet6_bind_port(udp, local, 7001));
    std::vector<uint8_t> body{0x1b, 0x58, 0x1b, 0x59, 0, 9, 0, 0, 0x4e};
    frame = incoming(0, remote, local, body, 64, 17);
    bad = frame;
    bad.back() ^= 1;
    deliver(0, bad);
    assert(!udp->count);
    bad = frame;
    bad[60] = bad[61] = 0;
    deliver(0, bad);
    assert(!udp->count);
    frame.resize(frame.size() + 3);
    frame[19] = 12;
    deliver(0, frame);
    assert(udp->count == 1 && inet6_front(udp)->length == 1 &&
           *inet6_bytes(inet6_front(udp)) == 0x4e);
    inet6_consume(udp);
    for (unsigned n = 0; n < inet6_queue_count + 1; n++)
        deliver(0, frame);
    assert(udp->count == inet6_queue_count);
    inet6_close(udp);

    auto count_errors = [&]() {
        unsigned count = 0;
        for (const auto& bytes : emitted[0])
            if (bytes.size() >= 62 && bytes[20] == 58 && bytes[54] == 1 && bytes[55] == 4)
                count++;
        return count;
    };
    unsigned before = count_errors();
    for (unsigned n = 0; n < 20; n++)
        deliver(0, frame);
    assert(count_errors() - before == 16);
    ticks += 100;
    deliver(0, frame);
    assert(count_errors() - before == 17);

    udp = inet6_allocate(2);
    assert(udp);
    udp->local = local;
    udp->connected = true;
    udp->peer = address(0, 99);
    udp->peer_port = __builtin_bswap16(uint16_t(7000));
    target = inet6_peer(udp);
    assert(inet6_send(udp, target, body.data(), 1) == 1);
    inet6_close(udp);
    auto reused = inet6_allocate(2);
    assert(reused == udp);
    reused->local = local;
    reused->connected = true;
    reused->peer = remote;
    reused->peer_port = __builtin_bswap16(uint16_t(7000));
    assert(inet6_send(reused, inet6_peer(reused), body.data(), 1) == 1);
    net_poll();
    assert(!reused->transmitted);
    ticks += 401;
    net_poll();
    assert(!inet6_error(reused) && !reused->transmitted);
    inet6_close(reused);
    reset();
}

static void raw_header_bounds() {
    reset();
    assert(!change(1, address(0, 2)));
    auto raw = inet6_allocate(3);
    assert(raw);
    uint8_t payload[4] = {129};
    Inet6Address target{10, 0, 0, address(0, 1), 0};
    for (unsigned unreachable = 0; unreachable < 2; unreachable++) {
        target.address = address(unreachable ? 7 : 0, 1);
        for (unsigned length = 0; length < sizeof(payload); length++)
            assert(inet6_send(raw, target, payload, length, true) == (length < 2    ? -14
                                                                      : unreachable ? -101
                                                                                    : -22));
    }
    target.address = address(0, 1);
    assert(inet6_send(raw, target, payload, 0) == -89);
    target.family = 2;
    assert(inet6_send(raw, target, payload, 0, true) == -97);
    target.family = 10;
    target.port = __builtin_bswap16(uint16_t(17));
    assert(inet6_send(raw, target, payload, 0, true) == -22);
    target.port = 0;
    raw->transmitted = raw->send_limit;
    assert(inet6_send(raw, target, payload, 1, true) == -14);
    inet6_close(raw);
    reset();
}

static void source_fragmentation() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        unsigned index = lane + 1;
        callback_index = index;
        auto local = address(lane, 2), remote = address(lane, 1);
        assert(!change(index, local));
        auto raw = inet6_allocate(3);
        assert(raw);
        raw->connected = true;
        Inet6Address target{10, 0, 0, remote, 0};
        uint8_t tiny[4] = {129};
        assert(inet6_send(raw, target, tiny, sizeof(tiny), true) == 4);
        net_poll();
        deliver(lane, advertisement(lane, remote, local));
        net_poll();
        assert(!raw->transmitted);
        emitted[lane].clear();
        std::vector<uint8_t> selected_mtu(2000, 0x71);
        selected_mtu[0] = 129;
        selected_mtu[1] = 0;
        raw->socket_mtu = 1280;
        assert(inet6_send(raw, target, selected_mtu.data(), 1400, true) == 1400);
        net_poll();
        assert(emitted[lane].size() == 1 &&
               ip6::decode(emitted[lane][0].data() + 14, emitted[lane][0].size() - 14).input ==
                   ip6::Input::payload);
        emitted[lane].clear();
        auto output = inet6_send_defaults(raw, target);
        output.source = local;
        output.index = index;
        output.hops = 43;
        output.traffic_class = 0xab;
        output.present = true;
        assert(inet6_send(raw, target, selected_mtu.data(), 2000, true, &output) == 2000);
        output.source = address(7, 1);
        output.hops = output.traffic_class = 0;
        raw->hops = 2;
        raw->traffic_class = 1;
        net_poll();
        raw->hops = 64;
        raw->traffic_class = 0;
        assert(!raw->transmitted && emitted[lane].size() == 2);
        for (const auto& frame : emitted[lane]) {
            auto decoded = ip6::decode(frame.data() + 14, frame.size() - 14);
            assert(frame.size() <= 1294 && decoded.input == ip6::Input::fragment &&
                   decoded.header.source == local && decoded.header.hop_limit == 43 &&
                   decoded.header.traffic_class == 0xab);
        }
        raw->pmtu_mode = 2;
        assert(inet6_send(raw, target, selected_mtu.data(), 1241, true) == -90);
        assert(inet6_send(raw, target, selected_mtu.data(), 1240, true) == 1240);
        net_poll();
        raw->pmtu_mode = 1;
        raw->socket_mtu = 0;
        emitted[lane].clear();
        std::vector<uint8_t> payload(65535), original;
        for (size_t n = 0; n < payload.size(); n++)
            payload[n] = uint8_t(n * 13 + 7);
        payload[0] = 129;
        payload[1] = payload[2] = payload[3] = 0;
        original = payload;
        assert(inet6_send(raw, target, payload.data(), payload.size(), true) == 65535);
        assert(raw->transmitted == 65575);
        std::fill(payload.begin(), payload.end(), 0xa5);
        send_budget = 1;
        net_poll();
        assert(emitted[lane].size() == 1);
        blocked = 1;
        for (unsigned n = 0; n < 3; n++)
            net_poll();
        assert(emitted[lane].size() == 1 && raw->transmitted == 65575);
        blocked = 0;
        send_budget = UINT32_MAX;
        assert(!net_configure(index, true, 1280));
        for (unsigned n = 0; raw->transmitted && n < 100; n++) {
            if (n == 1)
                assert(!net_configure(index, true, 1500));
            net_poll();
        }
        assert(!raw->transmitted && !raw->error);
        std::vector<uint8_t> restored;
        uint32_t identification = 0;
        for (const auto& frame : emitted[lane]) {
            auto part = ip6::decode(frame.data() + 14, frame.size() - 14);
            assert(part.input == ip6::Input::fragment && part.protocol == 58 &&
                   part.fragment.offset == restored.size() && part.header.source == local &&
                   part.header.destination == remote && frame.size() <= 1514);
            if (!identification)
                identification = part.fragment.identification;
            assert(identification && part.fragment.identification == identification);
            assert(part.fragment.more == (&frame != &emitted[lane].back()));
            restored.insert(restored.end(), part.payload, part.payload + part.length);
        }
        assert(restored.size() == original.size() &&
               !ip6::checksum(local, remote, 58, restored.data(), restored.size()));
        original[2] = restored[2];
        original[3] = restored[3];
        assert(restored == original);
        emitted[lane].clear();
        raw->send_limit = 262144;
        for (unsigned n = 0; n < 32; n++)
            assert(inet6_send(raw, target, original.data(), 7000, true) == 7000);
        assert(inet6_send(raw, target, original.data(), 7000, true) == -11);
        assert(!inet6_ready(raw, true));
        send_budget = 1;
        net_poll();
        assert(raw->transmitted);
        send_budget = UINT32_MAX;
        for (unsigned n = 0; raw->transmitted && n < 100; n++)
            net_poll();
        assert(!raw->transmitted && !raw->error && allocations.empty() && inet6_ready(raw, true));
        emitted[lane].clear();
        // A change during the driver's own poll must rebuild the unaccepted piece.
        assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
        raw->pmtu_mode = 2; // Accepted datagrams retain their original policy.
        if (!lane) {
            shrink_after_polls = 2;
            net_poll();
            assert(emitted[lane].empty() && raw->transmitted == 4040);
        }
        for (unsigned n = 0; raw->transmitted && n < 10; n++)
            net_poll();
        assert(!raw->transmitted && !raw->error);
        assert(inet6_send(raw, target, original.data(), 4000, true) == -90);
        raw->pmtu_mode = 1;
        // Closing a description keeps its queued copy, without touching a reused slot.
        emitted[lane].clear();
        assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
        send_budget = 1;
        net_poll();
        assert(raw->transmitted);
        inet6_close(raw);
        auto reused = inet6_allocate(3);
        assert(reused == raw && !reused->transmitted);
        send_budget = UINT32_MAX;
        for (unsigned n = 0; n < 10; n++)
            net_poll();
        assert(!reused->transmitted && !reused->error && emitted[lane].size() >= 3);
        raw = reused;
        raw->connected = true;
        emitted[lane].clear();
        assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
        fail_allocations = 1;
        net_poll();
        assert(!raw->transmitted && inet6_error(raw, true) == 12 && allocations.empty());
        entropy_available = false;
        assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
        net_poll();
        assert(raw->transmitted == 4040 && emitted[lane].empty());
        entropy_available = true;
        for (unsigned n = 0; raw->transmitted && n < 10; n++)
            net_poll();
        assert(!raw->transmitted);
        emitted[lane].clear();
        assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
        blocked = 1;
        net_poll();
        ticks = 400;
        net_poll();
        blocked = 0;
        assert(!raw->transmitted && inet6_error(raw, true) == 113 && allocations.empty());
        if (!lane) {
            Ipv6Route retained{address(0, 0), {}, 1, 1024, 64, 3};
            assert(!route(retained, false));
            assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
            remove_after_polls = 2;
            net_poll();
            assert(!raw->transmitted && !inet6_error(raw, true));
            std::vector<uint8_t> retained_payload;
            for (const auto& frame : emitted[lane]) {
                auto part = ip6::decode(frame.data() + 14, frame.size() - 14);
                assert(part.input == ip6::Input::fragment && part.protocol == 58 &&
                       part.fragment.offset == retained_payload.size() &&
                       part.header.source == local && part.header.destination == remote);
                retained_payload.insert(retained_payload.end(), part.payload,
                                        part.payload + part.length);
            }
            assert(retained_payload.size() == 4000 &&
                   !ip6::checksum(local, remote, 58, retained_payload.data(), 4000));
            assert(std::equal(original.begin() + 4, original.begin() + 4000,
                              retained_payload.begin() + 4));
            Ipv6Path fresh;
            assert(!ipv6_path({}, remote, lane + 1, fresh) && fresh.source.loopback());
            const auto emitted_before_fallback = emitted[lane].size();
            assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
            net_poll();
            assert(!raw->transmitted && !inet6_error(raw) &&
                   emitted[lane].size() == emitted_before_fallback);
        } else {
            assert(inet6_send(raw, target, original.data(), 4000, true) == 4000);
            shutdown_after_polls = 2;
            net_poll();
            assert(!raw->transmitted && inet6_error(raw, true) == 5 && emitted[lane].empty());
        }
        inet6_close(raw);
    }
    reset();
}

static void copied_error_queues() {
    reset();
    auto socket = inet6_allocate(2);
    assert(socket);
    Inet6Error metadata;
    metadata.destination.address = address(0, 1);
    metadata.offender.address = address(0, 250);
    metadata.packet_destination = address(0, 2);
    metadata.index = 1;
    metadata.hops = 53;
    metadata.traffic_class = 0xab;
    metadata.error = {111, 3, 1, 4, 0, 0, 0};
    uint8_t bytes[16];
    memset(bytes, 0x4e, sizeof(bytes));
    assert(!inet6_queue_error(socket, metadata, bytes, sizeof(bytes)) && allocations.empty());
    socket->receive_errors = true;
    uint8_t extensions[8] = {58, 0, 0x1e, 4, 1, 2, 3, 4};
    metadata.extension_protocol = 60;
    metadata.extension_length = sizeof(extensions);
    assert(!inet6_queue_error(socket, metadata, bytes, sizeof(bytes)) && allocations.empty());
    assert(inet6_queue_error(socket, metadata, bytes, sizeof(bytes), extensions));
    assert(socket->error_bytes == sizeof(Inet6Error) + sizeof(bytes) + sizeof(extensions));
    extensions[7] ^= 1;
    bytes[0] ^= 1;
    metadata.offender.address.bytes[15] ^= 1;
    metadata.packet_destination.bytes[15] ^= 1;
    metadata.index = 2;
    metadata.hops = 1;
    metadata.traffic_class = 0;
    auto record = inet6_take_error(socket);
    assert(record && record->length == 16 && *inet6_error_bytes(record) == 0x4e &&
           record->offender.address == address(0, 250) &&
           record->packet_destination == address(0, 2) && record->index == 1 &&
           record->hops == 53 && record->traffic_class == 0xab &&
           record->extension_protocol == 60 && record->extension_length == 8 &&
           inet6_error_bytes(record)[record->length + 7] == 4);
    release(record);
    metadata.extension_length = 65536;
    assert(!inet6_queue_error(socket, metadata, bytes, 0, extensions));
    metadata.extension_length = 65535;
    assert(!inet6_queue_error(socket, metadata, bytes, 1, extensions));
    metadata.extension_length = 0;
    assert(!inet6_error_queued(socket) && !inet6_error(socket) && allocations.empty());
    fail_allocations = 1;
    assert(!inet6_queue_error(socket, metadata, bytes, sizeof(bytes)) && !fail_allocations);
    assert(!inet6_error_queued(socket) && !socket->error_bytes && allocations.empty());
    assert(!inet6_queue_error(socket, metadata, bytes, SIZE_MAX));
    for (unsigned n = 0; n < inet6_queue_count; n++) {
        bytes[0] = n;
        assert(inet6_queue_error(socket, metadata, bytes, 1));
    }
    assert(!inet6_queue_error(socket, metadata, bytes, 1));
    for (unsigned n = 0; n < inet6_queue_count; n++) {
        record = inet6_take_error(socket);
        assert(record && *inet6_error_bytes(record) == n);
        release(record);
        if (n < 16) {
            bytes[0] = 32 + n;
            assert(inet6_queue_error(socket, metadata, bytes, 1));
        }
    }
    for (unsigned n = 32; n < 48; n++) {
        record = inet6_take_error(socket);
        assert(record && *inet6_error_bytes(record) == n);
        release(record);
    }
    assert(!inet6_error_queued(socket) && allocations.empty());
    metadata.error = {90, 1, 0, 0, 0, 1280, 0};
    assert(inet6_queue_error(socket, metadata, nullptr, 0));
    metadata.error = {13, 3, 1, 1, 0, 0, 0};
    assert(inet6_queue_error(socket, metadata, bytes, 1));
    socket->error = 111;
    release(inet6_take_error(socket));
    assert(inet6_error(socket, true) == 13 && inet6_error_queued(socket));
    release(inet6_take_error(socket));
    assert(!inet6_error(socket));
    assert(inet6_queue_error(socket, metadata, bytes, 1));
    socket->error = 111;
    inet6_purge_errors(socket);
    assert(inet6_error(socket, true) == 111 && !inet6_error_queued(socket) && allocations.empty());
    auto local = address(0, 2), remote = address(0, 1);
    assert(!change(1, local) && !inet6_bind_port(socket, local, 7001));
    socket->local = local;
    socket->index = 1;
    socket->receive_limit = 15000;
    std::vector<uint8_t> datagram(1460, 0x5b);
    datagram[0] = 0x1b;
    datagram[1] = 0x58;
    datagram[2] = 0x1b;
    datagram[3] = 0x59;
    datagram[4] = 1460 >> 8;
    datagram[5] = 1460 & 255;
    for (unsigned n = 0; n < 10; n++)
        deliver(0, incoming(0, remote, local, datagram, 64, 17));
    assert(socket->count == 10 && socket->bytes == 14520);
    // The fixed budget includes the copied outer extension bytes.
    metadata.extension_length = sizeof(extensions);
    size_t record_cost = sizeof(Inet6Error) + 1 + sizeof(extensions);
    unsigned admitted = (socket->receive_limit - socket->bytes) / record_cost;
    assert(admitted && admitted < inet6_queue_count);
    for (unsigned n = 0; n < admitted; n++)
        assert(inet6_queue_error(socket, metadata, bytes, 1, extensions));
    assert(!inet6_queue_error(socket, metadata, bytes, 1, extensions));
    assert(socket->count == 10 && socket->error_count == admitted &&
           socket->error_bytes == admitted * record_cost);
    // One byte below a complete record cannot admit its one-byte payload.
    socket->receive_limit = socket->bytes + socket->error_bytes + record_cost - 1;
    assert(!inet6_queue_error(socket, metadata, bytes, 1, extensions));
    socket->receive_limit++;
    assert(inet6_queue_error(socket, metadata, bytes, 1, extensions));
    assert(!inet6_queue_error(socket, metadata, bytes, 1, extensions));
    assert(socket->count == 10 && socket->error_count == admitted + 1);
    inet6_close(socket);
    assert(allocations.empty());
    auto reused = inet6_allocate(2);
    assert(reused == socket && !reused->receive_errors && !inet6_error_queued(reused) &&
           !inet6_error(reused));
    inet6_close(reused);
    reset();
}

static void path_mtu_errors() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        auto local = address(lane, 2), remote = address(lane, 1);
        assert(!change(lane + 1, local));
        auto socket = inet6_allocate(2);
        assert(socket && !inet6_bind_port(socket, local, 47500));
        socket->local = local;
        socket->peer = remote;
        socket->peer_port = __builtin_bswap16(uint16_t(48000));
        socket->index = lane + 1;
        socket->connected = true;
        socket->pmtu_mode = 2;
        Inet6Address target{10, socket->peer_port, 0, remote, 0};
        std::vector<uint8_t> bytes(1300, 0xa7);
        assert(inet6_send(socket, target, bytes.data(), bytes.size()) == 1300);
        net_poll();
        deliver(lane, advertisement(lane, remote, local));
        net_poll();
        const auto original = emitted[lane].back();
        assert(original.size() == 14 + 40 + 1308 && original[20] == 17);
        std::vector<uint8_t> quote(56);
        quote[0] = 2;
        quote[6] = 5;
        memcpy(quote.data() + 8, original.data() + 14, 48);
        auto error = incoming(lane, address(lane, 250), local, quote, 64);
        auto damaged = error;
        damaged.back() ^= 1;
        deliver(lane, damaged);
        Ipv6Path path;
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        assert(!inet6_error(socket));
        for (unsigned offset : {48, 50}) {
            auto unrelated = quote;
            unrelated[offset] ^= 1;
            deliver(lane, incoming(lane, remote, local, unrelated, 64));
            assert(!inet6_error(socket));
            assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        }
        deliver(lane, error);
        assert(inet6_error(socket, true) == 90 && !inet6_error(socket));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1280);
        assert(inet6_send(socket, target, bytes.data(), bytes.size()) == -90);
        socket->pmtu_mode = 3;
        assert(inet6_send(socket, target, bytes.data(), bytes.size()) == 1300);
        emitted[lane].clear();
        net_poll();
        assert(emitted[lane].size() == 1 && emitted[lane][0][20] == 17);
        socket->pmtu_mode = 1;
        assert(inet6_send(socket, target, bytes.data(), bytes.size()) == 1300);
        emitted[lane].clear();
        net_poll();
        assert(emitted[lane].size() == 2 && emitted[lane][0][20] == 44 &&
               emitted[lane][1][20] == 44 && emitted[lane][0].size() <= 14 + 1280);
        // Later hard diagnostics replace the pending error, as Linux does.
        quote[0] = 1;
        quote[1] = 4;
        deliver(lane, incoming(lane, remote, local, quote, 64));
        assert(inet6_error(socket) == 111);
        quote[1] = 1;
        deliver(lane, incoming(lane, remote, local, quote, 64));
        assert(inet6_error(socket, true) == 13);
        quote[1] = 0;
        deliver(lane, incoming(lane, remote, local, quote, 64));
        assert(!inet6_error(socket));
        ticks = 59999;
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1280);
        Ipv6Route host{remote, {}, lane + 1, 1024, 128, 3};
        assert(!ipv6_route_control(host, false, true));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        deliver(lane, error);
        inet6_error(socket, true);
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1280);
        assert(!ipv6_route_control(host, true, false));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1280);
        ticks = 60000;
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        // A hint received while a device polls must precede its byte copy.
        assert(inet6_send(socket, target, bytes.data(), bytes.size()) == 1300);
        emitted[lane].clear();
        callback_index = lane + 1;
        injected_frame = error;
        inject_after_polls = 2;
        net_poll();
        assert(!inject_after_polls && emitted[lane].empty() && socket->transmitted == 1348);
        assert(inet6_error(socket, true) == 90);
        net_poll();
        assert(emitted[lane].size() == 2 && emitted[lane][0][20] == 44 &&
               emitted[lane][1][20] == 44 && !socket->transmitted);
        quote[0] = 2;
        quote[1] = 0;
        deliver(lane, incoming(lane, remote, local, quote, 64));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1280);
        inet6_error(socket, true);
        assert(!net_configure(lane + 1, true, 1280));
        assert(!net_configure(lane + 1, true, 1500));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        deliver(lane, incoming(lane, remote, local, quote, 64));
        inet6_error(socket, true);
        assert(!change(lane + 1, local, true, true));
        assert(!change(lane + 1, local));
        assert(!ipv6_path(local, remote, lane + 1, path) && path.mtu == 1500);
        inet6_close(socket);
    }
    reset();
}

static void cached_routing_output() {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned variant = 0; variant < 13; variant++) {
            reset();
            auto local = address(lane, 2), first = address(lane, 128);
            auto final = address(144 + lane, 71);
            assert(!change(lane + 1, local));
            Ipv6Route host{first, {}, lane + 1, 100, 128};
            if (variant == 2)
                assert(!ipv6_route_control(host, false, true));
            Ipv6Path path;
            assert(!ipv6_path(local, first, lane + 1, path));
            bool learned = variant != 0 && variant != 2 && variant != 12;
            if (learned)
                assert(ip6::path_mtu_cache.learn(ip6::path_key(path, first), path.mtu, 1400,
                                                 ticks) == 1400);
            auto socket = inet6_allocate(variant == 7 ? 3 : 2);
            assert(socket);
            if (socket->type == 2)
                assert(!inet6_bind_port(socket, local, 47500));
            socket->local = local;
            socket->index = lane + 1;
            socket->peer = final;
            socket->peer_port = __builtin_bswap16(uint16_t(48000));
            uint8_t routing[40] = {250, 4, 4, 1, 1};
            memcpy(routing + 8, address(lane, 77).bytes, 16);
            memcpy(routing + 24, first.bytes, 16);
            assert(!inet6_extension_set(socket, 57, routing, sizeof(routing)));
            socket->connected = variant != 3;
            if (socket->connected)
                inet6_destination_store(socket, path, first);
            if (variant == 4)
                assert(!inet6_extension_set(socket, 57, routing, sizeof(routing)));
            if (variant == 5)
                ticks = ip6::path_mtu_lifetime;
            if (variant == 6) {
                assert(!ipv6_route_control(host, false, true));
                assert(!ipv6_path(local, first, lane + 1, path));
            }
            if (variant == 8) {
                first = address(lane, 160);
                memcpy(routing + 24, first.bytes, 16);
            }
            if (variant == 12)
                assert(ip6::path_mtu_cache.learn(ip6::path_key(path, first), path.mtu, 1400,
                                                 ticks) == 1400);
            Inet6Address target{10, socket->peer_port, 0, final, 0};
            auto control = inet6_send_defaults(socket, target);
            if (variant == 8) {
                control.extensions.routing = routing;
                control.present = true;
            }
            if (variant == 10) {
                control.hops = 55;
                control.present = true;
            }
            uint8_t payload[32] = {129};
            assert(inet6_send(socket, target, payload, sizeof(payload),
                              variant == 3 || variant == 9,
                              variant == 8 || variant == 10 ? &control : nullptr) == 32);
            if (variant == 11) {
                // Deferred output owns the effective destination and copied headers.
                assert(!inet6_extension_set(socket, 57, nullptr, 0));
                inet6_close(socket);
            }
            net_poll();
            deliver(lane, advertisement(lane, first, local));
            net_poll();
            const auto& frame = emitted[lane].back();
            unsigned transport = socket->type == 3 && variant != 11 ? 58 : 17;
            unsigned length = sizeof(payload) + (transport == 17 ? 8 : 0);
            bool reused =
                variant == 1 || variant == 2 || variant == 9 || variant == 10 || variant == 11;
            const auto& effective = reused ? first : final;
            assert(frame.size() == 14 + 40 + sizeof(routing) + length);
            assert(!memcmp(frame.data() + 38, first.bytes, 16));
            assert(!memcmp(frame.data() + 54 + 8, effective.bytes, 16));
            assert(!ip6::checksum(local, effective, transport, frame.data() + 94, length));
            assert(frame[21] == (variant == 10 ? 55 : 64));
            if (variant != 11) {
                assert(socket->peer == final);
                assert(!memcmp(socket->extensions.routing + 8, routing + 8, 16));
                socket->receive_errors = true;
                socket->pmtu_mode = 2;
                std::vector<uint8_t> oversized(1600, 0x5b);
                assert(inet6_send(socket, target, oversized.data(), oversized.size(),
                                  variant == 3 || variant == 9,
                                  variant == 8 || variant == 10 ? &control : nullptr) == -90);
                auto failure = inet6_take_error(socket);
                assert(failure && failure->destination.address == effective);
                assert(!ipv6_path(local, first, lane + 1, path));
                assert(failure->error.information == path.mtu - sizeof(routing));
                release(failure);
                inet6_close(socket);
            }
        }
    }
    reset();
}

static void routed_error_destinations(unsigned mode) {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        auto local = address(lane, 2), first = address(lane, 1), final = address(80 + lane, 71);
        assert(!change(lane + 1, local));
        Ipv6Path path;
        assert(!ipv6_path(local, first, lane + 1, path));
        assert(ip6::path_mtu_cache.learn(ip6::path_key(path, first), path.mtu, 1400, ticks) ==
               1400);
        auto socket = inet6_allocate(2);
        assert(socket && !inet6_bind_port(socket, local, 47500));
        socket->local = local;
        socket->peer = final;
        socket->peer_port = __builtin_bswap16(uint16_t(48000));
        socket->index = lane + 1;
        socket->connected = true;
        socket->receive_errors = true;
        socket->pmtu_mode = 2;
        size_t routing_size = mode == 0 ? 24 : mode == 1 ? 40 : 64;
        uint8_t routing[64] = {17, uint8_t(routing_size / 8 - 1), 4, uint8_t(mode), uint8_t(mode)};
        for (unsigned n = 0; n <= mode; n++)
            memcpy(routing + 8 + n * 16, address(8 + lane, 40 + n).bytes, 16);
        memcpy(routing + 8 + mode * 16, first.bytes, 16);
        if (mode == 2) {
            routing[56] = 0x1e;
            routing[57] = 6;
            memset(routing + 58, 0x99, 6);
        }
        assert(!inet6_extension_set(socket, 57, routing, routing_size));
        // Model connect after installing the header, as the syscall does.
        inet6_destination_store(socket, path, first);
        Inet6Address target{10, socket->peer_port, 0, final, 0};
        std::vector<uint8_t> payload(128, 0x5b);
        assert(!inet6_send_admit(socket, target, payload.size(), payload.data(), false));
        uint32_t metric = 0;
        assert(!inet6_destination_mtu(socket, metric) && metric == 1400);
        // Retaining the actual selected route keeps its metric after expiry.
        ticks = ip6::path_mtu_lifetime;
        assert(!ipv6_path(local, first, lane + 1, path) && path.mtu == 1500);
        assert(!inet6_destination_mtu(socket, metric) && metric == 1400);
        assert(inet6_send(socket, target, payload.data(), payload.size()) == 128);
        net_poll();
        deliver(lane, advertisement(lane, first, local));
        net_poll();
        const auto original = emitted[lane].back();
        assert(original.size() == 14 + 40 + routing_size + 8 + payload.size());
        assert(!memcmp(original.data() + 14 + 24, first.bytes, 16));
        std::vector<uint8_t> quote(8 + 40 + routing_size + 8 + payload.size());
        quote[0] = 2;
        quote[6] = 5;
        memcpy(quote.data() + 8, original.data() + 14, quote.size() - 8);
        // A different final destination cannot claim the connected UDP port.
        auto unrelated = quote;
        unrelated[8 + 40 + 8 + 15] ^= 1;
        deliver(lane, incoming(lane, address(lane, 250), local, unrelated, 64));
        assert(!inet6_error(socket) && !inet6_error_queued(socket));
        assert(!ipv6_path(local, first, lane + 1, path) && path.mtu == 1500);
        // A bounded quote with an impossible segment list cannot learn a PMTU.
        unrelated = quote;
        unrelated[8 + 40 + 4] = 3;
        unrelated[0] = 1;
        unrelated[1] = 4;
        socket->reuse = true;
        auto wire_owner = inet6_allocate(2);
        wire_owner->reuse = true;
        assert(!inet6_bind_port(wire_owner, local, socket->local_port));
        wire_owner->local = local;
        wire_owner->peer = first;
        wire_owner->peer_port = socket->peer_port;
        wire_owner->index = lane + 1;
        wire_owner->connected = wire_owner->receive_errors = true;
        deliver(lane, incoming(lane, address(lane, 250), local, unrelated, 64));
        assert(!inet6_error(socket) && !inet6_error_queued(socket));
        assert(inet6_error(wire_owner, true) == 111 && inet6_error_queued(wire_owner));
        inet6_close(wire_owner);
        deliver(lane, incoming(lane, address(lane, 250), local, quote, 64));
        assert(inet6_error(socket, true) == 90);
        assert(!ipv6_path(local, first, lane + 1, path) && path.mtu == 1280);
        assert(!inet6_destination_mtu(socket, metric) && metric == 1280);
        auto record = inet6_take_error(socket);
        assert(record && record->destination.address == first &&
               record->destination.port == socket->peer_port);
        assert(record->length == payload.size() &&
               !memcmp(record + 1, payload.data(), payload.size()));
        release(record);
        quote[0] = 1;
        quote[1] = 4;
        deliver(lane, incoming(lane, address(lane, 250), local, quote, 64));
        assert(inet6_error(socket, true) == 111 && inet6_error_queued(socket));
        release(inet6_take_error(socket));
        inet6_close(socket);
        assert(allocations.empty());
    }
    reset();
}

static void per_message_controls() {
    reset();
    auto socket = inet6_allocate(2);
    assert(socket);
    socket->local.bytes[15] = 1;
    socket->hops = 33;
    socket->traffic_class = 18;
    Inet6Address target{10, 0, 0, socket->local, 0};
    std::vector<uint8_t> bytes;
    auto append = [&](uint32_t type, const void* data, size_t size) {
        size_t at = bytes.size();
        bytes.resize(at + ((16 + size + 7) & ~size_t(7)), 0xa5);
        uint64_t length = 16 + size;
        uint32_t level = 41;
        memcpy(bytes.data() + at, &length, 8);
        memcpy(bytes.data() + at + 8, &level, 4);
        memcpy(bytes.data() + at + 12, &type, 4);
        if (size)
            memcpy(bytes.data() + at + 16, data, size);
    };

    struct Info {
        ip6::Address source;
        uint32_t index;
    } info{socket->local, ipv6_loopback};

    append(50, &info, sizeof(info));
    int value = 43;
    append(52, &value, 4);
    value = 0xab;
    append(67, &value, 4);
    value = 1;
    append(62, &value, 4);
    Inet6SendControl output;
    assert(!inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true));
    assert(output.source == socket->local && output.index == ipv6_loopback && output.hops == 43 &&
           output.traffic_class == 0xab && output.dont_fragment && output.present);
    assert(socket->hops == 33 && socket->traffic_class == 18 && !socket->dont_fragment);
    value = -1;
    append(52, &value, 4);
    append(67, &value, 4);
    assert(!inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true));
    assert(output.hops == 33 && output.traffic_class == 255);
    assert(!inet6_parse_send_control(socket, target, nullptr, 0, output, true));
    assert(output.hops == 33 && output.traffic_class == 18 && !output.present);
    for (unsigned index : {1u, 2u}) {
        bytes.clear();
        info.index = index;
        append(50, &info, sizeof(info));
        assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true) ==
               -22);
    }
    bytes.clear();
    info.index = 0;
    append(50, &info, sizeof(info));
    assert(!inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true));
    assert(output.source == socket->local && !output.index);
    // These duplicate/legacy outcomes come from the same complete native
    // admission probe, including its ordinary-user privilege checks.
    uint8_t first[8] = {250, 0, 0x1e, 4, 0x11, 0x11, 0x11, 0x11};
    uint8_t second[8] = {251, 0, 0x1e, 4, 0x22, 0x22, 0x22, 0x22};
    for (auto test : {std::array<unsigned, 3>{54, 54, 22},
                      {59, 59, 0},
                      {54, 3, 22},
                      {59, 4, 22},
                      {4, 4, 22},
                      {4, 59, 0},
                      {55, 59, 0},
                      {55, 55, 0}}) {
        bytes.clear();
        append(test[0], first, sizeof(first));
        append(test[1], second, sizeof(second));
        auto original = bytes;
        assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true) ==
               -int(test[2]));
        assert(bytes == original);
        assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output,
                                        false) == -1);
        if (!test[2]) {
            assert(!inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output,
                                             true));
            uint8_t encoded[32];
            memset(encoded, 0xa5, sizeof(encoded));
            assert(ip6::encode_output_extensions(encoded, sizeof(encoded), 17, output.extensions));
            assert(ip6::output_extension_size(output.extensions) == (test[1] == 55 ? 0 : 8));
            if (test[1] != 55)
                assert(encoded[0] == 17 && !memcmp(encoded + 1, second + 1, 7));
            else
                assert(std::all_of(encoded, encoded + sizeof(encoded),
                                   [](auto value) { return value == 0xa5; }));
        }
    }
    for (size_t size : {size_t(0), size_t(1), size_t(2), size_t(7), size_t(8), size_t(9),
                        size_t(16), size_t(2048)}) {
        std::vector<uint8_t> header(size);
        if (size > 1)
            header[1] = size == 2048 ? 255 : 0;
        for (uint32_t type : {3u, 4u, 54u, 55u, 59u}) {
            bytes.clear();
            append(type, header.data(), header.size());
            auto original = bytes;
            assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output,
                                            true) == (size < 8 ? -22 : 0));
            assert(bytes == original);
            assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output,
                                            false) == (size < 8 ? -22 : -1));
        }
    }
    uint8_t routing[24] = {250, 2, 2, 1, 0x71, 0x72, 0x73, 0x74};
    memcpy(routing + 8, target.address.bytes, 16);
    for (unsigned kind : {57u, 5u}) {
        bytes.clear();
        append(kind, routing, sizeof(routing));
        const auto original = bytes;
        assert(
            !inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, false));
        assert(bytes == original && output.extensions.routing_length == 24);
        ip6::Address first;
        const auto final = address(7, 9);
        assert(ip6::output_extension_destination(output.extensions, final, first) &&
               first == target.address);
        uint8_t encoded[24];
        memset(encoded, 0xa5, sizeof(encoded));
        assert(!ip6::encode_output_extensions(encoded, sizeof(encoded), 17, output.extensions));
        assert(std::all_of(encoded, encoded + sizeof(encoded),
                           [](auto value) { return value == 0xa5; }));
        assert(
            ip6::encode_output_extensions(encoded, sizeof(encoded), 17, output.extensions, &final));
        assert(encoded[0] == 17 && encoded[1] == 2 && encoded[2] == 2 && encoded[3] == 1 &&
               !memcmp(encoded + 4, routing + 4, 4) && !memcmp(encoded + 8, final.bytes, 16));
        for (unsigned field : {1u, 2u, 3u}) {
            bytes[16 + field] ^= 1;
            assert(inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output,
                                            false) == -22);
            bytes[16 + field] ^= 1;
        }
    }
    for (unsigned kind : {57u, 5u}) {
        bytes.clear();
        append(59, first, sizeof(first));
        append(kind, routing, sizeof(routing));
        assert(!inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true));
        assert(output.extensions.routing_length == 24);
        assert(output.extensions.before_routing_length == (kind == 5 ? 8 : 0));
        assert(output.extensions.destination_length == (kind == 5 ? 0 : 8));
    }
    uint32_t random = 0x641831;
    for (unsigned count = 0; count < 5000; count++) {
        bytes.resize(count % 257);
        for (auto& byte : bytes) {
            random = random * 1664525 + 1013904223;
            byte = random >> 24;
        }
        int error =
            inet6_parse_send_control(socket, target, bytes.data(), bytes.size(), output, true);
        assert(error == 0 || error == -22 || error == -19);
    }
    inet6_close(socket);
    reset();
}

static void receive_extension_policy() {
    for (uint8_t protocol : {0, 60}) {
        std::vector<uint8_t> bytes(40 + 24 + 4);
        ip6::Header header;
        header.next_header = protocol;
        header.payload_length = 28;
        assert(ip6::encode(bytes.data(), bytes.size(), header));
        bytes[40] = 58;
        bytes[41] = 2;
        for (unsigned n = 0; n < 8; n++) {
            bytes[42 + n * 2] = 0x1e;
            bytes[43 + n * 2] = 0;
        }
        auto packet = ip6::decode(bytes.data(), bytes.size());
        assert(packet.input == ip6::Input::payload && ip6::receive_extension_options(packet));
        bytes[58] = 0x1e;
        bytes[59] = 0;
        packet = ip6::decode(bytes.data(), bytes.size());
        assert(packet.input == ip6::Input::payload && !ip6::receive_extension_options(packet) &&
               ip6::receive_extension_options(packet, 9));
        std::fill(bytes.begin() + 42, bytes.end(), 0);
        bytes[49] = 0x1e;
        bytes[50] = 0;
        bytes[56] = 0x1e;
        bytes[57] = 0;
        packet = ip6::decode(bytes.data(), bytes.size());
        assert(packet.input == ip6::Input::payload && ip6::receive_extension_options(packet));
        bytes[49] = 0;
        bytes[50] = 0;
        packet = ip6::decode(bytes.data(), bytes.size());
        assert(packet.input == ip6::Input::payload && !ip6::receive_extension_options(packet));
        std::fill(bytes.begin() + 42, bytes.begin() + 64, 0);
        bytes[42] = 1;
        bytes[43] = 20;
        packet = ip6::decode(bytes.data(), bytes.size());
        assert(packet.input == ip6::Input::payload && !ip6::receive_extension_options(packet));
    }
}

static void copied_extension_output() {
    for (unsigned lane = 0; lane < 2; lane++) {
        reset();
        unsigned index = lane + 1;
        callback_index = index;
        auto local = address(lane, 2), remote = address(lane, 1);
        assert(!change(index, local));
        auto socket = inet6_allocate(3);
        assert(socket);
        Inet6Address target{10, 0, 0, remote, 0};
        uint8_t hop[8] = {250, 0, 0x1e, 4, 0x11, 0x11, 0x11, 0x11};
        uint8_t destination[16] = {251,  1, 0x1e, 4,    0x22, 0x22, 0x22, 0x22,
                                   0x1e, 6, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
        auto policy = inet6_send_defaults(socket, target);
        policy.extensions = {hop, sizeof(hop), destination, sizeof(destination)};
        policy.hops = 43;
        policy.traffic_class = 0xab;
        policy.present = true;
        std::vector<uint8_t> payload(4000, 0x7b);
        payload[0] = 129;
        payload[1] = payload[2] = payload[3] = 0;
        auto original = payload;
        uint8_t expected_destination[16];
        memcpy(expected_destination, destination, sizeof(destination));
        expected_destination[0] = 44;
        assert(inet6_send(socket, target, payload.data(), payload.size(), true, &policy) == 4000);
        memset(hop, 0xa5, sizeof(hop));
        memset(destination, 0xa5, sizeof(destination));
        std::fill(payload.begin(), payload.end(), 0xa5);
        socket->hops = 99;
        socket->traffic_class = 7;
        socket->dont_fragment = true;
        inet6_close(socket);
        auto reused = inet6_allocate(3);
        assert(reused == socket && !reused->transmitted && !reused->error);
        net_poll();
        deliver(lane, advertisement(lane, remote, local));
        net_poll();
        std::vector<uint8_t> restored;
        unsigned fragments = 0;
        for (const auto& frame : emitted[lane]) {
            auto packet = ip6::decode(frame.data() + 14, frame.size() - 14);
            if (packet.input != ip6::Input::fragment)
                continue;
            assert(packet.fragment.header_offset == 64 &&
                   packet.fragment.offset == restored.size() && packet.header.hop_limit == 43 &&
                   packet.header.traffic_class == 0xab && packet.header.source == local &&
                   packet.header.destination == remote);
            const auto* bytes = frame.data() + 14;
            assert(bytes[6] == 0 && bytes[40] == 60 && bytes[42] == 0x1e && bytes[44] == 0x11 &&
                   bytes[64] == 58);
            assert(!memcmp(bytes + 48, expected_destination, sizeof(expected_destination)));
            restored.insert(restored.end(), packet.payload, packet.payload + packet.length);
            fragments++;
        }
        assert(fragments >= 3 && restored.size() == original.size());
        assert(!ip6::checksum(local, remote, 58, restored.data(), original.size()));
        assert(std::equal(original.begin() + 4, original.end(), restored.begin() + 4));
        assert(!reused->transmitted && !reused->error);
        inet6_close(reused);
        reset();
    }
}

static void copied_routing_output() {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (int kind : {2, 3}) {
            reset();
            unsigned index = lane + 1;
            callback_index = index;
            auto local = address(lane, 2), first = address(lane, 1), final = address(7, 9);
            assert(!change(index, local));
            auto socket = inet6_allocate(kind);
            assert(socket);
            socket->local = local;
            socket->index = index;
            if (kind == 2)
                assert(!inet6_bind_port(socket, local, 7000 + lane));
            Inet6Address target{10, __builtin_bswap16(uint16_t(kind == 2 ? 9000 : 58)), 0, final,
                                0};
            uint8_t hop[8] = {250, 0, 0x1e, 4, 0x11, 0x11, 0x11, 0x11};
            uint8_t before[8] = {251, 0, 0x1e, 4, 0x22, 0x22, 0x22, 0x22};
            uint8_t routing[24] = {252, 2, 2, 1, 0x71, 0x72, 0x73, 0x74};
            memcpy(routing + 8, first.bytes, 16);
            uint8_t destination[16] = {253, 1, 0x1e, 12};
            memset(destination + 4, 0x33, 12);
            auto policy = inet6_send_defaults(socket, target);
            policy.extensions = {hop,    sizeof(hop),    destination, sizeof(destination),
                                 before, sizeof(before), routing,     sizeof(routing)};
            policy.hops = 47;
            policy.traffic_class = 0xcd;
            policy.present = true;
            std::vector<uint8_t> payload(16384);
            for (unsigned n = 0; n < payload.size(); n++)
                payload[n] = n * 23 + lane;
            if (kind == 3) {
                payload[0] = 129;
                payload[1] = payload[2] = payload[3] = 0;
            }
            const auto original = payload;
            assert(inet6_send(socket, target, payload.data(), payload.size(), true, &policy) ==
                   16384);
            memset(hop, 0xa5, sizeof(hop));
            memset(before, 0xa5, sizeof(before));
            memset(routing, 0xa5, sizeof(routing));
            memset(destination, 0xa5, sizeof(destination));
            std::fill(payload.begin(), payload.end(), 0xa5);
            socket->hops = 99;
            socket->traffic_class = 7;
            inet6_close(socket);
            auto reused = inet6_allocate(kind);
            assert(reused == socket && !reused->error && !reused->transmitted);
            net_poll();
            deliver(lane, advertisement(lane, first, local));
            for (unsigned count = 0; count < 10; count++)
                net_poll();
            std::vector<uint8_t> restored;
            unsigned pieces = 0;
            uint32_t identity = 0;
            for (const auto& frame : emitted[lane]) {
                if (frame.size() < 14 + 88 || frame[20] != 0)
                    continue;
                const auto* bytes = frame.data() + 14;
                assert(frame.size() <= 1514 &&
                       (size_t(bytes[4]) << 8 | bytes[5]) == frame.size() - 54);
                assert(bytes[0] == 0x6c && bytes[1] == 0xd0 && !bytes[2] && !bytes[3] &&
                       bytes[7] == 47);
                assert(!memcmp(bytes + 8, local.bytes, 16) && !memcmp(bytes + 24, first.bytes, 16));
                assert(bytes[40] == 60 && bytes[42] == 0x1e && bytes[44] == 0x11 &&
                       bytes[48] == 43 && bytes[50] == 0x1e && bytes[52] == 0x22);
                assert(bytes[56] == 44 && bytes[57] == 2 && bytes[58] == 2 && bytes[59] == 1 &&
                       bytes[60] == 0x71 && bytes[63] == 0x74 &&
                       !memcmp(bytes + 64, final.bytes, 16));
                assert(bytes[80] == 60 && !bytes[81]);
                uint16_t flags = uint16_t(bytes[82]) << 8 | bytes[83];
                assert(!(flags & 6) && (flags & 0xfff8) == restored.size());
                uint32_t actual = uint32_t(bytes[84]) << 24 | uint32_t(bytes[85]) << 16 |
                                  uint32_t(bytes[86]) << 8 | bytes[87];
                if (!pieces)
                    identity = actual;
                assert(identity && actual == identity);
                restored.insert(restored.end(), bytes + 88, frame.data() + frame.size());
                pieces++;
            }
            size_t upper = kind == 2 ? 8 : 0;
            uint8_t protocol = kind == 2 ? 17 : 58;
            assert(pieces > 8 && restored.size() == original.size() + upper + 16 &&
                   restored[0] == protocol && restored[1] == 1 && restored[2] == 0x1e &&
                   restored[3] == 12);
            for (unsigned n = 4; n < 16; n++)
                assert(restored[n] == 0x33);
            assert(!ip6::checksum(local, final, protocol, restored.data() + 16,
                                  upper + original.size()));
            assert(ip6::checksum(local, first, protocol, restored.data() + 16,
                                 upper + original.size()));
            if (kind == 2)
                assert(std::equal(original.begin(), original.end(), restored.begin() + 24));
            else
                assert(std::equal(original.begin() + 4, original.end(), restored.begin() + 20));
            assert(!reused->error && !reused->transmitted);
            inet6_close(reused);
            reset();
        }
    }
}

static void sticky_extension_controls() {
    auto socket = inet6_allocate(2);
    assert(socket);
    uint8_t hop[16] = {250, 0, 0x1e, 4, 0x11, 0x11, 0x11, 0x11};
    assert(!inet6_extension_set(socket, 54, hop, sizeof(hop)));
    size_t size = 0;
    auto saved = inet6_extension_get(socket, 54, size);
    assert(size == 8 && saved != hop && !memcmp(saved, hop, size));
    memset(hop, 0xa5, sizeof(hop));
    assert(saved[0] == 250 && saved[7] == 0x11);
    assert(inet6_extension_set(socket, 54, hop, sizeof(hop)) == -22);
    assert(inet6_extension_get(socket, 54, size) == saved && size == 8);
    Inet6Address target;
    auto defaults = inet6_send_defaults(socket, target);
    assert(defaults.extensions.hop == saved);
    Inet6SendControl selected;
    int value = 47;

    struct Scalar {
        uint64_t length;
        uint32_t level, kind;
        int value;
        uint32_t padding;
    } scalar{20, 41, 52, value, 0};

    assert(!inet6_parse_send_control(socket, target, reinterpret_cast<const uint8_t*>(&scalar),
                                     sizeof(scalar), selected, false));
    assert(selected.extensions.hop == saved && selected.hops == 47);
    uint8_t only_destination[24]{};
    uint64_t length = 24;
    uint32_t level = 41, option = 59;
    memcpy(only_destination, &length, 8);
    memcpy(only_destination + 8, &level, 4);
    memcpy(only_destination + 12, &option, 4);
    only_destination[16] = 250;
    assert(!inet6_parse_send_control(socket, target, only_destination, sizeof(only_destination),
                                     selected, true));
    assert(!selected.extensions.hop && selected.extensions.destination_length == 8);
    uint8_t routing[48] = {250, 4, 4, 1, 1};
    routing[39] = 1;
    assert(!inet6_extension_set(socket, 57, routing, 40));
    auto original = inet6_extension_get(socket, 57, size);
    assert(size == 40 && original != routing);
    for (auto [field, invalid] : {std::pair{2u, 0u}, std::pair{3u, 2u}, std::pair{4u, 2u}}) {
        auto before = routing[field];
        routing[field] = invalid;
        assert(inet6_extension_set(socket, 57, routing, 40) == -22);
        assert(inet6_extension_get(socket, 57, size) == original && size == 40);
        routing[field] = before;
    }
    assert(inet6_extension_set(socket, 57, routing, 48) == -22);
    routing[1] = 5;
    routing[40] = 0x1e;
    routing[41] = 6;
    assert(!inet6_extension_set(socket, 57, routing, sizeof(routing)));
    routing[41] = 7;
    assert(inet6_extension_set(socket, 57, routing, sizeof(routing)) == -22);
    assert(inet6_extension_set(socket, 54, nullptr, 8) == -22);
    assert(inet6_extension_set(socket, 56, nullptr, 0) == -92);
    auto policy = inet6_send_defaults(socket, target);
    auto request = static_cast<uint8_t*>(alloc(16));
    assert(!inet6_own_send_extensions(policy, request) && request);
    inet6_close(socket);
    auto reused = inet6_allocate(2);
    assert(reused == socket && !reused->extensions.hop && !reused->extensions.routing);
    ip6::Address first;
    assert(ip6::output_extension_destination(policy.extensions, target.address, first) &&
           first.bytes[15] == 1);
    release(request);
    inet6_close(reused);
}

static void copied_sticky_output(unsigned mode) {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (int kind : {2, 3}) {
            reset();
            unsigned index = lane + 1;
            callback_index = index;
            auto local = address(lane, 2), first = address(lane, 1), final = address(7, 9);
            assert(!change(index, local));
            auto socket = inet6_allocate(kind);
            assert(socket);
            socket->local = local;
            socket->index = index;
            if (kind == 2)
                assert(!inet6_bind_port(socket, local, 7000 + lane));
            Inet6Address target{10, __builtin_bswap16(uint16_t(kind == 2 ? 9000 : 58)), 0, final,
                                0};
            uint8_t hop[8] = {250, 0, 0x1e, 4, 0x11, 0x11, 0x11, 0x11};
            uint8_t before[8] = {251, 0, 0x1e, 4, 0x22, 0x22, 0x22, 0x22};
            size_t routing_size = mode == 1 ? 40 : mode == 3 ? 64 : 24;
            std::vector<uint8_t> routing(routing_size);
            routing[0] = 252;
            routing[1] = routing_size / 8 - 1;
            routing[2] = mode ? 4 : 2;
            routing[3] = mode == 2 ? 0 : mode == 3 ? 2 : 1;
            routing[4] = mode ? routing[3] : 0x71;
            routing[5] = mode ? 0 : 0x72;
            routing[6] = 0x73;
            routing[7] = 0x74;
            for (size_t at = 8; at + 16 <= routing.size(); at += 16)
                memcpy(routing.data() + at, address(6, at).bytes, 16);
            memcpy(routing.data() + 8 + (mode ? routing[3] * 16 : 0), first.bytes, 16);
            if (mode == 3) {
                routing[56] = 0x1e;
                routing[57] = 6;
                memset(routing.data() + 58, 0x99, 6);
            }
            auto expected_routing = routing;
            expected_routing[0] = 44;
            memcpy(expected_routing.data() + 8, final.bytes, 16);
            uint8_t destination[16] = {253, 1, 0x1e, 12};
            memset(destination + 4, 0x33, 12);
            assert(!inet6_extension_set(socket, 54, hop, sizeof(hop)));
            assert(!inet6_extension_set(socket, 55, before, sizeof(before)));
            assert(!inet6_extension_set(socket, 57, routing.data(), routing.size()));
            assert(!inet6_extension_set(socket, 59, destination, sizeof(destination)));
            auto policy = inet6_send_defaults(socket, target);
            uint8_t* retained = nullptr;
            assert(!inet6_own_send_extensions(policy, retained) && retained);
            policy.hops = 47;
            policy.traffic_class = 0xcd;
            std::vector<uint8_t> payload(16384);
            for (unsigned n = 0; n < payload.size(); n++)
                payload[n] = n * 23 + lane;
            if (kind == 3) {
                payload[0] = 129;
                payload[1] = payload[2] = payload[3] = 0;
            }
            const auto original = payload;
            assert(
                !inet6_send_admit(socket, target, payload.size(), payload.data(), true, &policy));
            // An alias clears shared options after request admission, before
            // actual send. The request must still own its selected header bytes.
            inet6_extensions_clear(socket);
            assert(inet6_send(socket, target, payload.data(), payload.size(), true, &policy) ==
                   16384);
            release(retained);
            memset(hop, 0xa5, sizeof(hop));
            memset(before, 0xa5, sizeof(before));
            std::fill(routing.begin(), routing.end(), 0xa5);
            memset(destination, 0xa5, sizeof(destination));
            std::fill(payload.begin(), payload.end(), 0xa5);
            socket->hops = 99;
            socket->traffic_class = 7;
            inet6_close(socket);
            auto reused = inet6_allocate(kind);
            assert(reused == socket && !reused->error && !reused->transmitted);
            net_poll();
            deliver(lane, advertisement(lane, first, local));
            for (unsigned count = 0; count < 10; count++)
                net_poll();
            assert(!reused->extensions.hop && !reused->extensions.before_routing &&
                   !reused->extensions.routing && !reused->extensions.destination);
            size_t fragment_at = 56 + routing_size;
            std::vector<uint8_t> restored;
            unsigned pieces = 0;
            uint32_t identity = 0;
            for (const auto& frame : emitted[lane]) {
                if (frame.size() < 14 + fragment_at + 8 || frame[20] != 0)
                    continue;
                const auto* bytes = frame.data() + 14;
                assert(frame.size() <= 1514 &&
                       (size_t(bytes[4]) << 8 | bytes[5]) == frame.size() - 54);
                assert(bytes[0] == 0x6c && bytes[1] == 0xd0 && !bytes[2] && !bytes[3] &&
                       bytes[7] == 47);
                assert(!memcmp(bytes + 8, local.bytes, 16) && !memcmp(bytes + 24, first.bytes, 16));
                assert(bytes[40] == 60 && bytes[42] == 0x1e && bytes[44] == 0x11 &&
                       bytes[48] == 43 && bytes[50] == 0x1e && bytes[52] == 0x22);
                assert(!memcmp(bytes + 56, expected_routing.data(), expected_routing.size()));
                assert(bytes[fragment_at] == 60 && !bytes[fragment_at + 1]);
                uint16_t flags = uint16_t(bytes[fragment_at + 2]) << 8 | bytes[fragment_at + 3];
                assert(!(flags & 6) && (flags & 0xfff8) == restored.size());
                uint32_t actual = uint32_t(bytes[fragment_at + 4]) << 24 |
                                  uint32_t(bytes[fragment_at + 5]) << 16 |
                                  uint32_t(bytes[fragment_at + 6]) << 8 | bytes[fragment_at + 7];
                if (!pieces)
                    identity = actual;
                assert(identity && actual == identity);
                restored.insert(restored.end(), bytes + fragment_at + 8,
                                frame.data() + frame.size());
                pieces++;
            }
            size_t upper = kind == 2 ? 8 : 0;
            uint8_t protocol = kind == 2 ? 17 : 58;
            assert(pieces > 8 && restored.size() == original.size() + upper + 16 &&
                   restored[0] == protocol && restored[1] == 1 && restored[2] == 0x1e &&
                   restored[3] == 12);
            for (unsigned n = 4; n < 16; n++)
                assert(restored[n] == 0x33);
            assert(!ip6::checksum(local, final, protocol, restored.data() + 16,
                                  upper + original.size()));
            assert(ip6::checksum(local, first, protocol, restored.data() + 16,
                                 upper + original.size()));
            if (kind == 2)
                assert(std::equal(original.begin(), original.end(), restored.begin() + 24));
            else
                assert(std::equal(original.begin() + 4, original.end(), restored.begin() + 20));
            assert(!reused->error && !reused->transmitted);
            inet6_close(reused);
            reset();
        }
    }
}

static void retained_address_expiry() {
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

static void legacy_route_inventory() {
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

static void local_route_visibility() {
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

static void queued_automatic_source_removal() {
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

static void retired_neighbor_source() {
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

static void cross_interface_source_output() {
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

static void manual_source_policy() {
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

static void loopback_source_output() {
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

static void loopback_source_mtu() {
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

static void reviewed_source_edges() {
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

static void fresh_link_dad_cycles() {
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

static void automatic_link_configuration() {
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

static void configuration_files() {
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
    dad();
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
