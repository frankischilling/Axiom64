// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/netlink.hpp"
#include "net/ipv6/reassembly.hpp"
#include "../../net/ipv6/socket.hpp"
#include <algorithm>
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
} // namespace

namespace ax {
uint64_t ticks;

void* alloc(size_t length) {
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
    assert(allocations.empty());
    emitted[0].clear();
    emitted[1].clear();
    ticks = 0;
    blocked = 0;
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
            assert(capacity == (type == 26 && !family ? 8192 : 4116));
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
                                        : ipv6_address_capacity + ipv6_route_capacity));
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

int main() {
    for (unsigned n = 0; n < 2; n++) {
        auto& adapter = adapters[n];
        adapter.info.live = adapter.info.carrier = adapter.info.writable = true;
        adapter.info.maximum_mtu = 1500;
        adapter.info.mac[0] = 0x52;
        adapter.info.mac[1] = 0x54;
        adapter.info.mac[5] = 0x10 + n;
        adapter.poll = [](NetAdapter&) {};
        adapter.stop = [](NetAdapter&) {};
        adapter.send = [](NetAdapter& device, const void* data, size_t length) {
            if (blocked)
                return -11;
            const auto bytes = static_cast<const uint8_t*>(data);
            emitted[device.info.index - 1].emplace_back(bytes, bytes + length);
            return 0;
        };
        assert(net_register(adapter) == n + 1);
        assert(net_configure(n + 1, true, 1500) == 0);
    }
    dad();
    echo_and_ownership();
    routes_and_deadlines();
    inventories_and_bounds();
    direct_neighbor_replies();
    prefix_lifetimes();
    prefix_route_order();
    socket_ownership();
    fragmented_delivery();
    reset();
    std::puts("IPV6_HOST_PASS adapters=2 DAD=1 duplicate=1 NS=1 NA=1 echo=1 owned_copy=1");
}
