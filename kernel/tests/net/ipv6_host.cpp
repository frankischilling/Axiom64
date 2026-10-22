// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/netlink.hpp"
#include "net/ipv6/reassembly.hpp"
#include "../../net/ipv6/socket.hpp"
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
} // namespace

namespace ax {
uint64_t ticks;

int random_read(void* output, size_t size, bool insecure) {
    static uint32_t next = 0x89abcdef;
    assert(size == sizeof(next) && !insecure);
    if (!entropy_available)
        return -11;
    memcpy(output, &next, size);
    next++;
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
    send_budget = UINT32_MAX;
    fail_allocations = shutdown_after_polls = remove_after_polls = shrink_after_polls = 0;
    entropy_available = true;
    callback_index = 1;
    inject_after_polls = 0;
    injected_frame.clear();
    for (auto& adapter : adapters) {
        adapter.info.live = adapter.info.carrier = true;
        assert(!net_configure(adapter.info.index, true, 1500));
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
        assert(ipv6_path({}, remote, lane + 1, path) == -99);
        ticks = 1050;
        assert(!configure_lifetime(lane + 1, local, 2, 8, 0x105, 96, 0));
        auto refreshed = address_observation(lane + 1, local);
        assert(refreshed.prefix == 64 && refreshed.cache[2] == 1000 && refreshed.cache[3] == 1050);
        ticks = 1099;
        ipv6_poll();
        assert(!ipv6_owned(lane + 1, local));
        ticks = 1100;
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

        reset();
        ticks = 1000;
        assert(!configure_lifetime(lane + 1, local, 2, 8, 0x605, 64, 0));
        ipv6_poll();
        deliver(lane, advertisement(lane, local, ip6::all_nodes()));
        assert((address_observation(lane + 1, local).flags & 0x48) == 0x48);
        assert(!configure_lifetime(lane + 1, local, 2, 8, 0x105));
        assert((address_observation(lane + 1, local).flags & 0x48) == 0x48);
        assert(!ipv6_owned(lane + 1, local, true));
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
            assert(!raw->transmitted && inet6_error(raw, true) == 99 && emitted[lane].empty());
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
    dad();
    echo_and_ownership();
    routes_and_deadlines();
    inventories_and_bounds();
    direct_neighbor_replies();
    prefix_lifetimes();
    finite_address_lifetimes();
    finite_address_dad();
    source_lifetime_preferences();
    finite_prefix_lifetimes();
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
    reset();
    std::puts("IPV6_HOST_PASS adapters=2 DAD=1 duplicate=1 NS=1 NA=1 echo=1 owned_copy=1");
}
