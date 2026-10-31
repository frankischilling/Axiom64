// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4/configuration.hpp"
#include "net/ipv4_wire.hpp"
#include "net/ipv6/configuration.hpp"
#include "net/ipv6/icmp.hpp"
#include "net/inet.hpp"
#include "net/udp.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
struct Frame {
    unsigned index;
    std::vector<uint8_t> bytes;
};

std::vector<Frame> frames;
std::unordered_set<void*> allocations;
unsigned delivered;
std::string mutation;
bool armed;
} // namespace

namespace ax {
void tcp6_icmp_error(unsigned, const ip6::ErrorQuote&) {
    std::abort();
}

void tcp_receive(unsigned, const ip6::Address&, const ip6::Address&, const void*, size_t) {
    std::abort();
}

uint64_t ticks = 100;

uint64_t clock_realtime_ticks() {
    return ticks;
}

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

int random_read(void*, size_t, bool) {
    std::abort();
}

Ipv4Destination* inet_output_destination(InetSocket* owner, uint32_t, bool) {
    assert(!owner);
    return nullptr;
}

bool inet_dont_fragment(const InetSocket* owner, bool) {
    assert(!owner);
    return true;
}

bool inet_fragmentation_allowed(const InetSocket* owner) {
    assert(!owner);
    return true;
}

bool inet_use_path_mtu(const InetSocket* owner) {
    assert(!owner);
    return true;
}

uint8_t inet_traffic_class(const InetSocket* owner) {
    assert(!owner);
    return 0;
}

void inet_reclaim(InetSocket*, size_t) {
    std::abort();
}

bool inet_stream(InetSocket*) {
    std::abort();
}

void inet_failed(InetSocket*, int, unsigned) {
    std::abort();
}

bool inet_deliver(const Ipv4ReceiveMetadata& metadata, const void* bytes, size_t length) {
    delivered++;
    std::printf("IPV4_SOURCE_ROUTE_RAW index=%u destination=%08x specific=%08x data=",
                metadata.index, metadata.destination, metadata.specific_destination);
    auto data = static_cast<const uint8_t*>(bytes);
    for (size_t at = 0; at < length; at++)
        std::printf("%02x", data[at]);
    std::puts("");
    return false;
}

void inet_icmp_error(unsigned, const uint8_t*, int, uint16_t) {
    std::abort();
}

UdpInput udp_receive(const Ipv4ReceiveMetadata&, bool, const void*, size_t) {
    std::abort();
}

void tcp_poll() {
}

void tcp_receive(unsigned, uint32_t, uint32_t, const void*, size_t, const ip4::ReceivedOptions*,
                 uint8_t) {
    std::abort();
}

void tcp_icmp_error(unsigned, const uint8_t*, size_t) {
    std::abort();
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}
} // namespace ax

using namespace ax;

static void mutate(const std::string& action) {
    if (action == "mtu" || action == "mtu-df")
        assert(!net_configure(2, true, 576));
    else if (action == "egress-address" || action == "egress-alias" ||
             action == "ingress-address") {
        unsigned index = action == "ingress-address" ? 1 : 2;
        assert(!ipv4_address_remove(index, index == 1 ? 0x0a000001 : 0x0a010001, 0xffffff00));
        if (action == "egress-alias")
            assert(ipv4_config(2) && ipv4_config(2)->address == 0x0a020001);
    } else if (action == "route")
        assert(!ipv4_route({0x0a010000, 0xffffff00, 0, 2}, true));
    else if (action == "egress-mask")
        assert(!ipv4_configure_label(2, "eth1", {0x0a010001, 0xffffffff, 0x0a0100ff}));
    else if (action == "egress-broadcast")
        assert(!ipv4_configure_label(2, "eth1", {0x0a010001, 0xffffff00, 0x0a01007f}));
    else if (action == "down" || action == "flap") {
        assert(!net_configure(2, false, net_info(2)->mtu));
        if (action == "flap")
            assert(!net_configure(2, true, net_info(2)->mtu));
    } else if (action == "forwarding")
        assert(!ip4::configuration_write(1, ip4::ConfigurationKey::forwarding, 0));
    else if (action == "source-policy")
        assert(!ip4::configuration_write(ip4::configuration_all,
                                         ip4::ConfigurationKey::accept_source_route, 0));
    else
        assert(action == "baseline");
}

static void poll(NetAdapter& adapter) {
    if (armed && adapter.info.index == 2) {
        armed = false;
        auto owned = allocations.size();
        mutate(mutation.substr(10));
        assert(owned && allocations.size() == owned);
        std::puts("IPV4_SOURCE_ROUTE_BORROWED_STORAGE_RETAINED");
    }
}

static int send(NetAdapter& adapter, const void* bytes, size_t length) {
    auto data = static_cast<const uint8_t*>(bytes);
    frames.push_back({adapter.info.index, {data, data + length}});
    return 0;
}

static void neighbor(unsigned index, bool reply = false) {
    auto info = net_info(index);
    uint8_t bytes[60]{};
    memcpy(bytes, info->mac, 6);
    const uint8_t peer[] = {2, 0, 0, 0, 1, uint8_t(index)};
    memcpy(bytes + 6, peer, 6);
    ip4::put16(bytes + 12, 0x0806);
    ip4::put16(bytes + 14, 1);
    ip4::put16(bytes + 16, 0x0800);
    bytes[18] = 6;
    bytes[19] = 4;
    ip4::put16(bytes + 20, reply ? 2 : 1);
    memcpy(bytes + 22, peer, 6);
    ip4::put32(bytes + 28, index == 1 ? 0x0a000002 : 0x0a010002);
    if (reply)
        memcpy(bytes + 32, info->mac, 6);
    ip4::put32(bytes + 38, reply ? 0x0a010001 : ipv4_config(index)->address);
    ipv4_receive(*info, bytes, sizeof(bytes));
}

int main(int argc, char** argv) {
    assert(argc == 4 || argc == 5);
    if (const char* selected = std::getenv("IPV4_SOURCE_ROUTE_MUTATION"))
        mutation = selected;
    bool held = mutation.starts_with("held-");
    bool unanswered = mutation.starts_with("unanswered-");
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
    NetAdapter adapters[2]{};
    for (unsigned at = 0; at < 2; at++) {
        auto& adapter = adapters[at];
        adapter.info.mac[0] = 2;
        adapter.info.mac[5] = uint8_t(at + 1);
        adapter.info.live = adapter.info.administrative = adapter.info.carrier = true;
        adapter.poll = adapter.stop = poll;
        adapter.send = send;
        assert(net_register(adapter) == at + 1);
        assert(!ipv4_configure(at + 1, {at ? 0x0a010001u : 0x0a000001u, 0xffffff00, 0}));
    }
    if (mutation.ends_with("egress-alias"))
        assert(!ipv4_address_add(2, "eth1:keep", {0x0a020001, 0xffffff00, 0}));
    assert(!net_configure(2, true, mutation.find("mtu") != std::string::npos ? 1500 : 576));
    assert(!ipv4_route({0xcb007100, 0xffffff00, 0x0a010002, 2}, false));
    neighbor(1);
    if (!held && !unanswered)
        neighbor(2);
    ipv4_poll();
    frames.clear();
    assert(!ip4::configuration_write(ip4::configuration_all,
                                     ip4::ConfigurationKey::accept_source_route,
                                     int32_t(std::strtol(argv[1], nullptr, 10))));
    assert(!ip4::configuration_write(1, ip4::ConfigurationKey::accept_source_route,
                                     int32_t(std::strtol(argv[2], nullptr, 10))));
    assert(!ip4::configuration_write(ip4::configuration_all, ip4::ConfigurationKey::forwarding,
                                     int32_t(std::strtol(argv[3], nullptr, 10))));
    if (argc == 5)
        assert(!ip4::configuration_write(1, ip4::ConfigurationKey::forwarding,
                                         int32_t(std::strtol(argv[4], nullptr, 10))));
    std::string encoded;
    unsigned inputs = 0;
    while (std::getline(std::cin, encoded)) {
        assert(!(encoded.size() % 2) && encoded.size() >= 68 &&
               encoded.size() <= 2 * max_ethernet_frame);
        std::vector<uint8_t> input;
        for (size_t at = 0; at < encoded.size(); at += 2)
            input.push_back(uint8_t(std::stoul(encoded.substr(at, 2), nullptr, 16)));
        ipv4_receive(*net_info(1), input.data(), input.size());
        inputs++;
    }
    assert(inputs && std::cin.eof());
    armed = mutation.starts_with("reentrant-");
    ipv4_poll();
    if (unanswered)
        for (unsigned second = 0; second < 5; second++) {
            ticks += 100;
            ipv4_poll();
        }
    if (held) {
        assert(frames.size() == 1 && frames[0].index == 2 &&
               ip4::get16(frames[0].bytes.data() + 12) == 0x0806 &&
               ip4::get32(frames[0].bytes.data() + 28) == 0x0a010001);
        mutate(mutation.substr(5));
        // The ioctl probe returns its mutation marker before the peer replies.
        // Run the normal output poll between those two external events.
        if (mutation == "held-egress-mask" || mutation == "held-egress-broadcast")
            ipv4_poll();
        neighbor(2, true);
        ipv4_poll();
    }
    for (const auto& frame : frames) {
        std::printf("{\"index\":%u,\"frame\":\"", frame.index);
        for (auto byte : frame.bytes)
            std::printf("%02x", byte);
        std::puts("\"}");
    }
    std::printf("IPV4_SOURCE_ROUTE_MODEL raw_deliveries=%u\n", delivered);
    ipv4_shutdown();
    assert(allocations.empty());
}
