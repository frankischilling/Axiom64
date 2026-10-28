// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/inet.hpp"
#include "net/udp.hpp"
#include "net/ipv6/configuration.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "net/ipv6/icmp.hpp"

namespace ax {
void tcp6_icmp_error(unsigned, const ip6::ErrorQuote&) {
}

void tcp_receive(unsigned, const ip6::Address&, const ip6::Address&, const void*, size_t) {
}

int random_read(void*, size_t, bool) {
    std::abort();
}

uint64_t ticks = 100;

void* alloc(size_t length) {
    return std::malloc(length);
}

void release(void* bytes) {
    std::free(bytes);
}

void log(const char*, ...) {
}

Ipv4Destination* inet_output_destination(InetSocket* socket, uint32_t, bool) {
    assert(!socket);
    return nullptr;
}

bool inet_dont_fragment(const InetSocket* socket, bool) {
    assert(!socket);
    return true;
}

bool inet_fragmentation_allowed(const InetSocket* socket) {
    assert(!socket);
    return false;
}

bool inet_use_path_mtu(const InetSocket* socket) {
    assert(!socket);
    return true;
}

uint8_t inet_traffic_class(const InetSocket*) {
    std::abort(); // This fixture submits only ownerless output.
}

void inet_reclaim(InetSocket*, size_t) {
    assert(false && "output fixture has no socket owner");
}

void inet_failed(InetSocket*, int, unsigned) {
    assert(false && "output fixture has no socket error recipient");
}

void inet_deliver(const Ipv4ReceiveMetadata&, const void*, size_t) {
    assert(false && "ARP fixture must not deliver transport input");
}

void inet_icmp_error(unsigned, const uint8_t*, int, uint16_t) {
    assert(false && "ARP fixture must not receive an ICMP error");
}

UdpInput udp_receive(const Ipv4ReceiveMetadata&, bool, const void*, size_t) {
    assert(false && "ARP fixture must not receive UDP");
    return UdpInput::dropped;
}

void tcp_poll() {
}

void tcp_receive(unsigned, uint32_t, uint32_t, const void*, size_t) {
    assert(false && "ARP fixture must not receive TCP");
}

void tcp_icmp_error(unsigned, const uint8_t*, size_t) {
    assert(false && "ARP fixture must not receive a quoted TCP error");
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}
} // namespace ax

using namespace ax;

struct Captured {
    unsigned index;
    std::vector<uint8_t> bytes;
};

static std::vector<Captured> captured;
static const uint8_t peer_mac[6] = {2, 0x55, 0x4e, 0x43, 0, 1};
static const uint8_t payload[8] = {8, 0, 0xf7, 0xff, 0, 0, 0, 0};

static void poll(NetAdapter&) {
}

static int transmit(NetAdapter& adapter, const void* bytes, size_t length) {
    const auto first = static_cast<const uint8_t*>(bytes);
    captured.push_back({adapter.info.index, {first, first + length}});
    return 0;
}

static std::vector<uint8_t> arp(unsigned index, uint32_t sender, uint32_t target) {
    auto info = net_info(index);
    assert(info);
    std::vector<uint8_t> frame(60);
    memcpy(frame.data(), info->mac, 6);
    memcpy(frame.data() + 6, peer_mac, 6);
    ip4::put16(frame.data() + 12, 0x0806);
    ip4::put16(frame.data() + 14, 1);
    ip4::put16(frame.data() + 16, 0x0800);
    frame[18] = 6;
    frame[19] = 4;
    ip4::put16(frame.data() + 20, 2);
    memcpy(frame.data() + 22, peer_mac, 6);
    ip4::put32(frame.data() + 28, sender);
    memcpy(frame.data() + 32, info->mac, 6);
    ip4::put32(frame.data() + 38, target);
    return frame;
}

static void receive(unsigned index, const std::vector<uint8_t>& frame) {
    ipv4_receive(*net_info(index), frame.data(), frame.size());
}

static void queue(uint32_t peer, uint8_t traffic_class = 0) {
    assert(ipv4_send(nullptr, 0, peer, 1, 1, 64, false, payload, sizeof(payload), true,
                     traffic_class) == 0);
}

static void request(size_t position, uint32_t peer, uint32_t source) {
    assert(captured.size() == position + 1 && captured[position].index == 1);
    const auto& frame = captured[position].bytes;
    assert(frame.size() == 60 && ip4::get16(frame.data() + 12) == 0x0806);
    assert(ip4::get16(frame.data() + 20) == 1);
    assert(ip4::get32(frame.data() + 28) == source);
    assert(ip4::get32(frame.data() + 38) == peer);
}

static void datagram(size_t position, uint32_t peer, uint32_t source, uint8_t traffic_class = 0) {
    assert(captured.size() == position + 1 && captured[position].index == 1);
    const auto& frame = captured[position].bytes;
    assert(frame.size() == 60 && !memcmp(frame.data(), peer_mac, 6));
    assert(ip4::get16(frame.data() + 12) == 0x0800);
    assert(frame[15] == traffic_class && frame[22] == 64);
    assert(ip4::get32(frame.data() + 26) == source);
    assert(ip4::get32(frame.data() + 30) == peer);
    assert(!ip4::checksum(frame.data() + 14, 20));
    assert(!memcmp(frame.data() + 34, payload, sizeof(payload)));
}

static void pending_reply_ownership(uint32_t source) {
    constexpr uint32_t peer = 0xc000020a;
    auto before = captured.size();
    queue(peer, 168);
    auto valid = arp(1, peer, source);
    receive(1, valid); // No ARP attempt yet: a queued output alone is insufficient.
    ipv4_poll();
    request(before, peer, source);
    auto wrong_target = valid;
    ip4::put32(wrong_target.data() + 38, source + 1);
    receive(1, wrong_target);
    receive(1, arp(1, peer + 1, source));
    receive(2, arp(2, peer, source));
    auto wrong_hardware = valid;
    wrong_hardware[32] ^= 2;
    receive(1, wrong_hardware);
    auto mismatched_sender = valid;
    mismatched_sender[22] ^= 2;
    receive(1, mismatched_sender);
    auto unsolicited_request = valid;
    ip4::put16(unsolicited_request.data() + 20, 1);
    receive(1, unsolicited_request);
    ipv4_poll();
    assert(captured.size() == before + 1);
    receive(1, valid);
    ipv4_poll();
    datagram(before + 1, peer, source, 168);

    // An unrelated reply cannot seed a future destination's neighbour mapping.
    before = captured.size();
    queue(peer + 1);
    ipv4_poll();
    request(before, peer + 1, source);
    receive(1, arp(1, peer + 1, source));
    ipv4_poll();
    datagram(before + 1, peer + 1, source);

    // A matching reply after output expiry cannot prime a later accepted packet.
    before = captured.size();
    queue(peer + 2);
    ipv4_poll();
    request(before, peer + 2, source);
    ticks += 400;
    receive(1, arp(1, peer + 2, source));
    ipv4_poll();
    assert(captured.size() == before + 1);
    queue(peer + 2);
    receive(1, arp(1, peer + 2, source));
    ipv4_poll();
    request(before + 1, peer + 2, source);
    receive(1, arp(1, peer + 2, source));
    ipv4_poll();
    datagram(before + 2, peer + 2, source);
    ipv4_shutdown();
}

int main() {
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
    NetAdapter adapters[2];
    for (unsigned n = 0; n < 2; n++) {
        auto& adapter = adapters[n];
        adapter.info.mac[0] = 2;
        adapter.info.mac[5] = n + 1;
        adapter.info.live = adapter.info.administrative = adapter.info.carrier = true;
        adapter.poll = adapter.stop = poll;
        adapter.send = transmit;
        assert(net_register(adapter) == n + 1);
    }
    pending_reply_ownership(0);
    assert(ipv4_configure(2, {0x0a170202, 0xffffff00, 0}) == 0);
    pending_reply_ownership(0x0a170202);
    std::puts("IPV4_OUTPUT_PASS zero-source other-source pending-ARP invalid-inputs expiry");
}
