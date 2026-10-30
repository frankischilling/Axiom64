// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;

void ipv4_raw_header_cases(NetAdapter& adapter, std::vector<std::vector<uint8_t>>& frames) {
    ipv4_shutdown();
    constexpr uint32_t local = 0x0a170902, peer = 0x0a170901;
    assert(ipv4_configure(1, {local, 0xffffff00, 0}) == 0);
    auto sender = inet_allocate(3);
    assert(sender);
    sender->header_included = true;
    sender->protocol = 1; // Header mode must suppress the ICMP payload prefix.
    sender->index = 1;
    InetAddress target{2, 0, __builtin_bswap32(peer), {}};
    std::vector<uint8_t> packet(1501, 0x71);
    auto reset = [&](size_t header = 20) {
        memset(packet.data(), 0, packet.size());
        packet[0] = uint8_t(0x40 | header / 4);
        packet[1] = 0x5a;
        packet[8] = 35;
        packet[9] = 75;
        ip4::put16(packet.data() + 2, 0x1111);
        ip4::put16(packet.data() + 4, 0x1357);
        ip4::put16(packet.data() + 10, 0xaaaa);
        ip4::put32(packet.data() + 12, 0xc0000201);
        // Header fields do not control the route, ARP source or multicast MAC.
        ip4::put32(packet.data() + 16, 0xe000004d);
        memset(packet.data() + 20, 1, header - 20);
    };
    reset();
    InetSendControl held;
    assert(inet_prepare_send(sender, target, true, sizeof(target), 28, nullptr, 0, held) == 0);
    assert(inet_send_prefix(sender, &held) == 0);
    assert(inet_send_admit(sender, target, 28, held) == 0);
    sender->header_included = false;
    sender->ttl = 9;
    assert(inet_send_prefix(sender) == 2 && inet_send_prefix(sender, &held) == 0);
    auto start = frames.size();
    assert(inet_send(sender, target, packet.data(), 28, true, &held) == 28);
    assert(sender->transmitted == 28);
    memset(packet.data(), 0xcc, 28);
    assert(sender->options.assign(nullptr, 0) == 0);
    ipv4_poll();
    assert(frames.size() == start + 1);
    auto reply = frames.back();
    assert(ip4::get16(reply.data() + 12) == 0x0806);
    assert(ip4::get32(reply.data() + 28) == local && ip4::get32(reply.data() + 38) == peer);
    const uint8_t hardware[6] = {2, 0x55, 0x4e, 0x43, 0, 1};
    memcpy(reply.data(), adapter.info.mac, 6);
    memcpy(reply.data() + 6, hardware, 6);
    ip4::put16(reply.data() + 20, 2);
    memcpy(reply.data() + 22, hardware, 6);
    ip4::put32(reply.data() + 28, peer);
    memcpy(reply.data() + 32, adapter.info.mac, 6);
    ip4::put32(reply.data() + 38, local);
    ipv4_receive(adapter.info, reply.data(), reply.size());
    ipv4_poll();
    assert(frames.size() == start + 2 && sender->transmitted == 0);
    const auto ip = frames.back().data() + ethernet_header;
    assert(!memcmp(frames.back().data(), hardware, 6));
    assert(ip[8] == 35 && ip[9] == 75 && ip4::get16(ip + 2) == 28 && !ip4::checksum(ip, 20));
    assert(ip4::get32(ip + 12) == 0xc0000201 && ip4::get32(ip + 16) == 0xe000004d);
    sender->header_included = true;
    sender->options = {};
    // Cached path MTU does not limit a complete literal header; the device does.
    assert(ipv4_learn_pmtu(local, peer, 1, 1000, 1500) == 1000);
    for (unsigned header : {20u, 24u, 60u}) {
        reset(header);
        packet[0] |= 0x20; // Another version is preserved on output.
        ip4::put32(packet.data() + 12, 0);
        ip4::put16(packet.data() + 4, 0);
        ip4::put16(packet.data() + 6, 0x4000);
        start = frames.size();
        assert(inet_send(sender, target, packet.data(), 1500, true) == 1500);
        ipv4_poll();
        assert(frames.size() == start + 1 && frames.back().size() == 1514 && !sender->transmitted);
        const auto actual = frames.back().data() + ethernet_header;
        assert(actual[0] == packet[0] && ip4::get32(actual + 12) == local &&
               ip4::get16(actual + 2) == 1500 && ip4::get16(actual + 4) == 0 &&
               ip4::get16(actual + 6) == 0x4000 && !ip4::checksum(actual, header) &&
               !memcmp(actual + 20, packet.data() + 20, 1480));
    }
    reset();
    assert(inet_send(sender, target, packet.data(), 1501, true) == -90);
    assert(inet_send(sender, target, packet.data(), 19, true) == -22);
    for (unsigned header : {0u, 4u, 15u}) {
        packet[0] = uint8_t(0x40 | header);
        assert(inet_send(sender, target, packet.data(), 28, true) == -22);
    }
    reset(28);
    const uint8_t literal[8] = {134, 8, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa};
    memcpy(packet.data() + 20, literal, 8);
    assert(inet_send(sender, target, packet.data(), 36, true) == 36);
    ipv4_poll();
    assert(!memcmp(frames.back().data() + ethernet_header + 20, literal, 8));
    assert(sender->options.assign(nullptr, 0) == 0 && sender->options.assigned() &&
           sender->options.size() == 0);
    assert(inet_send(sender, target, packet.data(), 36, true) == -22);
    sender->options = {};
    start = frames.size();
    assert(inet_send(sender, target, packet.data(), 36, true) == 36 && sender->transmitted == 36);
    // The assigned route source owns a pending spoofed packet's local lifetime.
    assert(ipv4_configure(1, {}) == 0 && sender->transmitted == 0);
    ipv4_poll();
    assert(frames.size() == start && inet_error(sender, true) == 0);
    inet_dispose(sender);
    ipv4_shutdown();
    std::puts(
        "IPV4_RAW_HEADERS_HOST_PASS literal_fields route_ownership captured_mode caller_reuse "
        "device_mtu cached_pmtu_ignored options_presence source_retirement quota");
}
