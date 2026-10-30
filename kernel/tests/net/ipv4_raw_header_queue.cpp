// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace ax;

void ipv4_raw_header_queue_cases(NetAdapter& adapter, std::vector<std::vector<uint8_t>>& frames) {
    constexpr uint32_t local = 0x0a170902, survivor = local + 1, peer = 0x0a170901;
    const char* names[] = {"source", "mtu", "route", "close", "mode"};
    const char* only = std::getenv("AXIOM_IPV4_RAW_QUEUE_CASE");
    unsigned ran = 0;
    for (unsigned test = 0; test < 5; test++) {
        if (only && strcmp(only, names[test]))
            continue;
        ran++;
        ipv4_shutdown();
        assert(net_configure(1, true, 1500) == 0);
        assert(ipv4_configure(1, {local, 0xffffff00, 0}) == 0);
        assert(ipv4_address_add(1, "eth0:raw-wait", {survivor, UINT32_MAX, 0}) == 0);
        Ipv4Route route{peer, UINT32_MAX, 0, 1};
        if (test == 2)
            assert(ipv4_route(route, false) == 0);
        auto socket = inet_allocate(3);
        assert(socket);
        socket->header_included = true;
        socket->protocol = 255;
        socket->index = 1;
        const size_t length = test == 1 ? 1500 : 28;
        std::vector<uint8_t> bytes(length);
        bytes[0] = 0x45;
        bytes[1] = 0x5a;
        bytes[8] = 35;
        bytes[9] = 75;
        ip4::put16(bytes.data() + 2, 0x1111);
        ip4::put16(bytes.data() + 4, 0x1357);
        ip4::put16(bytes.data() + 10, 0xaaaa);
        ip4::put32(bytes.data() + 12, 0xc0000201);
        ip4::put32(bytes.data() + 16, 0x0a17094d);
        for (size_t at = 20; at < length; at++)
            bytes[at] = uint8_t(at * 37 + 11);
        auto expected = bytes;
        ip4::put16(expected.data() + 2, length);
        ip4::put16(expected.data() + 10, 0);
        ip4::put16(expected.data() + 10, ip4::checksum(expected.data(), 20));
        InetAddress destination{2, 0, __builtin_bswap32(peer), {}};
        auto before = frames.size();
        assert(inet_send(socket, destination, bytes.data(), length, true) == int64_t(length));
        assert(socket->transmitted == length);
        ipv4_poll();
        assert(frames.size() == before + 1 && ip4::get16(frames.back().data() + 12) == 0x0806 &&
               ip4::get32(frames.back().data() + 28) == local &&
               ip4::get32(frames.back().data() + 38) == peer);
        auto reply = frames.back();
        if (test == 0) {
            assert(ipv4_address_remove(1, local, 0xffffff00) == 0);
            // Linux keeps the complete accepted packet while another address
            // remains, independently of its literal or selected source.
            assert(socket->transmitted == length);
        } else if (test == 1)
            assert(net_configure(1, true, 68) == 0);
        else if (test == 2)
            assert(ipv4_route(route, true) == 0);
        else if (test == 3)
            inet_dispose(socket);
        else {
            socket->header_included = false;
            assert(socket->options.assign(nullptr, 0) == 0);
        }
        memset(bytes.data(), 0xcc, bytes.size());
        const uint8_t hardware[6] = {2, 0x41, 0x58, 0x49, 0x50, 0};
        memcpy(reply.data(), adapter.info.mac, 6);
        memcpy(reply.data() + 6, hardware, 6);
        ip4::put16(reply.data() + 20, 2);
        memcpy(reply.data() + 22, hardware, 6);
        ip4::put32(reply.data() + 28, peer);
        memcpy(reply.data() + 32, adapter.info.mac, 6);
        ip4::put32(reply.data() + 38, test == 0 ? survivor : local);
        ipv4_receive(adapter.info, reply.data(), reply.size());
        ipv4_poll();
        assert(frames.size() == before + 2 && !memcmp(frames.back().data(), hardware, 6) &&
               frames.back().size() >= ethernet_header + length &&
               !memcmp(frames.back().data() + ethernet_header, expected.data(), length));
        if (test == 1) {
            // The internal admitted packet must not relax a fresh AF_PACKET
            // send or permit a frame above the device's physical capability.
            assert(net_send(1, frames.back().data(), frames.back().size()) == -90);
            adapter.info.maximum_mtu = 1400;
            assert(net_send_checked(1, frames.back().data(), frames.back().size(), nullptr, nullptr,
                                    nullptr, 1500) == -90);
            adapter.info.maximum_mtu = 1500;
        }
        if (test != 3) {
            assert(socket->transmitted == 0 && inet_error(socket, true) == 0);
            inet_dispose(socket);
        }
        assert(net_configure(1, true, 1500) == 0);
        assert(ipv4_address_remove(1, survivor, UINT32_MAX) == 0);
        assert(ipv4_configure(1, {}) == 0);
        ipv4_shutdown();
        std::printf("IPV4_RAW_HEADER_QUEUE_CASE_PASS case=%s\n", names[test]);
    }
    assert(ran == (only ? 1u : 5u));
}
