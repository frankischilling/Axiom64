// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../net/ipv4/socket.hpp"
#include "core/time.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;

void ipv4_address_lifecycle_cases(NetAdapter& adapter, std::vector<std::vector<uint8_t>>& frames) {
    constexpr uint32_t local = 0xc6122802, survivor = 0xc6122902, peer = 0xc6122801;
    for (unsigned test = 0; test < 4; test++) {
        bool raw = test & 1, keep = test < 2;
        ipv4_shutdown();
        assert(!ipv4_configure(1, {}));
        assert(!ipv4_address_add(1, "eth0", {local, 0xffffff00, 0}, {0, 1}));
        if (keep)
            assert(!ipv4_address_add(1, "eth0:keep", {survivor, 0xffffff00, 0}));
        auto socket = inet_allocate(raw ? 3 : 2);
        assert(socket);
        socket->index = 1;
        socket->local = local;
        socket->local_port = 49169;
        socket->protocol = raw ? 253 : 17;
        InetAddress target{2, __builtin_bswap16(uint16_t(49170)), __builtin_bswap32(peer), {}};
        uint8_t bytes[8] = {7, 6, 5, 4, 3, 2, 1, 0};
        const auto expected = std::vector<uint8_t>(bytes, bytes + sizeof(bytes));
        auto before = frames.size();
        assert(inet_send(socket, target, bytes, sizeof(bytes), true) == sizeof(bytes));
        assert(socket->transmitted);
        ipv4_poll();
        assert(frames.size() == before + 1 && ip4::get16(frames.back().data() + 12) == 0x0806 &&
               ip4::get32(frames.back().data() + 28) == local);
        auto reply = frames.back();
        memset(bytes, 0xcc, sizeof(bytes));
        ticks += 100;
        assert(!ipv4_local(local)); // Expiry reaches the actual output and route owners.
        if (keep) {
            assert(socket->transmitted && ipv4_local(survivor));
            auto fresh = inet_allocate(raw ? 3 : 2);
            assert(fresh);
            fresh->index = 1;
            fresh->local = local;
            fresh->protocol = raw ? 253 : 17;
            assert(inet_send(fresh, target, bytes, sizeof(bytes), true) == -101);
            inet_dispose(fresh);
        } else {
            assert(!socket->transmitted && !inet_error(socket, true));
        }
        const uint8_t hardware[6] = {2, 0x41, 0x58, 0x49, 0x50, 0};
        memcpy(reply.data(), adapter.info.mac, 6);
        memcpy(reply.data() + 6, hardware, 6);
        ip4::put16(reply.data() + 20, 2);
        memcpy(reply.data() + 22, hardware, 6);
        ip4::put32(reply.data() + 28, peer);
        memcpy(reply.data() + 32, adapter.info.mac, 6);
        // A reply to the original solicitation can complete the admitted
        // packet after its source expired, while a device address survives.
        ip4::put32(reply.data() + 38, local);
        ipv4_receive(adapter.info, reply.data(), reply.size());
        ipv4_poll();
        unsigned packets = 0;
        for (size_t at = before + 1; at < frames.size(); at++) {
            const auto& frame = frames[at];
            if (ip4::get16(frame.data() + 12) != 0x0800)
                continue;
            packets++;
            const auto ip = frame.data() + ethernet_header;
            size_t length = 20 + (raw ? 0 : 8) + expected.size();
            assert(ip[0] == 0x45 && ip[9] == (raw ? 253 : 17) && ip4::get16(ip + 2) == length &&
                   !ip4::checksum(ip, 20) && ip4::get32(ip + 12) == local &&
                   ip4::get32(ip + 16) == peer &&
                   !memcmp(ip + length - expected.size(), expected.data(), expected.size()));
            if (!raw) {
                uint8_t pseudo[28]{};
                ip4::put32(pseudo, local);
                ip4::put32(pseudo + 4, peer);
                pseudo[9] = 17;
                ip4::put16(pseudo + 10, 16);
                memcpy(pseudo + 12, ip + 20, 16);
                assert(ip4::get16(ip + 26) && !ip4::checksum(pseudo, sizeof(pseudo)));
            }
        }
        assert(packets == unsigned(keep) && !socket->transmitted);
        if (keep)
            assert(!inet_error(socket, true));
        inet_dispose(socket);
        if (keep)
            assert(!ipv4_address_remove(1, survivor, 0xffffff00));
        ipv4_shutdown();
    }
    puts("IPV4_FINITE_OUTPUT_PASS raw udp original_bytes checksums arp expiry fresh_source "
         "last_address");
}
