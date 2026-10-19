// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/udp.hpp"
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace ax {
uint64_t ticks = 100;

void* alloc(size_t n) {
    return std::malloc(n);
}

void release(void* p) {
    std::free(p);
}

void log(const char*, ...) {
}

bool inet_stream(InetSocket* socket) {
    assert(socket && socket->type != 1);
    return false;
}

int tcp_error(InetSocket*, bool) {
    assert(false);
    return 0;
}

int64_t tcp_write(InetSocket*, const void*, size_t) {
    assert(false);
    return -5;
}

bool tcp_port_busy(uint32_t, uint16_t, unsigned, bool) {
    return false;
}

void tcp_failed(InetSocket*, int) {
    assert(false);
}

void tcp_poll() {
}

void tcp_receive(unsigned, uint32_t, uint32_t, const void*, size_t) {
    assert(false);
}

void tcp_icmp_error(unsigned, const uint8_t*, size_t) {
    assert(false);
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}
} // namespace ax

using namespace ax;
static std::vector<std::vector<uint8_t>> frames;

static void poll(NetAdapter&) {
}

static int send(NetAdapter&, const void* bytes, size_t length) {
    auto data = static_cast<const uint8_t*>(bytes);
    frames.emplace_back(data, data + length);
    return 0;
}

int main() {
    NetAdapter adapters[2];
    for (unsigned n = 0; n < 2; n++) {
        auto& device = adapters[n];
        device.info.mac[0] = 2;
        device.info.mac[5] = n + 1;
        device.info.live = device.info.administrative = device.info.carrier = true;
        device.poll = device.stop = poll;
        device.send = send;
        assert(net_register(device) == n + 1);
    }
    constexpr uint32_t peer = 0xc613000a;
    auto socket = inet_allocate(2);
    assert(socket);
    socket->index = 1;
    socket->peer = peer;
    socket->local_port = 49200;
    socket->peer_port = __builtin_bswap16(uint16_t(48010));
    socket->mtu_policy = 2;
    assert(ipv4_destination(socket->destination, 0, peer, 1) == 0);
    socket->local = socket->destination.path.source;
    assert(socket->local == 0);
    auto raw = inet_allocate(3);
    assert(raw);
    raw->index = 1;
    raw->peer = peer + 1;
    raw->mtu_policy = 2;
    assert(ipv4_destination(raw->destination, 0, raw->peer, 1) == 0);
    auto target = inet_peer(socket);
    uint8_t payload[1100]{};
    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == 1 && ip4::get16(frames[0].data() + 12) == 0x0806);
    auto reply = frames[0];
    const uint8_t hardware[6] = {2, 0x55, 0x4e, 0x43, 0, 1};
    memcpy(reply.data(), adapters[0].info.mac, 6);
    memcpy(reply.data() + 6, hardware, 6);
    ip4::put16(reply.data() + 20, 2);
    memcpy(reply.data() + 22, hardware, 6);
    ip4::put32(reply.data() + 28, peer);
    memcpy(reply.data() + 32, adapters[0].info.mac, 6);
    ip4::put32(reply.data() + 38, 0);
    ipv4_receive(adapters[0].info, reply.data(), reply.size());
    ipv4_poll();
    assert(frames.size() == 2 && ip4::get32(frames.back().data() + 26) == 0);
    assert(ipv4_configure(2, {0x0a180102, 0xffffff00, 0}) == 0);
    // A Linux 6.6 getter releases the obsolete route before this cached send.
    assert(ipv4_destination_mtu(socket->destination, true) == 1500);
    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == 3 && ip4::get16(frames.back().data() + 12) == 0x0800);
    assert(ip4::get32(frames.back().data() + 26) == 0);
    assert(inet_send(socket, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == 4 && ip4::get32(frames.back().data() + 26) == 0x0a180102);
    assert(socket->local == 0 && socket->destination.path.source == 0);
    uint8_t hint[70]{};
    memcpy(hint, adapters[0].info.mac, 6);
    memcpy(hint + 6, hardware, 6);
    ip4::put16(hint + 12, 0x0800);
    auto ip = hint + 14;
    ip[0] = 0x45;
    ip4::put16(ip + 2, 56);
    ip[8] = 51;
    ip[9] = 1;
    ip4::put32(ip + 12, peer);
    ip4::put32(ip + 16, 0x0a180102);
    auto icmp = ip + 20;
    icmp[0] = 3;
    icmp[1] = 4;
    ip4::put16(icmp + 6, 900);
    memcpy(icmp + 8, frames.back().data() + 14, 28);
    ip4::put16(icmp + 2, ip4::checksum(icmp, 36));
    ip4::put16(ip + 10, ip4::checksum(ip, 20));
    ipv4_receive(adapters[0].info, hint, sizeof(hint));
    assert(inet_error(socket, true) == 90);
    assert(socket->local == 0 && socket->destination.path.index == 1);
    assert(ipv4_destination_mtu(socket->destination, true) == 1500);

    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == 5 && ip4::get32(frames.back().data() + 26) == 0);
    auto wildcard = inet_allocate(2);
    assert(wildcard);
    wildcard->index = 1;
    wildcard->local_port = 49201;
    wildcard->mtu_policy = 2;
    assert(inet_send(wildcard, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == 6 && ip4::get32(frames.back().data() + 26) == 0x0a180102);
    assert(!wildcard->destination.path.index);
    // ARP chooses an assigned address while this connected UDP description
    // continues to use its original zero IP source.
    ipv4_shutdown();
    assert(ipv4_destination_mtu(socket->destination, true) == 1500);
    auto before = frames.size();
    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == before + 1);
    assert(ip4::get16(frames.back().data() + 12) == 0x0806);
    assert(ip4::get32(frames.back().data() + 28) == 0x0a180102);
    ipv4_receive(adapters[0].info, reply.data(), reply.size());
    ipv4_poll();
    assert(frames.size() == before + 1); // The old zero target was never solicited.
    auto assigned_reply = reply;
    ip4::put32(assigned_reply.data() + 38, 0x0a180102);
    ipv4_receive(adapters[0].info, assigned_reply.data(), assigned_reply.size());
    ipv4_poll();
    assert(frames.size() == before + 2);
    assert(ip4::get16(frames.back().data() + 12) == 0x0800);
    assert(ip4::get32(frames.back().data() + 26) == 0);

    // Without a release operation, the first send refills an obsolete route
    // using current selection. The next cached send uses the connected flow.
    assert(ipv4_configure(1, {0x0a170102, 0xffffff00, 0}) == 0);
    before = frames.size();
    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == before + 1);
    assert(ip4::get16(frames.back().data() + 12) == 0x0806);
    ip4::put32(assigned_reply.data() + 38, 0x0a170102);
    ipv4_receive(adapters[0].info, assigned_reply.data(), assigned_reply.size());
    ipv4_poll();
    assert(frames.size() == before + 2 && ip4::get16(frames.back().data() + 12) == 0x0800);
    assert(ip4::get32(frames.back().data() + 26) == 0x0a170102);
    assert(inet_send(socket, target, payload, sizeof(payload)) == sizeof(payload));
    ipv4_poll();
    assert(frames.size() == before + 3 && ip4::get32(frames.back().data() + 26) == 0);
    assert(ipv4_configure(1, {}) == 0);
    uint8_t echo[8] = {8, 0, 0xf7, 0xff, 0, 0, 0, 0};
    assert(inet_send(raw, inet_peer(raw), echo, sizeof(echo)) == sizeof(echo));
    assert(raw->destination.path.source == 0x0a180102);

    auto selected = inet_allocate(2);
    assert(selected);
    selected->index = 1;
    selected->local = 0x0a180102;
    selected->peer = peer;
    selected->local_port = 49202;
    selected->peer_port = target.port;
    selected->mtu_policy = 2;
    assert(ipv4_destination(selected->destination, selected->local, peer, 1) == 0);
    auto retained = selected->destination;
    assert(ipv4_configure(2, {}) == 0);
    auto removed = inet_send(selected, target, payload, sizeof(payload), true);
    assert(removed == -101);
    assert(selected->destination.path.source == retained.path.source);
    assert(selected->destination.path.index == retained.path.index);
    assert(selected->destination.generation == retained.generation);
    // A raw description with wildcard lookup input can refresh after the
    // previously selected wire source disappears.
    assert(ipv4_destination_mtu(raw->destination, true) == 1500);
    assert(ipv4_destination_mtu(raw->destination, true) == 1500);
    ipv4_shutdown();
    std::puts("IPV4_SOCKET_OUTPUT_PASS retained-zero named-selection wildcard-selection "
              "ICMP-refresh ARP-ownership removed-source");
}
