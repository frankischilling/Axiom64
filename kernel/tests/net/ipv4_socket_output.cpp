// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/udp.hpp"
#include "net/ipv6/configuration.hpp"
#include "../../net/ipv4/socket.hpp"
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

uint64_t clock_realtime_ticks() {
    return ticks;
}

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

int64_t tcp_write(InetSocket*, const void*, size_t, bool) {
    assert(false);
    return -5;
}

bool tcp_port_busy(const tcp::Binding&, uint16_t, bool) {
    return false;
}

bool tcp_port_busy(uint32_t, uint16_t, unsigned, bool) {
    return false;
}

void tcp_failed(InetSocket*, int, unsigned) {
    assert(false);
}

void tcp_poll() {
}

void tcp_receive(unsigned, uint32_t, uint32_t, const void*, size_t, const ip4::ReceivedOptions*,
                 uint8_t) {
    assert(false);
}

void tcp_icmp_error(unsigned, const uint8_t*, size_t) {
    assert(false);
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}
} // namespace ax

using namespace ax;
void ipv4_send_control_cases(std::vector<std::vector<uint8_t>>&);
void ipv4_raw_header_cases(NetAdapter&, std::vector<std::vector<uint8_t>>&);
void ipv4_raw_header_queue_cases(NetAdapter&, std::vector<std::vector<uint8_t>>&);
static std::vector<std::vector<uint8_t>> frames;

static void poll(NetAdapter&) {
}

static int send(NetAdapter&, const void* bytes, size_t length) {
    auto data = static_cast<const uint8_t*>(bytes);
    frames.emplace_back(data, data + length);
    return 0;
}

static void raw_protocol_delivery() {
    auto sender = inet_allocate(3);
    auto observer = inet_allocate(3);
    auto errors = inet_allocate(3);
    assert(sender && observer && errors);
    sender->local = 0x7f000002;
    sender->protocol = observer->protocol = 253;
    errors->protocol = 1;
    InetAddress target{2, 0, __builtin_bswap32(uint32_t(0x7f000001)), {}};
    const uint8_t payload[] = {1, 2, 3};
    assert(inet_send(sender, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv4_poll();
    const auto* packet = inet_front(observer);
    assert(packet && packet->length == 20 + sizeof(payload));
    assert(inet_bytes(packet)[9] == 253 &&
           !memcmp(inet_bytes(packet) + 20, payload, sizeof(payload)));
    assert(!inet_front(errors));
    inet_dispose(observer);
    ticks += 200;
    assert(inet_send(sender, target, payload, sizeof(payload), true) == sizeof(payload));
    ipv4_poll();
    ipv4_poll();
    packet = inet_front(errors);
    assert(packet && inet_bytes(packet)[20] == 3 && inet_bytes(packet)[21] == 2);
    inet_consume(errors);
    observer = inet_allocate(3);
    assert(observer);
    sender->protocol = observer->protocol = 2;
    const uint8_t malformed_igmp[8] = {0x11};
    assert(inet_send(sender, target, malformed_igmp, sizeof(malformed_igmp), true) ==
           sizeof(malformed_igmp));
    ipv4_poll();
    packet = inet_front(observer);
    assert(packet && packet->length == 28 && inet_bytes(packet)[9] == 2 &&
           !memcmp(inet_bytes(packet) + 20, malformed_igmp, sizeof(malformed_igmp)));
    assert(!inet_front(errors));
    inet_dispose(sender);
    inet_dispose(observer);
    inet_dispose(errors);
    puts("IPV4_RAW_PROTOCOL_PASS unknown_protocol suppression absent_listener "
         "igmp_before_validation");
}

static void raw_udp_delivery() {
    constexpr uint32_t local = 0x0a170102;
    assert(ipv4_configure(1, {local, 0xffffff00, 0}) == 0);
    auto sender = inet_allocate(3);
    auto first = inet_allocate(3);
    auto second = inet_allocate(3);
    auto wrong_device = inet_allocate(3);
    auto wrong_address = inet_allocate(3);
    auto wrong_peer = inet_allocate(3);
    auto icmp = inet_allocate(3);
    auto udp = inet_allocate(2);
    assert(sender && first && second && wrong_device && wrong_address && wrong_peer && icmp && udp);
    for (auto socket : {sender, first, second, wrong_device, wrong_address, wrong_peer}) {
        socket->protocol = 17;
        socket->index = 1;
    }
    wrong_device->index = 2;
    wrong_address->local = local + 1;
    wrong_peer->peer = local + 1;
    icmp->index = udp->index = 1;
    udp->local_port = 44801;
    InetAddress target{2, __builtin_bswap16(uint16_t(12345)), __builtin_bswap32(local), {}};
    uint8_t datagram[12] = {0xa0, 0x28, 0xaf, 0x01, 0, 12, 0, 0, 0x52, 0x41, 0x57, 0x17};
    auto check_raw = [&](InetSocket* socket, size_t payload) {
        auto frame = inet_front(socket);
        assert(frame && frame->length == 20 + payload);
        auto bytes = static_cast<const uint8_t*>(inet_bytes(frame));
        assert(bytes[0] == 0x45 && bytes[9] == 17 && !ip4::checksum(bytes, 20));
        assert(ip4::get32(bytes + 12) == local && ip4::get32(bytes + 16) == local);
        assert(!memcmp(bytes + 20, datagram, payload));
        assert(frame->source.port == 0);
        inet_consume(socket);
    };
    assert(inet_send(sender, target, datagram, sizeof(datagram), true) == sizeof(datagram));
    ipv4_poll();
    check_raw(first, sizeof(datagram));
    check_raw(second, sizeof(datagram));
    auto received = inet_front(udp);
    assert(received && received->length == 4 && !memcmp(inet_bytes(received), datagram + 8, 4));
    inet_consume(udp);
    assert(!inet_front(icmp) && !inet_front(wrong_device) && !inet_front(wrong_address) &&
           !inet_front(wrong_peer));

    // Raw delivery precedes UDP minimum-length and checksum validation.
    assert(inet_send(sender, target, datagram, 0, true) == 0);
    ipv4_poll();
    check_raw(first, 0);
    check_raw(second, 0);
    assert(!inet_front(udp) && !inet_front(icmp));
    datagram[7] = 1;
    assert(inet_send(sender, target, datagram, sizeof(datagram), true) == sizeof(datagram));
    ipv4_poll();
    check_raw(first, sizeof(datagram));
    check_raw(second, sizeof(datagram));
    assert(!inet_front(udp) && !inet_front(icmp));

    uint8_t quote[28]{};
    quote[9] = 17;
    ip4::put32(quote + 12, local);
    ip4::put32(quote + 16, local);
    first->peer = second->peer = icmp->peer = local;
    inet_icmp_error(1, quote, 111, 0);
    assert(inet_error(first, true) == 111 && inet_error(second, true) == 111);
    assert(inet_error(icmp, true) == 0);
    for (auto socket : {sender, first, second, wrong_device, wrong_address, wrong_peer, icmp, udp})
        inet_dispose(socket);
}

int main() {
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
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
    raw_udp_delivery();
    raw_protocol_delivery();
    ipv4_send_control_cases(frames);
    ipv4_raw_header_cases(adapters[0], frames);
    ipv4_raw_header_queue_cases(adapters[0], frames);
    ipv4_shutdown();
    std::puts("IPV4_SOCKET_OUTPUT_PASS retained-zero named-selection wildcard-selection "
              "ICMP-refresh ARP-ownership removed-source");
}
