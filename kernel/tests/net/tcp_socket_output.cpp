// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/tcp/socket.hpp"
#include "net/tcp/connection.hpp"
#include "net/ipv6/configuration.hpp"
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace ax {
uint64_t ticks = 100;

uint64_t clock_realtime_ticks() {
    return ticks;
}

void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* p) {
    std::free(p);
}

void log(const char*, ...) {
}

void clock_refresh(bool) {
}

int random_read(void* p, size_t n, bool) {
    memset(p, 0x53, n);
    return 0;
}

void packet_deliver(const NetInfo&, const void*, size_t, unsigned, const void*) {
}
} // namespace ax

using namespace ax;

struct Packet {
    unsigned index;
    std::vector<uint8_t> bytes;
};

static std::vector<Packet> frames, held;
static bool blocked[3];
static int send_error[3];

static void poll(NetAdapter&) {
}

static int output(NetAdapter& adapter, const void* bytes, size_t n) {
    auto data = static_cast<const uint8_t*>(bytes);
    if (blocked[adapter.info.index]) {
        held.push_back({adapter.info.index, {data, data + n}});
        return -11;
    }
    if (send_error[adapter.info.index])
        return send_error[adapter.info.index];
    frames.push_back({adapter.info.index, {data, data + n}});
    return 0;
}

static tcp::Segment decoded(const Packet& packet) {
    auto ip = packet.bytes.data() + 14;
    tcp::Segment result;
    assert(ip4::get16(packet.bytes.data() + 12) == 0x0800 && ip[9] == 6);
    assert(tcp::decode(ip4::get32(ip + 12), ip4::get32(ip + 16), ip + 20, ip4::get16(ip + 2) - 20,
                       result));
    return result;
}

static void answer(InetSocket* socket, tcp::Segment segment, unsigned index = 0,
                   uint8_t traffic_class = 0) {
    uint8_t bytes[1500];
    segment.source = __builtin_bswap16(socket->peer_port);
    segment.destination = socket->local_port;
    size_t n = tcp::encode(socket->peer, socket->local, segment, bytes, sizeof(bytes));
    assert(n);
    tcp_receive(index ? index : socket->destination.path.index, socket->peer, socket->local, bytes,
                n, nullptr, traffic_class);
}

static void resolve(NetAdapter& adapter, InetSocket* socket) {
    auto request = frames.back().bytes;
    assert(frames.back().index == adapter.info.index && ip4::get16(request.data() + 12) == 0x0806);
    const uint8_t hardware[6] = {2, 0x41, 0x58, 0x54, 0x43, uint8_t(adapter.info.index)};
    memcpy(request.data(), adapter.info.mac, 6);
    memcpy(request.data() + 6, hardware, 6);
    ip4::put16(request.data() + 20, 2);
    memcpy(request.data() + 22, hardware, 6);
    ip4::put32(request.data() + 28, socket->peer);
    memcpy(request.data() + 32, adapter.info.mac, 6);
    ip4::put32(request.data() + 38, socket->local);
    ipv4_receive(adapter.info, request.data(), request.size());
    ipv4_poll();
}

static InetSocket* connect(NetAdapter& adapter, uint32_t peer, unsigned binding = 0,
                           uint16_t port = 0) {
    auto socket = inet_allocate(1);
    assert(socket);
    socket->index = binding;
    socket->reuse = true;
    if (port) {
        assert(inet_bind_port(socket, 0x0a170202, port) == 0);
        socket->local = 0x0a170202;
        socket->bound = true;
    }
    InetAddress address{2, __builtin_bswap16(uint16_t(49000)), __builtin_bswap32(peer), {}};
    assert(tcp_connect(socket, address) == -115);
    ipv4_poll();
    if (ip4::get16(frames.back().bytes.data() + 12) == 0x0806)
        resolve(adapter, socket);
    auto syn = decoded(frames.back());
    assert(syn.flags & tcp::syn);
    tcp::Segment ack;
    ack.sequence = 10000;
    ack.acknowledgment = syn.sequence + 1;
    ack.flags = tcp::syn | tcp::ack;
    ack.window = 65535;
    ack.maximum_segment = 1460;
    answer(socket, ack);
    tcp_poll();
    ipv4_poll();
    assert(tcp_connect_result(socket) == 0);
    assert(socket->index == binding && socket->destination.path.index == adapter.info.index);
    return socket;
}

void tcp_ipv6_socket_tests();
void tcp_ipv6_error_tests(ax::NetAdapter&);
void tcp_ipv6_reset_tests(ax::NetAdapter (&adapters)[2]);

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
        adapter.send = output;
        assert(net_register(adapter) == n + 1);
        assert(ipv4_configure(n + 1, {0x0a170102 + (n << 8), 0xffffff00, 0}) == 0);
    }
    auto socket = connect(adapters[0], 0x0a170101);
    auto companion = connect(adapters[1], 0x0a170201);
    uint8_t payload[512];
    for (size_t n = 0; n < sizeof(payload); n++)
        payload[n] = uint8_t(n * 29);
    for (unsigned mode = 0; mode < 2; mode++) {
        Ipv4Route host{socket->peer, 0xffffffff, 0, 1};
        if (mode)
            assert(ipv4_route(host, true) == 0);
        else
            assert(ipv4_configure(1, {socket->local, 0xffffffff, 0}) == 0);
        Ipv4Path absent;
        assert(ipv4_path(socket->local, socket->peer, 0, absent) == -101);
        size_t before = frames.size();
        uint32_t sequence = socket->stream->next_send();
        assert(tcp_write(socket, payload, sizeof(payload)) == sizeof(payload));
        tcp_poll();
        ipv4_poll();
        assert(frames.size() == before &&
               "unbound TCP must not turn a learned egress into a device binding");
        assert(socket->stream->next_send() == sequence &&
               socket->stream->queued() == sizeof(payload));
        assert(tcp_so_error(socket, false) == 0);
        assert(tcp_write(companion, payload, sizeof(payload)) == sizeof(payload));
        tcp_poll();
        ipv4_poll();
        assert(frames.size() == before + 1 && frames.back().index == 2);
        auto sent = decoded(frames.back());
        assert(sent.length == sizeof(payload) && !memcmp(sent.payload, payload, sizeof(payload)));
        tcp::Segment ack;
        ack.flags = tcp::ack;
        ack.window = 65535;
        ack.sequence = companion->stream->next_receive();
        ack.acknowledgment = sent.sequence + uint32_t(sent.length);
        answer(companion, ack);
        if (mode)
            assert(ipv4_route(host, false) == 0);
        else
            assert(ipv4_configure(1, {socket->local, 0xffffff00, 0}) == 0);
        ticks += 20;
        tcp_poll();
        ipv4_poll();
        bool arp = ip4::get16(frames.back().bytes.data() + 12) == 0x0806;
        if (arp)
            resolve(adapters[0], socket);
        assert(frames.size() == before + 2 + size_t(arp) && frames.back().index == 1);
        sent = decoded(frames.back());
        assert(sent.sequence == sequence && sent.length == sizeof(payload) &&
               !memcmp(sent.payload, payload, sizeof(payload)));
        ack.sequence = socket->stream->next_receive();
        ack.acknowledgment = sent.sequence + uint32_t(sent.length);
        answer(socket, ack);
        assert(socket->stream->queued() == 0);
        if (!mode) {
            assert(ipv4_route(host, false) == 0);
            assert(ipv4_configure(1, {socket->local, 0xffffffff, 0}) == 0);
        }
    }
    Ipv4Route original{socket->peer, 0xffffffff, 0, 1};
    Ipv4Route moved{socket->peer, 0xffffffff, 0, 2};
    assert(ipv4_route(original, true) == 0);
    assert(ipv4_route(moved, false) == 0);
    assert(tcp_write(socket, payload, sizeof(payload)) == sizeof(payload));
    tcp_poll();
    ipv4_poll();
    if (ip4::get16(frames.back().bytes.data() + 12) == 0x0806)
        resolve(adapters[1], socket);
    assert(frames.back().index == 2);
    auto rerouted = decoded(frames.back());
    assert(rerouted.length == sizeof(payload));
    tcp::Segment returned;
    returned.flags = tcp::ack;
    returned.window = 65535;
    returned.sequence = socket->stream->next_receive();
    returned.acknowledgment = rerouted.sequence + uint32_t(rerouted.length);
    answer(socket, returned, 2);
    assert(socket->stream->queued() == 0 && "unbound TCP accepts the reply on its new route");
    uint8_t large[1100];
    for (size_t n = 0; n < sizeof(large); n++)
        large[n] = uint8_t(n * 13);
    assert(tcp_write(socket, large, sizeof(large)) == sizeof(large));
    tcp_poll();
    ipv4_poll();
    assert(frames.back().index == 2);
    auto quoted = decoded(frames.back());
    assert(quoted.length == sizeof(large));
    uint8_t hint[36]{};
    hint[0] = 3;
    hint[1] = 4;
    ip4::put16(hint + 6, 900);
    memcpy(hint + 8, frames.back().bytes.data() + 14, 28);
    ip4::put16(hint + 2, ip4::checksum(hint, sizeof(hint)));
    tcp_icmp_error(2, hint, sizeof(hint));
    assert(ipv4_destination_mtu(socket->destination, false) == 900);
    returned.acknowledgment = quoted.sequence + uint32_t(quoted.length);
    answer(socket, returned, 2);
    assert(socket->stream->queued() == 0);

    // Queue an owned copy on the old device, then reroute before that device fails.
    assert(ipv4_route(moved, true) == 0);
    assert(ipv4_route(original, false) == 0);
    assert(tcp_write(socket, payload, sizeof(payload)) == sizeof(payload));
    tcp_poll();
    ipv4_poll();
    if (ip4::get16(frames.back().bytes.data() + 12) == 0x0806)
        resolve(adapters[0], socket);
    auto warm = decoded(frames.back());
    assert(frames.back().index == 1 && warm.length == sizeof(payload));
    returned.acknowledgment = warm.sequence + uint32_t(warm.length);
    answer(socket, returned, 1);
    blocked[1] = true;
    auto held_sequence = socket->stream->next_send();
    size_t held_frames = frames.size(), held_before = held.size();
    assert(tcp_write(socket, payload, sizeof(payload)) == sizeof(payload));
    tcp_poll();
    ipv4_poll();
    assert(frames.size() == held_frames && held.size() > held_before && held.back().index == 1 &&
           decoded(held.back()).sequence == held_sequence &&
           decoded(held.back()).length == sizeof(payload) &&
           socket->stream->queued() == sizeof(payload));
    assert(ipv4_route(original, true) == 0);
    assert(ipv4_route(moved, false) == 0);
    adapters[0].info.live = false;
    ipv4_poll();
    assert(tcp_so_error(socket, false) == 0 && socket->stream->state() == tcp::State::established);
    assert(socket->stream->queued() == sizeof(payload));
    ticks += 200;
    tcp_poll();
    ipv4_poll();
    auto recovered = decoded(frames.back());
    assert(frames.back().index == 2 && recovered.sequence == held_sequence &&
           recovered.length == sizeof(payload) &&
           !memcmp(recovered.payload, payload, sizeof(payload)));
    returned.acknowledgment = recovered.sequence + uint32_t(recovered.length);
    answer(socket, returned, 2);
    assert(socket->stream->queued() == 0);
    blocked[1] = false;
    adapters[0].info.live = true;

    // An unbound TIME_WAIT tuple follows the current route on either ingress.
    assert(tcp_shutdown(socket, 1) == 0);
    tcp_poll();
    ipv4_poll();
    auto finish = decoded(frames.back());
    assert(frames.back().index == 2 && (finish.flags & tcp::fin));
    returned.acknowledgment = finish.sequence + 1;
    answer(socket, returned, 1);
    returned.flags = tcp::fin | tcp::ack;
    answer(socket, returned, 1);
    tcp_poll();
    ipv4_poll();
    assert(socket->stream->state() == tcp::State::time_wait);
    InetSocket tuple;
    tuple.local = socket->local;
    tuple.peer = socket->peer;
    tuple.local_port = socket->local_port;
    tuple.peer_port = socket->peer_port;
    inet_close(socket);
    tcp_poll();
    assert(!socket->used);
    size_t closed_frames = frames.size();
    answer(&tuple, returned, 1);
    tcp_poll();
    ipv4_poll();
    auto duplicate = decoded(frames.back());
    assert(frames.size() == closed_frames + 1 && frames.back().index == 2 &&
           duplicate.flags == tcp::ack && duplicate.acknowledgment == returned.sequence + 1);
    auto overlapping = inet_allocate(1);
    assert(overlapping);
    overlapping->index = 2;
    overlapping->reuse = true;
    assert(inet_bind_port(overlapping, tuple.local, tuple.local_port) == 0);
    overlapping->local = tuple.local;
    overlapping->bound = true;
    InetAddress same{2, tuple.peer_port, __builtin_bswap32(tuple.peer), {}};
    assert(tcp_connect(overlapping, same) == -99);
    inet_close(overlapping);

    // Distinct explicit device bindings own separate live tuple domains.
    auto first = connect(adapters[0], 0x0a170203, 1, 48088);
    auto second = connect(adapters[1], 0x0a170203, 2, 48088);
    assert(first->local == second->local && first->local_port == second->local_port);
    auto wildcard = inet_allocate(1);
    assert(wildcard);
    wildcard->reuse = true;
    assert(inet_bind_port(wildcard, first->local, first->local_port) == 0);
    wildcard->local = first->local;
    wildcard->bound = true;
    InetAddress occupied{2, first->peer_port, __builtin_bswap32(first->peer), {}};
    assert(tcp_connect(wildcard, occupied) == -99);
    inet_close(wildcard);
    assert(tcp_connect(first, {}) == 0);
    inet_close(first);

    // A closed port routes its reset independently of the incoming interface.
    InetSocket absent;
    absent.local = tuple.local;
    absent.peer = tuple.peer;
    absent.local_port = 48100;
    absent.peer_port = tuple.peer_port;
    tcp::Segment opening;
    opening.flags = tcp::syn;
    opening.sequence = 60000;
    opening.window = 65535;
    for (uint8_t ecn = 0; ecn < 4; ecn++) {
        answer(&absent, opening, 1, 0x28 | ecn);
        ipv4_poll();
        auto reset = decoded(frames.back());
        assert(frames.back().index == 2 && reset.flags == (tcp::rst | tcp::ack) &&
               reset.acknowledgment == 60001 && frames.back().bytes[15] == 0x28);
    }

    // Keep the existing fatal failure when no alternative route exists or binding forbids it.
    blocked[2] = true;
    assert(tcp_write(companion, payload, sizeof(payload)) == sizeof(payload));
    assert(tcp_write(second, payload, sizeof(payload)) == sizeof(payload));
    tcp_poll();
    ipv4_poll();
    bool companion_copy = false, bound_copy = false;
    for (const auto& copy : held)
        if (copy.index == 2) {
            auto segment = decoded(copy);
            companion_copy |=
                segment.source == companion->local_port && segment.length == sizeof(payload);
            bound_copy |= segment.source == second->local_port && segment.length == sizeof(payload);
        }
    assert(companion_copy && bound_copy);
    assert(ipv4_route({second->peer, 0xffffffff, 0, 1}, false) == 0);
    adapters[1].info.live = false;
    ipv4_poll();
    assert(tcp_so_error(companion, false) == 5 && tcp_so_error(second, false) == 5);
    assert(companion->stream->state() == tcp::State::closed &&
           second->stream->state() == tcp::State::closed);
    blocked[2] = false;
    adapters[1].info.live = true;
    assert(tcp_connect(second, {}) == 0);
    inet_close(second);
    assert(tcp_connect(companion, {}) == 0);
    inet_close(companion);
    // A healthy bound device can reject an owned copy without disappearing.
    auto rejected = connect(adapters[1], 0x0a17020b, 2);
    blocked[2] = true;
    assert(tcp_write(rejected, payload, sizeof(payload)) == sizeof(payload));
    tcp_poll();
    ipv4_poll();
    assert(held.back().index == 2 && decoded(held.back()).length == sizeof(payload));
    assert(ipv4_route({rejected->peer, 0xffffffff, 0, 1}, false) == 0);
    Ipv4Path alternative;
    assert(ipv4_path(rejected->local, rejected->peer, 0, alternative) == 0 &&
           alternative.index == 1);
    assert(adapters[0].info.live && adapters[1].info.live);
    blocked[2] = false;
    send_error[2] = -5;
    ipv4_poll();
    assert(tcp_so_error(rejected, false) == 5 && rejected->stream->state() == tcp::State::closed);
    send_error[2] = 0;
    assert(tcp_connect(rejected, {}) == 0);
    inet_close(rejected);
    tcp_ipv6_socket_tests();
    tcp_ipv6_error_tests(adapters[0]);
    tcp_ipv6_reset_tests(adapters);
    puts("TCP_SOCKET_ROUTE_OUTPUT_PASS connected host companion exact_retry reroute pmtu "
         "failed_copy time_wait tuple_binding reset fatal_failure driver_error");
}
