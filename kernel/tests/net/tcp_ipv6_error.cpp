// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/tcp/connection.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"
#include "net/ipv4_wire.hpp"
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

namespace {
using namespace ax;
std::vector<std::vector<uint8_t>> sent, held;
bool blocked;
constexpr uint8_t peer_mac[6] = {2, 0x54, 0x43, 0x50, 0x36, 1};
ip6::Address local{{0x20, 1, 0x0d, 0xb8, 0x17, 1}};

int output(NetAdapter&, const void* data, size_t size) {
    const auto bytes = static_cast<const uint8_t*>(data);
    (blocked ? held : sent).emplace_back(bytes, bytes + size);
    return blocked ? -11 : 0;
}

void input(unsigned index, const ip6::Address& source, const ip6::Address& destination,
           uint8_t protocol, std::vector<uint8_t> bytes, uint8_t hops = 64) {
    const auto info = net_info(index);
    assert(info);
    std::vector<uint8_t> frame(14 + 40 + bytes.size());
    memcpy(frame.data(), info->mac, 6);
    memcpy(frame.data() + 6, peer_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    ip6::Header header;
    header.source = source;
    header.destination = destination;
    header.next_header = protocol;
    header.hop_limit = hops;
    header.payload_length = uint16_t(bytes.size());
    assert(ip6::encode(frame.data() + 14, 40, header));
    memcpy(frame.data() + 54, bytes.data(), bytes.size());
    ipv6_receive(*info, frame.data(), frame.size());
}

void checksum(std::vector<uint8_t>& bytes, const ip6::Address& source,
              const ip6::Address& destination) {
    bytes[2] = bytes[3] = 0;
    ip4::put16(bytes.data() + 2,
               ip6::checksum(source, destination, 58, bytes.data(), bytes.size()));
}

tcp::Segment segment(const std::vector<uint8_t>& frame) {
    auto packet = ip6::decode(frame.data() + 14, frame.size() - 14);
    assert(packet.protocol == 6);
    tcp::Segment result;
    assert(tcp::decode(packet.header.source, packet.header.destination, packet.payload,
                       packet.length, result));
    return result;
}

void answer(InetSocket* socket, uint32_t acknowledgment, uint16_t flags = tcp::ack,
            bool old_sequence = false, uint16_t maximum_segment = 1440) {
    tcp::Segment reply;
    reply.source = __builtin_bswap16(socket->peer_port);
    reply.destination = socket->local_port;
    reply.sequence = flags & tcp::syn ? 10000 : socket->stream->next_receive();
    if (old_sequence)
        reply.sequence--;
    reply.acknowledgment = acknowledgment;
    reply.flags = flags;
    reply.window = 65535;
    reply.maximum_segment = flags & tcp::syn ? maximum_segment : 0;
    std::vector<uint8_t> bytes(24);
    size_t length = tcp::encode(socket->peer6, socket->local6, reply, bytes.data(), bytes.size());
    assert(length);
    bytes.resize(length);
    input(1, socket->peer6, socket->local6, 6, bytes);
}

void resolve(const ip6::Address& remote) {
    std::vector<uint8_t> advertisement(32);
    advertisement[0] = 136;
    advertisement[4] = 0x60;
    memcpy(advertisement.data() + 8, remote.bytes, 16);
    advertisement[24] = 2;
    advertisement[25] = 1;
    memcpy(advertisement.data() + 26, peer_mac, 6);
    checksum(advertisement, remote, local);
    input(1, remote, local, 58, advertisement, 255);
    ipv6_poll();
}

InetSocket* connect(unsigned last, bool complete = true) {
    auto socket = inet_allocate(1);
    assert(socket);
    socket->ipv6 = socket->wire6 = true;
    socket->nodelay = true;
    socket->index = 1;
    auto remote = local;
    remote.bytes[15] = last;
    Inet6Address address;
    address.address = remote;
    address.port = __builtin_bswap16(uint16_t(49600 + last));
    assert(tcp6_connect(socket, address) == -115);
    ipv6_poll();
    resolve(remote);
    auto syn = segment(sent.back());
    if (!complete)
        return socket;
    assert(syn.flags == tcp::syn);
    answer(socket, syn.sequence + 1, tcp::syn | tcp::ack);
    tcp_poll();
    ipv6_poll();
    assert(!tcp_connect_result(socket) && socket->stream->segment_size() == 1440);
    return socket;
}

void retire(InetSocket* socket) {
    Inet6Address address;
    address.family = 0;
    assert(!tcp6_connect(socket, address));
    inet_close(socket);
    tcp_poll();
    ipv6_poll();
}

std::vector<uint8_t> quote(const std::vector<uint8_t>& original, uint8_t type, uint8_t code,
                           uint32_t information = 0) {
    std::vector<uint8_t> bytes(8 + 40 + 8);
    bytes[0] = type;
    bytes[1] = code;
    ip4::put32(bytes.data() + 4, information);
    memcpy(bytes.data() + 8, original.data() + 14, 48);
    return bytes;
}

void error(InetSocket* socket, std::vector<uint8_t> bytes, unsigned index = 1,
           bool valid_checksum = true) {
    checksum(bytes, socket->peer6, socket->local6);
    if (!valid_checksum)
        bytes[2] ^= 1;
    input(index, socket->peer6, socket->local6, 58, bytes);
}

void handshake_errors() {
    struct Case {
        uint8_t type, code;
        int error;
        bool passive_abort;
    };

    constexpr Case cases[] = {{1, 0, 101, false}, {1, 1, 13, true},  {1, 2, 113, false},
                              {1, 3, 113, false}, {1, 4, 111, true}, {1, 5, 13, true},
                              {1, 6, 13, true},   {1, 99, 71, true}, {3, 0, 113, false},
                              {3, 1, 113, false}, {4, 0, 71, true},  {4, 1, 71, true},
                              {4, 2, 71, true}};
    auto companion = connect(200);
    for (unsigned at = 0; at < sizeof(cases) / sizeof(*cases); at++) {
        const auto& test = cases[at];
        auto socket = connect(100 + at, false);
        auto original = sent.back();
        auto syn = segment(original);
        auto invalid = quote(original, test.type, test.code);
        ip4::put32(invalid.data() + 52, syn.sequence + 2);
        error(socket, invalid);
        assert(socket->stream->state() == tcp::State::syn_sent && !tcp_so_error(socket, false));
        error(socket, quote(original, test.type, test.code));
        assert(tcp_connect_result(socket) == -test.error);
        inet_close(socket);
        assert(companion->stream->state() == tcp::State::established &&
               !tcp_so_error(companion, false));

        auto listener = inet_allocate(1);
        assert(listener);
        listener->ipv6 = listener->wire6 = listener->v6only = true;
        listener->index = 1;
        listener->local6 = local;
        listener->bound = true;
        assert(!inet_bind_port(listener, 0, 49701));
        assert(!tcp_listen(listener, 4));
        auto remote = local;
        remote.bytes[15] = 220 + at;
        tcp::Segment opening;
        opening.source = 41000;
        opening.destination = 49701;
        opening.sequence = 123000;
        opening.flags = tcp::syn;
        opening.maximum_segment = 1440;
        opening.window = 65535;
        std::vector<uint8_t> bytes(24);
        assert(tcp::encode(remote, local, opening, bytes.data(), bytes.size()) == bytes.size());
        input(1, remote, local, 6, bytes);
        assert(listener->children == 1 && !listener->accept_count);
        tcp_poll();
        ipv6_poll();
        resolve(remote);
        original = sent.back();
        auto synack = segment(original);
        assert(synack.flags == (tcp::syn | tcp::ack));
        InetSocket* child = nullptr;
        for (auto& candidate : inet_sockets)
            if (candidate.used && candidate.listener == listener)
                child = &candidate;
        assert(child && child->stream->state() == tcp::State::syn_received);
        error(child, quote(original, test.type, test.code));
        tcp_poll();
        if (test.passive_abort)
            assert(!listener->children && !listener->accept_count);
        else {
            assert(listener->children == 1 && child->stream->state() == tcp::State::syn_received);
            opening.sequence++;
            opening.flags = tcp::ack;
            opening.maximum_segment = 0;
            opening.acknowledgment = synack.sequence + 1;
            bytes.resize(20);
            assert(tcp::encode(remote, local, opening, bytes.data(), bytes.size()) == bytes.size());
            input(1, remote, local, 6, bytes);
            assert(listener->accept_count == 1 &&
                   child->stream->state() == tcp::State::established);
        }
        inet_close(listener);
        tcp_poll();
        ipv6_poll();
        assert(companion->stream->state() == tcp::State::established &&
               !tcp_so_error(companion, false));
    }
    retire(companion);
    puts("TCP6_ICMP_HANDSHAKE_PASS active=13 passive=13 codes errors sequence listener companion");
}

void metric_ownership() {
    auto small = connect(241, false);
    auto opening = segment(sent.back());
    answer(small, opening.sequence + 1, tcp::syn | tcp::ack, false, 536);
    tcp_poll();
    ipv6_poll();
    assert(small->stream->segment_size() == 536);
    uint8_t data[200] = {};
    assert(tcp_write(small, data, sizeof(data)) == sizeof(data));
    ipv6_poll();
    auto original = sent.back();
    error(small, quote(original, 2, 0, 1280));
    Ipv6Path path;
    assert(!ipv6_path(small->local6, small->peer6, small->index, path) && path.mtu == 1500);
    assert(small->stream->segment_size() == 536);
    retire(small);

    auto idle = connect(242);
    original = sent.back();
    auto packet = segment(original);
    assert(packet.flags == tcp::ack && !packet.length && !idle->stream->queued());
    assert(!idle->stream->owns_pmtu_quote(packet.sequence));
    assert(idle->stream->owns_pmtu_quote(packet.sequence, true));
    size_t before = sent.size();
    error(idle, quote(original, 2, 0, 1280));
    assert(idle->stream->segment_size() == 1220 && !idle->stream->queued());
    assert(!ipv6_path(idle->local6, idle->peer6, idle->index, path) && path.mtu == 1280);
    tcp_poll();
    ipv6_poll();
    assert(sent.size() == before && !tcp_so_error(idle, false));
    retire(idle);

    auto pending = connect(243, false);
    original = sent.back();
    error(pending, quote(original, 2, 0, 1280));
    assert(pending->stream->state() == tcp::State::syn_sent);
    assert(!ipv6_path(pending->local6, pending->peer6, pending->index, path) && path.mtu == 1500);
    assert(pending->stream->segment_size() == 1440 && !tcp_so_error(pending, false));
    retire(pending);
    puts("TCP6_PMTU_METRICS_PASS small_peer_no_cache idle_quote_no_retry pending_SYN_ignored");
}

} // namespace

void tcp_ipv6_error_tests(ax::NetAdapter& adapter) {
    using namespace ax;
    auto previous = adapter.send;
    adapter.send = output;
    local.bytes[15] = 2;
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
    assert(!net_configure(1, true, 1500));
    assert(!ipv6_address_add({local, 1, 0x82, 64}));
    auto socket = connect(1);
    std::vector<uint8_t> payload(4096);
    for (size_t n = 0; n < payload.size(); n++)
        payload[n] = uint8_t(n * 29);
    size_t beginning = sent.size();
    uint32_t origin = socket->stream->next_send();
    assert(tcp_write(socket, payload.data(), payload.size()) == int64_t(payload.size()));
    ipv6_poll();
    assert(socket->stream->next_send() == origin + uint32_t(payload.size()));
    auto original = sent[beginning];
    assert(segment(original).length == 1440);
    auto notification = quote(original, 2, 0, 1280);
    for (unsigned mutation = 0; mutation < 9; mutation++) {
        auto changed = notification;
        if (mutation == 1)
            ip4::put32(changed.data() + 52, origin - 1);
        if (mutation == 2)
            ip4::put32(changed.data() + 52, socket->stream->next_send() + 1);
        if (mutation == 3)
            changed[16] ^= 1;
        if (mutation == 4)
            changed[32] ^= 1;
        if (mutation == 5)
            changed[48] ^= 1;
        if (mutation == 6)
            changed[50] ^= 1;
        if (mutation == 7)
            changed.resize(55);
        if (mutation == 8)
            ip4::put16(changed.data() + 12, 8);
        error(socket, changed, 1, mutation != 0);
        assert(socket->stream->segment_size() == 1440 && !tcp_so_error(socket, false));
    }
    error(socket, notification, 2);
    assert(socket->stream->segment_size() == 1440);
    auto too_small = notification;
    ip4::put32(too_small.data() + 4, 1279);
    error(socket, too_small);
    assert(socket->stream->segment_size() == 1440);

    // A delayed PTB quotes an actually emitted packet. Its RTO copy is still
    // held by the device, and must retire without aborting the stream.
    blocked = true;
    ticks += 100;
    tcp_poll();
    ipv6_poll();
    assert(!held.empty() && segment(held.back()).length == 1440);
    error(socket, notification);
    assert(socket->stream->segment_size() == 1220 && !tcp_so_error(socket, false));
    blocked = false;
    beginning = sent.size();
    tcp_poll();
    ipv6_poll();
    auto resized = segment(sent[beginning]);
    assert(resized.sequence == origin && resized.length == 1220);
    assert(!memcmp(resized.payload, payload.data(), resized.length));
    assert(socket->stream->queued() == payload.size());
    answer(socket, origin + uint32_t(payload.size()) + 1);
    assert(socket->stream->queued() == payload.size());
    answer(socket, origin + uint32_t(payload.size()), tcp::ack, true);
    assert(socket->stream->queued() == payload.size());
    answer(socket, origin + uint32_t(payload.size()));
    assert(!socket->stream->queued());
    error(socket, quote(original, 1, 4));
    // The old data is acknowledged, so its now stale error cannot reach SO_ERROR.
    assert(!tcp_so_error(socket, true));
    beginning = sent.size();
    assert(tcp_write(socket, payload.data(), 32) == 32);
    tcp_poll();
    ipv6_poll();
    error(socket, quote(sent[beginning], 1, 4));
    assert(tcp_so_error(socket, true) == 111 && !tcp_so_error(socket, true));
    assert(socket->stream->state() == tcp::State::established);
    retire(socket);

    // A physical MTU change after admission reaches the copied-output callback.
    assert(!net_configure(1, true, 1500));
    socket = connect(3);
    origin = socket->stream->next_send();
    blocked = true;
    assert(tcp_write(socket, payload.data(), 1400) == 1400);
    ipv6_poll();
    assert(segment(held.back()).length == 1400);
    assert(!net_configure(1, true, 1280));
    blocked = false;
    beginning = sent.size();
    ipv6_poll();
    assert(!tcp_so_error(socket, false));
    tcp_poll();
    ipv6_poll();
    resized = segment(sent[beginning]);
    assert(resized.sequence == origin && resized.length == 1220 &&
           !memcmp(resized.payload, payload.data(), resized.length));
    assert(socket->stream->state() == tcp::State::established);
    retire(socket);
    assert(!net_configure(1, true, 1500));
    handshake_errors();
    metric_ownership();
    ipv6_shutdown();
    tcp_poll();
    assert(!net_configure(1, true, 1500));
    adapter.send = previous;
    puts("TCP6_ICMP_OUTPUT_PASS checksum tuple sequence scope short_quote minimum_MTU "
         "owned_PTB pending_copy exact_retry stale_error soft_error device_MTU_callback");
}
