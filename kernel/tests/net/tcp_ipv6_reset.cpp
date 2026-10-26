// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/tcp/wire.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"
#include "net/ipv4_wire.hpp"
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

namespace {
using namespace ax;

struct Packet {
    unsigned index;
    std::vector<uint8_t> bytes;
};

std::vector<Packet> frames;

int output(NetAdapter& adapter, const void* data, size_t size) {
    auto bytes = static_cast<const uint8_t*>(data);
    frames.push_back({adapter.info.index, {bytes, bytes + size}});
    return 0;
}

void input(unsigned index, const ip6::Address& source, const ip6::Address& destination,
           uint8_t protocol, const std::vector<uint8_t>& bytes, const uint8_t* hardware,
           uint8_t hops = 64) {
    const auto info = net_info(index);
    assert(info);
    std::vector<uint8_t> frame(54 + bytes.size());
    memcpy(frame.data(), info->mac, 6);
    memcpy(frame.data() + 6, hardware, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    ip6::Header header;
    header.source = source;
    header.destination = destination;
    header.next_header = protocol;
    header.payload_length = uint16_t(bytes.size());
    header.hop_limit = hops;
    assert(ip6::encode(frame.data() + 14, 40, header));
    memcpy(frame.data() + 54, bytes.data(), bytes.size());
    ipv6_receive(*info, frame.data(), frame.size());
    ipv6_poll();
}
} // namespace

void tcp_ipv6_reset_tests(ax::NetAdapter (&adapters)[2]) {
    using namespace ax;
    auto original_first = adapters[0].send, original_second = adapters[1].send;
    adapters[0].send = adapters[1].send = output;
    ipv6_shutdown();
    assert(!ip6::configuration_write(ip6::configuration_all, ip6::ConfigurationKey::generation_mode,
                                     1));
    ip6::Address local{{0xfe, 0x80}}, remote{{0xfe, 0x80}};
    local.bytes[15] = 2;
    remote.bytes[15] = 1;
    for (unsigned index = 1; index <= 2; index++)
        assert(!ipv6_address_add({local, index, 0x82, 64}));
    for (unsigned index = 1; index <= 2; index++) {
        const uint8_t hardware[6] = {2, 0x52, 0x53, 0x54, 0x36, uint8_t(index)};
        std::vector<uint8_t> solicitation(32);
        solicitation[0] = 135;
        memcpy(solicitation.data() + 8, local.bytes, 16);
        solicitation[24] = solicitation[25] = 1;
        memcpy(solicitation.data() + 26, hardware, 6);
        ip4::put16(solicitation.data() + 2,
                   ip6::checksum(remote, local, 58, solicitation.data(), solicitation.size()));
        frames.clear();
        input(index, remote, local, 58, solicitation, hardware, 255);
        assert(frames.size() == 1 && frames.back().index == index);
        Ipv6Path path;
        assert(!ipv6_path(local, remote, index, path) && path.index == index);
        for (unsigned kind = 0; kind < 3; kind++) {
            InetSocket* listener = nullptr;
            if (kind == 2) {
                listener = inet_allocate(1);
                assert(listener);
                listener->ipv6 = listener->wire6 = listener->v6only = true;
                assert(!inet_bind_port(listener, 0, 49460));
                assert(!tcp_listen(listener, 2));
            }
            tcp::Segment request;
            request.source = 49560;
            request.destination = 49460;
            request.sequence = 0x89abc000 + index;
            request.acknowledgment = 0x12340000 + index;
            request.flags = kind == 1 ? tcp::syn : tcp::ack;
            request.window = 8192;
            std::vector<uint8_t> bytes(20);
            assert(tcp::encode(remote, local, request, bytes.data(), bytes.size()) == 20);
            frames.clear();
            input(index, remote, local, 6, bytes, hardware);
            printf("TCP6_SCOPED_RESET_OBSERVED index=%u kind=%u frames=%zu sent_index=%u\n", index,
                   kind, frames.size(), frames.empty() ? 0 : frames.back().index);
            fflush(stdout);
            assert(frames.size() == 1 && frames.back().index == index);
            const auto& frame = frames.back().bytes;
            assert(!memcmp(frame.data(), hardware, 6) &&
                   !memcmp(frame.data() + 6, net_info(index)->mac, 6));
            auto packet = ip6::decode(frame.data() + 14, frame.size() - 14);
            assert(packet.protocol == 6 && packet.header.source == local &&
                   packet.header.destination == remote);
            tcp::Segment reset;
            assert(tcp::decode(local, remote, packet.payload, packet.length, reset));
            assert(reset.source == request.destination && reset.destination == request.source &&
                   reset.flags == (kind == 1 ? tcp::rst | tcp::ack : tcp::rst) && !reset.length &&
                   !reset.window && reset.sequence == (kind == 1 ? 0 : request.acknowledgment) &&
                   reset.acknowledgment == (kind == 1 ? request.sequence + 1 : 0));
            if (listener) {
                assert(!listener->children);
                inet_close(listener);
            }
        }
    }
    ipv6_shutdown();
    adapters[0].send = original_first;
    adapters[1].send = original_second;
    puts("TCP6_SCOPED_RESET_PASS interfaces=2 closed_ack closed_syn wildcard_ack exact_wire");
}
