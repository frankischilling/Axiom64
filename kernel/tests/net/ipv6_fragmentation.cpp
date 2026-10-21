// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/fragmentation.hpp"
#include "net/ipv6/wire.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax::ip6;

static std::vector<uint8_t> datagram(size_t size) {
    std::vector<uint8_t> packet(header_size + size);
    Header header;
    header.source.bytes[0] = header.destination.bytes[0] = 0x20;
    header.source.bytes[15] = 2;
    header.destination.bytes[15] = 1;
    header.flow_label = 0xabcde;
    header.traffic_class = 0xb9;
    header.hop_limit = 37;
    header.next_header = 17;
    header.payload_length = size;
    assert(encode(packet.data(), packet.size(), header));
    for (size_t n = 0; n < size; n++)
        packet[header_size + n] = uint8_t(n * 13 + 7);
    return packet;
}

int main() {
    unsigned cases = 0, pieces = 0;
    for (size_t size :
         std::initializer_list<size_t>{0, 1, 1231, 1232, 1233, 1452, 1453, 65527, 65535}) {
        auto source = datagram(size), original = source;
        for (uint32_t mtu : {1280u, 1281u, 1499u, 1500u, 65536u, 70000u}) {
            std::vector<uint8_t> output(65575), restored;
            size_t offset = 0;
            while (true) {
                auto part = fragment_packet(source.data(), source.size(), mtu, offset, 0x89abcdef,
                                            output.data(), output.size());
                assert(!part.error && part.length <= mtu && source == original);
                auto decoded = decode(output.data(), part.length);
                assert(decoded.header.flow_label == 0xabcde &&
                       decoded.header.traffic_class == 0xb9 && decoded.header.hop_limit == 37 &&
                       decoded.protocol == 17 && decoded.header.source.bytes[15] == 2 &&
                       decoded.header.destination.bytes[15] == 1);
                if (source.size() > mtu || offset) {
                    assert(decoded.input == Input::fragment &&
                           decoded.fragment.identification == 0x89abcdef &&
                           decoded.fragment.offset == offset &&
                           decoded.fragment.more == !part.complete);
                    assert(output[41] == 0 && !(output[43] & 6));
                } else
                    assert(decoded.input == Input::payload);
                assert(decoded.length == part.consumed);
                restored.insert(restored.end(), decoded.payload, decoded.payload + decoded.length);
                offset += part.consumed;
                pieces++;
                if (part.complete)
                    break;
                assert(part.consumed && part.consumed % 8 == 0);
            }
            assert(std::equal(restored.begin(), restored.end(), source.begin() + header_size));
            cases++;
        }
    }
    auto source = datagram(4000);
    std::vector<uint8_t> output(5000, 0xa5);
    auto first =
        fragment_packet(source.data(), source.size(), 1500, 0, 7, output.data(), output.size());
    assert(!first.error && !first.complete);
    auto tail = fragment_packet(source.data(), source.size(), 9000, first.consumed, 7,
                                output.data(), output.size());
    assert(!tail.error && tail.complete &&
           decode(output.data(), tail.length).input == Input::fragment);
    for (size_t offset : std::initializer_list<size_t>{1, 4000, 4008, SIZE_MAX}) {
        std::fill(output.begin(), output.end(), 0xa5);
        assert(fragment_packet(source.data(), source.size(), 1500, offset, 7, output.data(),
                               output.size())
                   .error);
        assert(std::all_of(output.begin(), output.end(), [](auto b) { return b == 0xa5; }));
    }
    for (uint8_t protocol : {0, 43, 44, 50, 51, 60}) {
        source[6] = protocol;
        assert(
            fragment_packet(source.data(), source.size(), 1500, 0, 7, output.data(), output.size())
                .error == -95);
    }
    source[6] = 17;
    assert(
        fragment_packet(source.data(), source.size() - 1, 1500, 0, 7, output.data(), output.size())
            .error == -22);
    assert(fragment_packet(source.data(), source.size(), 1279, 0, 7, output.data(), output.size())
               .error == -22);
    assert(fragment_packet(source.data(), source.size(), 1500, 0, 7, output.data(), 1495).error ==
           -105);
    std::printf("IPv6 source fragmentation: %u datagrams, %u pieces, MTU transitions and negative "
                "bounds passed\n",
                cases, pieces);
}
