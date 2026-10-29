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
    for (uint8_t protocol : {44, 50, 51}) {
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
    // Actual extension chains are reconstructed independently from all emitted
    // fragment bytes, including the repeated prefix and first-fragment boundary.
    unsigned extension_cases = 0;
    for (unsigned mask = 0; mask < 8; mask++) {
        size_t hop = mask & 1 ? 8 : 0, before_routing = mask & 2 ? 8 : 0;
        size_t routing = mask & 2 ? 24 : 0, destination = mask & 4 ? 16 : 0;
        size_t unfragmentable = hop + before_routing + routing;
        auto plain = datagram(4096);
        std::vector<uint8_t> packet(plain.size() + unfragmentable + destination);
        std::copy_n(plain.begin(), header_size, packet.begin());
        size_t at = header_size, previous = 6;
        auto append = [&](uint8_t protocol, size_t length) {
            packet[previous] = protocol;
            packet[at + 1] = length / 8 - 1;
            previous = at;
            at += length;
        };
        if (hop)
            append(0, hop);
        if (before_routing)
            append(60, before_routing);
        if (routing) {
            append(43, routing);
            packet[at - routing + 2] = 2;
        }
        if (destination)
            append(60, destination);
        packet[previous] = 17;
        std::copy(plain.begin() + header_size, plain.end(), packet.begin() + at);
        packet[4] = (packet.size() - header_size) >> 8;
        packet[5] = packet.size() - header_size;
        const auto original = packet;
        for (auto layout : {FragmentLayout::protocol, FragmentLayout::linux_socket})
            for (uint32_t mtu : {1280u, 1500u, 65536u}) {
                std::vector<uint8_t> restored;
                size_t offset = 0;
                for (;;) {
                    auto part = fragment_packet(packet.data(), packet.size(), mtu, offset,
                                                0x11223344, output.data(), output.size(), layout);
                    assert(!part.error && packet == original && part.length <= mtu);
                    if (packet.size() <= mtu) {
                        assert(part.complete && part.length == packet.size() &&
                               std::equal(packet.begin(), packet.end(), output.begin()));
                        break;
                    }
                    const size_t prefix =
                        header_size + unfragmentable +
                        (layout == FragmentLayout::linux_socket && !routing ? destination : 0);
                    auto decoded = decode(output.data(), part.length);
                    assert(decoded.input == Input::fragment &&
                           decoded.fragment.header_offset == prefix &&
                           decoded.fragment.offset == offset &&
                           decoded.fragment.identification == 0x11223344 &&
                           decoded.fragment.more == !part.complete);
                    assert(
                        output[prefix] ==
                        (destination && (layout == FragmentLayout::protocol || routing) ? 60 : 17));
                    for (size_t n = 0; n < prefix; n++)
                        if (n != 4 && n != 5 && n != decoded.fragment.previous_header_offset)
                            assert(output[n] == packet[n]);
                    restored.insert(restored.end(), output.begin() + prefix + 8,
                                    output.begin() + part.length);
                    offset += part.consumed;
                    if (part.complete) {
                        assert(
                            std::equal(restored.begin(), restored.end(), packet.begin() + prefix));
                        break;
                    }
                }
                extension_cases++;
            }
    }
    // A fragment cannot omit part of an extension/UDP header chain, and failed
    // admission must not leave a partial output prefix visible.
    source = datagram(4000);
    source[6] = 60;
    source[40] = 17;
    source[41] = 200;
    std::fill(output.begin(), output.end(), 0xa5);
    assert(fragment_packet(source.data(), source.size(), 1280, 0, 7, output.data(), output.size())
               .error == -90);
    assert(std::all_of(output.begin(), output.end(), [](auto value) { return value == 0xa5; }));
    source[6] = 0;
    source[40] = 17;
    assert(fragment_packet(source.data(), source.size(), 1280, 0, 7, output.data(), output.size())
               .error == -90);
    source[41] = 255;
    assert(fragment_packet(source.data(), 100, 1500, 0, 7, output.data(), output.size()).error ==
           -22);
    std::printf(
        "IPv6 extension fragmentation: %u chain/MTU cases and header-boundary rejections passed\n",
        extension_cases);
    std::printf("IPv6 source fragmentation: %u datagrams, %u pieces, MTU transitions and negative "
                "bounds passed\n",
                cases, pieces);
}
