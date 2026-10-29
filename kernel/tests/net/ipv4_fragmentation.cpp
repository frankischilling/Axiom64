// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/fragmentation.hpp"
#include "net/ipv4_wire.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax::ip4;

namespace {
unsigned cases, pieces;
}

static void checksum_header(std::vector<uint8_t>& packet) {
    put16(packet.data() + 10, 0);
    put16(packet.data() + 10, checksum(packet.data(), (packet[0] & 15) * 4));
}

static std::vector<uint8_t> datagram(size_t length, bool df = false, size_t header = 20) {
    std::vector<uint8_t> bytes(header + length);
    bytes[0] = 0x40 | (header / 4);
    bytes[1] = 0xb9;
    put16(bytes.data() + 2, bytes.size());
    put16(bytes.data() + 4, 0x3456);
    put16(bytes.data() + 6, df ? 0x4000 : 0);
    bytes[8] = 51;
    bytes[9] = 17;
    put32(bytes.data() + 12, 0x0a170102);
    put32(bytes.data() + 16, 0x0a170101);
    for (size_t at = header; at < bytes.size(); at++)
        bytes[at] = uint8_t(at * 17 + 31);
    checksum_header(bytes);
    return bytes;
}

static void split(const std::vector<uint8_t>& source, size_t mtu, size_t original_offset = 0,
                  bool original_more = false) {
    auto before = source;
    size_t header = (source[0] & 15) * 4;
    std::vector<uint8_t> reconstructed(source.size() - header), output(65535, 0xa5);
    size_t offset = 0;
    do {
        auto part = fragment_packet(source.data(), source.size(), mtu, offset, output.data(),
                                    output.size());
        assert(!part.error && part.length <= mtu && part.length == header + part.consumed);
        assert(get16(output.data() + 2) == part.length && !checksum(output.data(), header));
        assert(output[0] == source[0] && output[1] == source[1] && output[8] == 51 &&
               output[9] == 17 && get16(output.data() + 4) == 0x3456);
        assert(std::equal(output.begin() + 12, output.begin() + 20, source.begin() + 12));
        uint16_t fragment = get16(output.data() + 6);
        assert(size_t(fragment & 0x1fff) * 8 == original_offset + offset);
        assert(bool(fragment & 0x2000) == (!part.complete || original_more));
        if (!part.complete)
            assert(part.consumed && part.consumed % 8 == 0);
        assert(std::equal(output.begin() + header, output.begin() + part.length,
                          source.begin() + header + offset));
        std::copy(output.begin() + header, output.begin() + part.length,
                  reconstructed.begin() + offset);
        if (original_offset + offset && source.size() > mtu && header == 32) {
            for (size_t at = 20; at < 28; at++)
                assert(output[at] == 1);
            assert(std::equal(output.begin() + 28, output.begin() + 32, source.begin() + 28));
        }
        offset += part.consumed;
        assert(source == before);
        pieces++;
        if (part.complete)
            break;
    } while (true);
    assert(std::equal(reconstructed.begin(), reconstructed.end(), source.begin() + header));
    cases++;
}

static void rejected(std::vector<uint8_t> source, size_t mtu, size_t offset, size_t capacity,
                     int error) {
    std::vector<uint8_t> output(65535, 0xa5);
    auto before = source;
    auto result =
        fragment_packet(source.data(), source.size(), mtu, offset, output.data(), capacity);
    assert(result.error == error && !result.length && !result.consumed && !result.complete);
    assert(source == before &&
           std::all_of(output.begin(), output.end(), [](auto x) { return x == 0xa5; }));
    cases++;
}

int main() {
    for (size_t mtu : {68, 69, 77, 576, 1499, 1500, 9000, 65535})
        for (size_t length : {0, 1, 7, 8, 47, 48, 49, 1479, 1480, 1481, 65515}) {
            split(datagram(length), mtu);
            if (length + 20 <= mtu)
                split(datagram(length, true), mtu);
            else
                rejected(datagram(length, true), mtu, 0, 65535, -90);
        }
    auto options = datagram(4096, false, 32);
    const uint8_t fields[] = {1, 7, 7, 4, 0, 0, 0, 0, 148, 4, 0, 0};
    std::copy(std::begin(fields), std::end(fields), options.begin() + 20);
    checksum_header(options);
    split(options, 68);
    split(options, 1500);
    auto again = datagram(640);
    put16(again.data() + 6, 8 | 0x2000);
    checksum_header(again);
    split(again, 68, 64, true);
    auto bad = datagram(64);
    rejected(bad, 67, 0, 65535, -22);
    rejected(bad, 65536, 0, 65535, -22);
    rejected(bad, 68, 1, 65535, -22);
    rejected(bad, 68, 64, 65535, -22);
    rejected(bad, 68, 0, 20, -105);
    rejected(bad, 1500, 0, 20, -105);
    bad[10] ^= 1;
    rejected(bad, 68, 0, 65535, -22);
    bad = datagram(63);
    put16(bad.data() + 6, 0x2000);
    checksum_header(bad);
    rejected(bad, 68, 0, 65535, -22);
    bad = datagram(64);
    put16(bad.data() + 6, 0x1fff);
    checksum_header(bad);
    rejected(bad, 68, 0, 65535, -22);
    bad = options;
    bad[22] = 1;
    checksum_header(bad);
    rejected(bad, 68, 0, 65535, -22);
    bad = datagram(64);
    bad[0] = 0x4f;
    checksum_header(bad);
    put16(bad.data() + 2, 59);
    checksum_header(bad);
    rejected(bad, 68, 0, 65535, -22);
    // A later MTU change must resume at the accepted cursor, never resend offset zero.
    auto changing = datagram(4096);
    std::vector<uint8_t> wire(1500);
    auto first = fragment_packet(changing.data(), changing.size(), 68, 0, wire.data(), wire.size());
    auto next = fragment_packet(changing.data(), changing.size(), 1500, first.consumed, wire.data(),
                                wire.size());
    assert(!first.error && !next.error && (get16(wire.data() + 6) & 0x1fff) == 6);
    assert(std::equal(wire.begin() + 20, wire.begin() + next.length, changing.begin() + 68));
    cases++;
    std::printf("IPV4_FRAGMENTATION_HOST_PASS cases=%u pieces=%u\n", cases, pieces);
}
