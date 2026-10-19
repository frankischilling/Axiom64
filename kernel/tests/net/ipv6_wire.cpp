// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/wire.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace ax::ip6;

static std::vector<uint8_t> golden() {
    // An independently checksummed ICMPv6 echo: 2001:db8::1 to 2001:db8::2,
    // traffic class a5, flow 54321, identifier 1234, sequence 1, "IPv6!".
    const char* hex = "6a554321000d3a2020010db8000000000000000000000001"
                      "20010db800000000000000000000000280003187123400014950763621";
    std::vector<uint8_t> bytes;
    for (size_t n = 0; hex[n]; n += 2) {
        auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        bytes.push_back(uint8_t(digit(hex[n]) * 16 + digit(hex[n + 1])));
    }
    return bytes;
}

static std::vector<uint8_t> packet(uint8_t protocol, std::vector<uint8_t> body,
                                   bool multicast = false) {
    auto bytes = golden();
    bytes.resize(40);
    bytes[4] = body.size() >> 8;
    bytes[5] = body.size();
    bytes[6] = protocol;
    if (multicast) {
        std::fill(bytes.begin() + 24, bytes.begin() + 40, 0);
        bytes[24] = 0xff;
        bytes[25] = 2;
        bytes[39] = 1;
    }
    bytes.insert(bytes.end(), body.begin(), body.end());
    return bytes;
}

static void fixed_and_checksum() {
    auto bytes = golden();
    auto decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::payload && decoded.protocol == 58 && decoded.size == 53);
    assert(decoded.header.traffic_class == 0xa5 && decoded.header.flow_label == 0x54321);
    assert(decoded.header.hop_limit == 32 && decoded.length == 13);
    assert(decoded.next_header_offset == 6 && decoded.payload == bytes.data() + 40);
    auto header = decoded.header;
    assert(header.source.bytes[15] == 1 && header.destination.bytes[15] == 2);
    assert(checksum(header.source, header.destination, 58, decoded.payload, 13) == 0);
    bytes[42] = bytes[43] = 0;
    assert(checksum(header.source, header.destination, 58, bytes.data() + 40, 13) == 0x3187);
    assert(checksum(header.source, header.destination, 17, bytes.data() + 40, 13) != 0x3187);
    auto other = header.destination;
    other.bytes[15] = 3;
    assert(checksum(header.source, other, 58, bytes.data() + 40, 13) != 0x3187);
    std::array<uint8_t, 48> output;
    output.fill(0xa7);
    assert(encode(output.data() + 1, 40, header));
    auto original = golden();
    assert(std::equal(output.begin() + 1, output.begin() + 41, original.begin()));
    assert(output.front() == 0xa7 && output[41] == 0xa7);
    auto saved = output;
    assert(!encode(output.data(), 39, header) && output == saved);
    header.flow_label = 0x100000;
    assert(!encode(output.data(), output.size(), header) && output == saved);
    assert(!encode(nullptr, 40, header));
    for (size_t n = 0; n < original.size(); n++)
        assert(decode(original.data(), n).input == Input::discard);
    assert(decode(nullptr, 200).input == Input::discard);
    original[0] = 0x45;
    assert(decode(original.data(), original.size()).input == Input::discard);
    auto padded = golden();
    padded.resize(128, 0xff);
    decoded = decode(padded.data(), padded.size());
    assert(decoded.input == Input::payload && decoded.size == 53 && decoded.length == 13);
}

static void extensions_and_options() {
    auto bytes = packet(0, {60, 0, 0, 1, 3, 0, 0, 0, 17, 0, 0x22, 2, 0xa7, 0xa8, 0, 0, 1, 2, 3});
    auto decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::payload && decoded.protocol == 17 && decoded.length == 3);
    assert(decoded.next_header_offset == 48 && decoded.payload == bytes.data() + 56);
    // HBH cannot follow another extension; point to its declaring Next Header.
    bytes[40] = 0;
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_code == 1 &&
           decoded.error_pointer == 40 && !decoded.payload);
    for (bool multicast : {false, true})
        for (unsigned action = 0; action < 4; action++) {
            auto option =
                packet(60, {58, 0, uint8_t(0x1e | action << 6), 0, 0, 0, 0, 0}, multicast);
            decoded = decode(option.data(), option.size());
            if (!action)
                assert(decoded.input == Input::payload && decoded.length == 0);
            else if (action == 1 || (action == 3 && multicast))
                assert(decoded.input == Input::discard && !decoded.payload);
            else
                assert(decoded.input == Input::parameter_problem && decoded.error_code == 2 &&
                       decoded.error_pointer == 42 && !decoded.payload);
        }
    auto malformed = packet(60, {58, 0, 1, 5, 0, 0, 0, 0});
    decoded = decode(malformed.data(), malformed.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_pointer == 43);
    malformed = packet(60, {58, 1, 0, 0, 0, 0, 0, 0});
    decoded = decode(malformed.data(), malformed.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_pointer == 41);
    auto padding = packet(60, {58, 0, 1, 4, 0, 0, 0, 0});
    assert(decode(padding.data(), padding.size()).input == Input::payload);
    for (unsigned n = 44; n < 48; n++) {
        padding[n] = 0xa7;
        assert(decode(padding.data(), padding.size()).input == Input::discard);
        padding[n] = 0;
    }
    // Zero padding remains valid independently of an optional receive policy
    // that limits cumulative padding to seven bytes, as Linux does by default.
    std::vector<uint8_t> longer_padding(16);
    longer_padding[0] = 58;
    longer_padding[1] = 1;
    longer_padding[2] = 1;
    longer_padding[3] = 12;
    padding = packet(60, longer_padding);
    assert(decode(padding.data(), padding.size()).input == Input::payload);
    for (size_t n = 0; n < 8; n++) {
        auto truncated = packet(60, std::vector<uint8_t>(n));
        assert(decode(truncated.data(), truncated.size()).input == Input::discard);
    }
    // No Next Header ignores remaining content. AH/ESP remain opaque, even when
    // their first octet names an ordinary transport or a malformed extension.
    for (uint8_t next : {50, 51, 59, 250}) {
        bytes = packet(next, {60, 255, 0xff});
        decoded = decode(bytes.data(), bytes.size());
        assert(decoded.input == (next == 59 ? Input::no_next_header : Input::payload));
        assert(decoded.protocol == next && decoded.next_header_offset == 6);
        assert(next == 59 ? !decoded.payload : decoded.length == 3);
    }
    // Extension order is otherwise advisory; a long finite chain must not be
    // mistaken for an inner transport because of an arbitrary walker limit.
    std::vector<uint8_t> body(8 * 32 + 1);
    for (size_t n = 0; n < 32; n++)
        body[n * 8] = n == 31 ? 58 : 60;
    body.back() = 0xa7;
    bytes = packet(60, body);
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::payload && decoded.protocol == 58 && decoded.length == 1);
    assert(decoded.next_header_offset == 40 + 31 * 8);
    for (uint8_t type : {0, 2, 253}) {
        bytes = packet(43, {58, 0, type, 0, 0, 0, 0, 0, 0xa7});
        assert(decode(bytes.data(), bytes.size()).input == Input::payload);
        bytes[43] = 1;
        decoded = decode(bytes.data(), bytes.size());
        assert(decoded.input == Input::parameter_problem && decoded.error_code == 0 &&
               decoded.error_pointer == 42);
    }
}

static void fragments_and_addresses() {
    auto bytes = packet(44, {60, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 58, 0, 0, 0, 0, 0, 0, 0, 0xa7});
    auto decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::payload && decoded.protocol == 58 && decoded.length == 1);
    assert(decoded.fragment.identification == 0x12345678 && decoded.next_header_offset == 48);
    bytes[43] = 8;
    bytes[49] = 255; // Not an extension until the non-first fragment is reassembled.
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::fragment && decoded.fragment.offset == 8);
    assert(decoded.length == 9 && decoded.protocol == 60 && decoded.next_header_offset == 40);
    bytes[43] = 1;
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_pointer == 4);
    bytes.pop_back();
    bytes[5]--;
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::fragment && decoded.fragment.more && decoded.length == 8);
    bytes[42] = bytes[43] = 0xff;
    decoded = decode(bytes.data(), bytes.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_pointer == 42);
    // A final fragment can have a different preceding-header chain from the
    // first fragment. Its own prefix cannot reduce the reconstructed limit.
    std::vector<uint8_t> final_body(8 + 8 + 15);
    final_body[0] = 44;
    final_body[8] = 58;
    final_body[10] = 0xff;
    final_body[11] = 0xf0;
    auto prefixed = packet(0, final_body);
    decoded = decode(prefixed.data(), prefixed.size());
    assert(decoded.input == Input::fragment && decoded.fragment.offset == 65520 &&
           decoded.length == 15 && decoded.next_header_offset == 48);
    prefixed[51] = 0xf8;
    decoded = decode(prefixed.data(), prefixed.size());
    assert(decoded.input == Input::parameter_problem && decoded.error_pointer == 50);
    Address zero, loop, link, other;
    loop.bytes[15] = 1;
    link.bytes[0] = 0xfe;
    link.bytes[1] = 0xbf;
    assert(zero.unspecified() && !zero.loopback() && loop.loopback() && !loop.unspecified());
    assert(link.link_local() && !link.multicast());
    other = link;
    other.bytes[1] = 0x80;
    assert(link.matches(other, 10) && !link.matches(other, 11));
    assert(link.matches(zero, 0) && !link.matches(link, 129));
    assert(link.matches(link, 128) && !link.matches(other, 128));
    link.bytes[1] = 0xc0;
    assert(!link.link_local());
    link.bytes[0] = 0xff;
    assert(link.multicast());
}

static void bounded_inputs() {
    std::mt19937 random(0x8200);
    for (unsigned trial = 0; trial < 20000; trial++) {
        std::vector<uint8_t> bytes(random() % 256);
        for (auto& byte : bytes)
            byte = random();
        if (bytes.size() >= 40) {
            bytes[0] = 0x60 | (bytes[0] & 15);
            bytes[4] = 0;
            bytes[5] = bytes.size() - 40;
        }
        auto decoded = decode(bytes.data(), bytes.size());
        if (decoded.input == Input::payload || decoded.input == Input::fragment) {
            assert(decoded.payload >= bytes.data() + 40);
            assert(decoded.payload + decoded.length <= bytes.data() + bytes.size());
        } else
            assert(!decoded.payload && !decoded.length);
        if (decoded.input == Input::parameter_problem)
            assert(decoded.error_pointer < bytes.size());
    }
}

int main() {
    fixed_and_checksum();
    extensions_and_options();
    fragments_and_addresses();
    bounded_inputs();
    std::puts("IPV6_WIRE_PASS fixed=1 checksum=1 options=4 routing=3 fragments=3 bounded=20000");
}
