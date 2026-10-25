// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/wire.hpp"
#include "net/tcp/wire.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ax;
using namespace ax::tcp;
static constexpr ip6::Address source{
    {32, 1, 13, 184, 18, 52, 86, 120, 154, 188, 222, 240, 1, 2, 3, 4}};
static constexpr ip6::Address destination{
    {32, 1, 13, 184, 255, 255, 238, 238, 221, 221, 204, 204, 187, 170, 153, 136}};

static void fixture(const char* hex, uint8_t* bytes) {
    for (size_t at = 0; hex[at * 2]; at++) {
        unsigned value;
        assert(std::sscanf(hex + at * 2, "%2x", &value) == 1);
        bytes[at] = value;
    }
}

// These fixed packets were constructed independently from the RFC pseudo-header.
static void fixed_packets() {
    uint8_t expected[128], bytes[128];
    fixture("c00001bbfffffff0000004d26002100091f90000020404c4", expected);
    Segment value{};
    value.source = 49152;
    value.destination = 443;
    value.sequence = 0xfffffff0;
    value.acknowledgment = 1234;
    value.window = 4096;
    value.flags = syn;
    value.maximum_segment = 1220;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 24);
    assert(!std::memcmp(bytes, expected, 24));
    Segment decoded{};
    assert(decode(source, destination, expected, 24, decoded));
    assert(decoded.source == 49152 && decoded.destination == 443);
    assert(decoded.sequence == 0xfffffff0 && decoded.acknowledgment == 1234);
    assert(decoded.flags == syn && decoded.maximum_segment == 1220 && decoded.length == 0);

    fixture("c00001bbfffffff0000004d25018100064d8000068656c6c6f", expected);
    value.flags = psh | ack;
    value.maximum_segment = 0;
    value.payload = reinterpret_cast<const uint8_t*>("hello");
    value.length = 5;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
    assert(decode(source, destination, expected, 25, decoded));
    assert(decoded.length == 5 && !std::memcmp(decoded.payload, "hello", 5));
    // Both supported overlapping copy directions must retain actual wire bytes.
    std::memcpy(bytes, "hello", 5);
    value.payload = bytes;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
    value.payload = bytes + 20;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
}

// The independent repair keeps malformed-header tests past checksum validation.
static void repair(uint8_t* bytes, size_t count) {
    bytes[16] = bytes[17] = 0;
    uint64_t sum = count + 6;
    for (size_t at = 0; at < 16; at += 2) {
        sum += unsigned(source.bytes[at]) * 256 + source.bytes[at + 1];
        sum += unsigned(destination.bytes[at]) * 256 + destination.bytes[at + 1];
    }
    for (size_t at = 0; at < count; at++)
        sum += uint64_t(bytes[at]) << (at % 2 ? 0 : 8);
    while (sum > 65535)
        sum = sum % 65536 + sum / 65536;
    uint16_t checked = ~sum;
    bytes[16] = checked >> 8;
    bytes[17] = checked;
}

static void rejected_inputs() {
    uint8_t bytes[64];
    fixture("c00001bbfffffff0000004d25018100064d8000068656c6c6f", bytes);
    Segment output{};
    output.sequence = 0x12345678;
    output.payload = bytes + 50;
    auto untouched = [&] { assert(output.sequence == 0x12345678 && output.payload == bytes + 50); };
    for (size_t at = 0; at < 16; at++) {
        auto changed = source;
        changed.bytes[at] ^= 1;
        assert(!decode(changed, destination, bytes, 25, output));
        untouched();
        changed = destination;
        changed.bytes[at] ^= 1;
        assert(!decode(source, changed, bytes, 25, output));
        untouched();
    }
    bytes[24] ^= 1;
    assert(!decode(source, destination, bytes, 25, output));
    untouched();
    assert(!decode(source, destination, nullptr, 25, output));
    assert(!decode(source, destination, bytes, 19, output));
    untouched();
    fixture("c00001bbfffffff0000004d25018100064d8000068656c6c6f", bytes);
    bytes[12] = 4 << 4;
    repair(bytes, 25);
    assert(!decode(source, destination, bytes, 25, output));
    untouched();
    fixture("c00001bbfffffff0000004d26002100091f90000020404c4", bytes);
    bytes[21] = 3;
    repair(bytes, 24);
    assert(!decode(source, destination, bytes, 24, output));
    untouched();
    fixture("c00001bbfffffff0000004d25018100064d8000068656c6c6f", bytes);
    bytes[12] = 15 << 4;
    repair(bytes, 25);
    assert(!decode(source, destination, bytes, 25, output));
    untouched();
}

// TCP has no UDP-style special meaning for a zero checksum field.
static void zero_checksum() {
    uint8_t expected[22], bytes[22];
    fixture("c00001bbfffffff0000004d25010100000000000a8b5", expected);
    const uint8_t payload[] = {168, 181};
    Segment value{};
    value.source = 49152;
    value.destination = 443;
    value.sequence = 0xfffffff0;
    value.acknowledgment = 1234;
    value.window = 4096;
    value.flags = ack;
    value.payload = payload;
    value.length = sizeof(payload);
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == sizeof(bytes));
    assert(!bytes[16] && !bytes[17] && !std::memcmp(bytes, expected, sizeof(bytes)));
    Segment decoded{};
    assert(decode(source, destination, bytes, sizeof(bytes), decoded));
    bytes[21] ^= 1;
    assert(!decode(source, destination, bytes, sizeof(bytes), decoded));
}

static void upper_layer_bounds() {
    std::vector<uint8_t> payload(65516, 0x5a), bytes(65536, 0xa5);
    Segment value{};
    value.source = 7;
    value.destination = 8;
    value.flags = ack;
    value.payload = payload.data();
    value.length = 65515;
    assert(encode(source, destination, value, bytes.data(), bytes.size()) == 65535);
    Segment output{};
    assert(decode(source, destination, bytes.data(), 65535, output));
    assert(output.length == 65515 && !std::memcmp(output.payload, payload.data(), 65515));
    assert(!decode(uint32_t(1), uint32_t(2), bytes.data(), 65535, output));
    assert(!decode(source, destination, bytes.data(), 65536, output));
    std::fill(bytes.begin(), bytes.end(), 0xa5);
    value.length = 65516;
    assert(!encode(source, destination, value, bytes.data(), bytes.size()));
    assert(bytes.front() == 0xa5 && bytes.back() == 0xa5);
    value.length = 1;
    assert(!encode(source, destination, value, bytes.data(), 20));
    assert(bytes.front() == 0xa5);
    value.payload = nullptr;
    assert(!encode(source, destination, value, bytes.data(), bytes.size()));
    assert(bytes.front() == 0xa5);
}

int main() {
    fixed_packets();
    rejected_inputs();
    zero_checksum();
    upper_layer_bounds();
    std::puts("TCP_IPV6_WIRE_PASS fixed_packets address_checksum malformed_options overlap "
              "zero_checksum upper_layer_bounds");
}
