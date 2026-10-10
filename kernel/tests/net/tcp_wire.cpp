// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/wire.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace ax::tcp;
constexpr uint32_t source = 0xc0000201, destination = 0xc6336402;

static void fixture(const char* hex, uint8_t* bytes) {
    for (size_t at = 0; hex[at * 2]; at++) {
        unsigned value;
        assert(std::sscanf(hex + at * 2, "%2x", &value) == 1);
        bytes[at] = value;
    }
}

// Independent fixed fixtures use Python struct/network-order checksum construction.
static void fixed_packets() {
    uint8_t expected[128], bytes[128];
    fixture("c0000050fffffff0000004d260021000d6db0000020405b4", expected);
    Segment value{};
    value.source = 49152;
    value.destination = 80;
    value.sequence = 0xfffffff0;
    value.acknowledgment = 1234;
    value.window = 4096;
    value.flags = syn;
    value.maximum_segment = 1460;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 24);
    assert(!std::memcmp(bytes, expected, 24));
    Segment decoded;
    assert(decode(source, destination, expected, 24, decoded));
    assert(decoded.source == 49152 && decoded.destination == 80 && decoded.sequence == 0xfffffff0);
    assert(decoded.acknowledgment == 1234 && decoded.flags == syn && decoded.window == 4096);
    assert(decoded.maximum_segment == 1460 && !decoded.length && sequence_length(decoded) == 1);
    fixture("c0000050fffffff0000004d250181000aaaa000068656c6c6f", expected);
    value.maximum_segment = 0;
    value.flags = ack | psh;
    value.payload = reinterpret_cast<const uint8_t*>("hello");
    value.length = 5;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
    assert(decode(source, destination, expected, 25, decoded));
    assert(decoded.length == 5 && !std::memcmp(decoded.payload, "hello", 5));
    assert(sequence_length(decoded) == 5);
    for (size_t bit = 0; bit < 25 * 8; bit++) {
        std::memcpy(bytes, expected, 25);
        bytes[bit / 8] ^= 1u << (bit % 8);
        decoded.sequence = 0x12345678;
        assert(!decode(source, destination, bytes, 25, decoded));
        assert(decoded.sequence == 0x12345678);
    }
    assert(!decode(source ^ 1, destination, expected, 25, decoded));
    assert(!decode(source, destination ^ 1, expected, 25, decoded));
    std::memcpy(bytes, "hello", 5);
    value.payload = bytes;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
    value.payload = bytes + 20;
    assert(encode(source, destination, value, bytes, sizeof(bytes)) == 25);
    assert(!std::memcmp(bytes, expected, 25));
    value.flags |= syn | fin;
    assert(sequence_length(value) == 7);
}

static void repair(uint8_t* bytes, size_t count) {
    bytes[16] = bytes[17] = 0;
    uint8_t pseudo[] = {192, 0, 2, 1, 198, 51, 100, 2, 0, 6, uint8_t(count >> 8), uint8_t(count)};
    uint64_t sum = 0;
    for (size_t at = 0; at < sizeof(pseudo); at += 2)
        sum += unsigned(pseudo[at]) * 256 + pseudo[at + 1];
    for (size_t at = 0; at < count; at++)
        sum += uint64_t(bytes[at]) << ((at % 2) ? 0 : 8);
    while (sum > 65535)
        sum = (sum % 65536) + sum / 65536;
    uint16_t checked = ~sum;
    bytes[16] = checked >> 8;
    bytes[17] = checked;
}

static bool options(const uint8_t* option, size_t count, Segment& decoded, uint8_t flags = syn) {
    uint8_t bytes[64]{};
    assert(count <= 40 && count % 4 == 0);
    bytes[12] = (20 + count) / 4 << 4;
    bytes[13] = flags;
    std::memcpy(bytes + 20, option, count);
    repair(bytes, count + 20);
    return decode(source, destination, bytes, count + 20, decoded);
}

static void malformed_options() {
    Segment value{};
    const uint8_t combined[] = {2, 4, 5, 180, 1, 3, 3, 255, 201, 4, 99, 77, 0, 255, 255, 255};
    assert(options(combined, sizeof(combined), value));
    assert(value.maximum_segment == 1460 && value.has_window_scale && value.window_scale == 14);
    assert(options(combined, sizeof(combined), value, ack));
    assert(!value.maximum_segment && !value.has_window_scale);
    const uint8_t bad[][4] = {{2, 1, 0, 0}, {2, 3, 0, 0},   {2, 5, 0, 0},
                              {3, 4, 0, 0}, {4, 3, 0, 0},   {5, 2, 0, 0},
                              {8, 3, 0, 0}, {1, 1, 1, 222}, {222, 0, 0, 0}};
    for (const auto& option : bad) {
        value.sequence = 42;
        assert(!options(option, sizeof(option), value));
        assert(value.sequence == 42);
    }
    uint8_t bytes[20]{};
    for (unsigned offset = 0; offset <= 15; offset++) {
        bytes[12] = offset << 4;
        repair(bytes, sizeof(bytes));
        if (offset != 5)
            assert(!decode(source, destination, bytes, sizeof(bytes), value));
    }
    assert(!decode(source, destination, nullptr, 20, value));
    assert(!decode(source, destination, bytes, 19, value));
    assert(!decode(source, destination, bytes, maximum_segment_size + 1, value));
    std::memset(bytes, 0xa5, sizeof(bytes));
    Segment output{};
    output.flags = syn;
    output.maximum_segment = 1460;
    assert(!encode(source, destination, output, bytes, sizeof(bytes)));
    for (auto byte : bytes)
        assert(byte == 0xa5);
    output.maximum_segment = 0;
    output.has_window_scale = true;
    assert(!encode(source, destination, output, bytes, sizeof(bytes)));
}

static void sequence_checks() {
    assert(before(0xfffffffe, 2) && !before(2, 0xfffffffe) && !before(123, 123));
    assert(acceptable(100, 0, 100, 0) && !acceptable(100, 1, 100, 0));
    assert(!acceptable(99, 0, 100, 0) && !acceptable(101, 0, 100, 0));
    assert(acceptable(100, 0, 100, 4) && acceptable(103, 0, 100, 4));
    assert(!acceptable(104, 0, 100, 4) && !acceptable(99, 0, 100, 4));
    assert(acceptable(98, 4, 100, 4) && acceptable(102, 7, 100, 4));
    assert(!acceptable(90, 20, 100, 4) && !acceptable(99, 1, 100, 4));
    assert(acceptable(0, 1, 0xfffffffe, 4) && !acceptable(2, 1, 0xfffffffe, 4));
    assert(acceptable(0xfffffffc, 4, 0xfffffffe, 4));
    assert(reset(100, 100, 4) == Reset::accept && reset(100, 100, 0) == Reset::accept);
    assert(reset(103, 100, 4) == Reset::challenge && reset(104, 100, 4) == Reset::ignore);
    assert(reset(99, 100, 4) == Reset::ignore && reset(0, 0xfffffffe, 4) == Reset::challenge);
}

static void mutations() {
    uint32_t seed = 0x9f44;
    uint8_t bytes[256]{};
    for (unsigned trial = 0; trial < 50000; trial++) {
        size_t count = trial % sizeof(bytes);
        for (size_t at = 0; at < count; at++) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            bytes[at] = seed;
        }
        if (count >= 20)
            repair(bytes, count);
        Segment value{};
        if (decode(source, destination, bytes, count, value)) {
            assert(value.payload >= bytes + 20 && value.payload <= bytes + count);
            assert(value.length == size_t(bytes + count - value.payload));
            assert(value.window_scale <= 14);
        }
    }
}

int main() {
    fixed_packets();
    malformed_options();
    sequence_checks();
    mutations();
    std::puts("TCP_WIRE_PASS fixed_packets malformed_options sequence_windows reset_filter "
              "mutations=50000");
}
