// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/icmp.hpp"
#include "net/tcp/connection.hpp"
#include "net/ipv4_wire.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;

static std::vector<uint8_t> capture() {
    // Minimum port-unreachable quote captured from the actual failing guest SYN.
    constexpr char hex[] =
        "0303b498000000004500002c000140004006249b0a1701020a1701018000bb809a6b7277";
    std::vector<uint8_t> bytes;
    auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
    for (size_t at = 0; at + 1 < sizeof(hex); at += 2)
        bytes.push_back(uint8_t(digit(hex[at]) * 16 + digit(hex[at + 1])));
    return bytes;
}

static void checksums(std::vector<uint8_t>& bytes, bool header = true) {
    if (header) {
        bytes[18] = bytes[19] = 0;
        ip4::put16(bytes.data() + 18, ip4::checksum(bytes.data() + 8, (bytes[8] & 15) * 4));
    }
    bytes[2] = bytes[3] = 0;
    ip4::put16(bytes.data() + 2, ip4::checksum(bytes.data(), bytes.size()));
}

static void decoder() {
    auto original = capture();
    tcp::IcmpError value;
    assert(tcp::decode_icmp_error(original.data(), original.size(), value));
    assert(value.local == 0x0a170102 && value.peer == 0x0a170101 && value.source == 32768 &&
           value.destination == 48000 && value.sequence == 0x9a6b7277 && value.error == 111 &&
           !value.abort_request);
    for (size_t length = 0; length < original.size(); length++)
        assert(!tcp::decode_icmp_error(original.data(), length, value));
    assert(!tcp::decode_icmp_error(nullptr, original.size(), value));
    for (size_t at = 0; at < original.size(); at++) {
        auto corrupted = original;
        corrupted[at] ^= 1;
        assert(!tcp::decode_icmp_error(corrupted.data(), corrupted.size(), value));
    }
    constexpr std::array<int, 16> errors{101, 113, 92,  111, 0,   95,  101, 112,
                                         64,  101, 113, 101, 113, 113, 113, 113};
    for (unsigned code = 0; code < errors.size(); code++) {
        auto bytes = original;
        bytes[1] = code;
        checksums(bytes);
        bool decoded = tcp::decode_icmp_error(bytes.data(), bytes.size(), value);
        assert(decoded == bool(errors[code]));
        if (decoded)
            assert(value.error == errors[code] && value.abort_request == (code < 2));
    }
    for (auto [type, limit, error] : {std::array<int, 3>{11, 1, 113}, {12, 3, 71}}) {
        for (int code = 0; code <= limit; code++) {
            auto bytes = original;
            bytes[0] = type;
            bytes[1] = code;
            checksums(bytes);
            bool decoded = tcp::decode_icmp_error(bytes.data(), bytes.size(), value);
            assert(decoded == (code < limit));
            if (decoded)
                assert(value.error == error && value.abort_request);
        }
    }
    for (unsigned at : {8u, 10u, 14u, 17u, 20u, 24u}) {
        auto bytes = original;
        if (at == 8)
            bytes[at] = 0x44;
        else if (at == 10)
            ip4::put16(bytes.data() + at, 28);
        else if (at == 14)
            ip4::put16(bytes.data() + at, 0x2000);
        else if (at == 17)
            bytes[at] = 17;
        else
            ip4::put32(bytes.data() + at, 0xe0000001);
        checksums(bytes, at != 8);
        assert(!tcp::decode_icmp_error(bytes.data(), bytes.size(), value));
    }
    for (unsigned size = 24; size <= 60; size += 4) {
        auto bytes = original;
        bytes.insert(bytes.begin() + 28, size - 20, 0);
        bytes[8] = 0x40 | size / 4;
        ip4::put16(bytes.data() + 10, size + 24);
        checksums(bytes);
        assert(tcp::decode_icmp_error(bytes.data(), bytes.size(), value));
        assert(value.source == 32768 && value.sequence == 0x9a6b7277);
        bytes.pop_back();
        checksums(bytes);
        assert(!tcp::decode_icmp_error(bytes.data(), bytes.size(), value));
    }
    uint32_t random = 0x87654321;
    for (unsigned trial = 0; trial < 50000; trial++) {
        std::array<uint8_t, 128> bytes;
        for (auto& byte : bytes) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = random;
        }
        tcp::decode_icmp_error(bytes.data(), random % bytes.size(), value);
    }
    std::puts(
        "TCP_ICMP_DECODER_PASS capture truncation checksums codes fragments options fuzz=50000");
}

static tcp::Segment emitted(tcp::Connection& connection, uint64_t now) {
    tcp::Segment segment;
    assert(connection.next(now, segment));
    connection.emitted(now);
    return segment;
}

static void establish(tcp::Connection& active, tcp::Connection& passive, uint32_t sequence) {
    active.active(sequence, 0);
    auto syn = emitted(active, 0);
    assert(passive.passive(0xfffffff0, syn, 1));
    active.input(emitted(passive, 1), 2);
    passive.input(emitted(active, 2), 3);
    assert(active.state() == tcp::State::established && passive.state() == tcp::State::established);
}

static void state_policy() {
    for (uint32_t sequence : {uint32_t(100), UINT32_MAX}) {
        tcp::Connection active;
        active.active(sequence, 0);
        active.quoted_error(sequence, 111, false);
        assert(active.state() == tcp::State::syn_sent); // Unowned candidate is not a sent SYN.
        emitted(active, 0);
        active.quoted_error(sequence - 1, 111, false);
        active.quoted_error(sequence + 2, 111, false);
        assert(!active.error());
        active.quoted_error(sequence + 1, 111, false); // Inclusive Linux upper edge, across wrap.
        assert(active.state() == tcp::State::closed && active.error() == 111);
        active.quoted_error(sequence, 113, true);
        assert(active.error() == 111);
    }
    for (bool abort_request : {false, true}) {
        tcp::Connection passive;
        tcp::Segment syn{};
        syn.flags = tcp::syn;
        syn.sequence = 10;
        assert(passive.passive(UINT32_MAX, syn, 0));
        emitted(passive, 0);
        passive.quoted_error(0, 113, true); // Passive request owns its exact SYN-ACK ISN.
        assert(!passive.error());
        passive.quoted_error(UINT32_MAX, 113, abort_request);
        assert(passive.state() == (abort_request ? tcp::State::closed : tcp::State::syn_received));
    }
    for (bool progress : {false, true}) {
        tcp::Connection active, passive;
        establish(active, passive, UINT32_MAX - 1);
        active.user_timeout(2500);
        assert(active.write("abc", 3, 10) == 3);
        auto data = emitted(active, 10);
        active.quoted_error(data.sequence - 1, 71, true);
        active.quoted_error(data.sequence + 4, 71, true);
        active.quoted_error(data.sequence, 111, false);
        active.quoted_error(data.sequence + 3, 113, true);
        assert(active.state() == tcp::State::established && !active.error() &&
               active.queued() == 3);
        assert(active.network_error() == 113 && active.network_error() == 113);
        if (progress) {
            passive.input(data, 11);
            active.input(emitted(passive, 11), 12);
            assert(!active.queued());
            assert(active.write("new", 3, 20) == 3);
            emitted(active, 20);
        }
        tcp::Segment pending;
        active.next(progress ? 2520 : 2510, pending);
        assert(active.state() == tcp::State::closed && active.error() == (progress ? 110 : 113));
        assert(active.network_error(true) == (progress ? 0 : 113) && !active.network_error());
    }
    tcp::Connection consumed, silent;
    establish(consumed, silent, 10);
    consumed.user_timeout(2500);
    assert(consumed.write("one", 3, 10) == 3);
    auto outstanding = emitted(consumed, 10);
    consumed.quoted_error(outstanding.sequence, 111, false);
    assert(consumed.network_error(true) == 111 && !consumed.network_error() && !consumed.error());
    tcp::Segment candidate;
    consumed.next(2510, candidate);
    assert(consumed.error() == 110);
    tcp::Connection active, passive;
    establish(active, passive, 100);
    active.close_write();
    passive.input(emitted(active, 5), 6);
    active.input(emitted(passive, 6), 7);
    passive.close_write();
    active.input(emitted(passive, 8), 9);
    assert(active.state() == tcp::State::time_wait);
    active.quoted_error(active.next_send(), 111, true);
    assert(active.state() == tcp::State::time_wait && !active.error());
    std::puts("TCP_ICMP_STATE_PASS sent_ownership wrap active passive soft recovery time_wait");
}

int main() {
    decoder();
    state_policy();
}
