// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/path_mtu.hpp"
#include "net/ipv6/icmp.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ax::ip6;

static Address address(unsigned host) {
    Address value;
    value.bytes[0] = 0x20;
    value.bytes[1] = 1;
    value.bytes[14] = host >> 8;
    value.bytes[15] = host;
    return value;
}

static void retained_metrics() {
    PathMtuCache cache;
    PathKey key{address(2), address(1), address(1), 1, 17};
    assert(!cache.retain(key, 0));
    assert(cache.learn(key, 1500, 1400, 10) == 1400);
    auto first = cache.retain(key, 11), second = cache.retain(key, 12);
    assert(first && second && cache.metric(first) == 1400 && cache.metric(second) == 1400);
    PathMtuCache foreign;
    assert(foreign.learn(key, 1500, 1300, 10) == 1300);
    auto foreign_reference = foreign.retain(key, 11);
    assert(foreign_reference && !foreign.metric(first) && !cache.metric(foreign_reference));
    auto wrong_owner = first;
    foreign.release(wrong_owner);
    assert(cache.metric(first) == 1400 && foreign.metric(foreign_reference) == 1300);
    foreign.release(foreign_reference);
    assert(cache.learn(key, 1500, 1280, 1000) == 1280);
    assert(cache.metric(first) == 1280 && cache.metric(second) == 1280);
    assert(cache.lookup(key, 1500, 60010) == 1500);
    assert(!cache.active(first, key, 60010) && cache.metric(first) == 1280);
    assert(cache.learn(key, 1500, 1400, 70000) == 1400);
    auto current = cache.retain(key, 70001);
    assert(cache.active(current, key, 70002) && cache.metric(current) == 1400);
    assert(cache.metric(first) == 1280 && cache.metric(second) == 1280);
    auto stale = first;
    cache.release(first);
    auto reused = cache.retain(key, 70003);
    assert(reused && !cache.metric(stale));
    cache.release(stale);
    assert(cache.metric(reused) == 1400);
    cache.discard_route(key.route_owner);
    assert(cache.lookup(key, 1500, 70004) == 1500 && cache.metric(current) == 1400);
    cache.release(current);
    cache.release(reused);
    cache.release(second);

    // Every socket can pin a different retired metric while the full active
    // exception table continues to learn, evict, and reuse its own storage.
    PathMtuReference held[path_mtu_reference_capacity];
    for (unsigned n = 0; n < path_mtu_reference_capacity; n++) {
        key.destination = address(100 + n);
        assert(cache.learn(key, 1500, 1400, 80000 + n) == 1400);
        held[n] = cache.retain(key, 80000 + n);
        assert(held[n]);
        cache.discard_route(key.route_owner);
    }
    for (unsigned n = 0; n < path_mtu_capacity + 1; n++) {
        key.destination = address(500 + n);
        assert(cache.learn(key, 1500, 1300, 90000 + n) == 1300);
    }
    assert(!cache.retain(key, 90100));
    for (auto& reference : held) {
        assert(cache.metric(reference) == 1400);
        cache.release(reference);
        assert(!reference && !cache.metric(reference));
    }
    current = cache.retain(key, 90101);
    assert(current && cache.metric(current) == 1300);
    cache.discard_source(key.source);
    assert(cache.metric(current) == 1300 && !cache.active(current, key, 90102));
    cache.release(current);
    cache.discard();
    assert(cache.learn(key, 1500, 1280, 100000) == 1280);
}

static void cache() {
    PathMtuCache cache;
    PathKey key{address(2), address(1), address(1), 1, 17};
    assert(cache.lookup(key, 1500, 0) == 1500);
    assert(cache.learn(key, 1500, 1400, 10) == 1400);
    auto other = key;
    other.index = 2;
    assert(cache.lookup(other, 1500, 11) == 1500);
    other = key;
    other.source = address(3);
    assert(cache.lookup(other, 1500, 11) == 1500);
    other = key;
    other.next_hop = address(4);
    assert(cache.lookup(other, 1500, 11) == 1500);
    other = key;
    other.route_owner++;
    assert(cache.lookup(other, 1500, 11) == 1500);
    for (uint32_t report : {0u, 1279u, 1400u, 1500u, UINT32_MAX})
        assert(cache.learn(key, 1500, report, 1000) == 1400);
    assert(cache.lookup(key, 1500, 60009) == 1400);
    assert(cache.lookup(key, 1500, 60010) == 1500);
    assert(cache.learn(key, 1500, 1400, 70000) == 1400);
    assert(cache.learn(key, 1500, 1280, 71000) == 1280);
    // Lower feedback changes the metric, not the existing destination expiry.
    assert(cache.lookup(key, 1500, 129999) == 1280);
    assert(cache.lookup(key, 1500, 130000) == 1500);
    other = key;
    other.destination = address(5);
    assert(cache.learn(other, 1500, 1280, 71000) == 1280);
    assert(cache.lookup(other, 1500, 130000) == 1280);
    assert(cache.lookup(other, 1500, 130999) == 1280);
    assert(cache.lookup(other, 1500, 131000) == 1500);
    assert(cache.learn(key, 1500, 1400, 200000) == 1400);
    cache.update_mtu(2, 1500, 1280);
    assert(cache.lookup(key, 1500, 200001) == 1400);
    cache.update_mtu(1, 1500, 1280);
    assert(cache.lookup(key, 1280, 200002) == 1280);
    cache.update_mtu(1, 1280, 1500);
    assert(cache.lookup(key, 1500, 200003) == 1500);
    assert(cache.learn(key, 1500, 1400, 200004) == 1400);
    cache.discard_route(18);
    assert(cache.lookup(key, 1500, 200005) == 1400);
    cache.discard_route(17);
    assert(cache.lookup(key, 1500, 200006) == 1500);
    assert(cache.learn(key, 1500, 1400, 200007) == 1400);
    cache.discard_source(key.source, 2);
    assert(cache.lookup(key, 1500, 200008) == 1400);
    cache.discard_source(key.source);
    assert(cache.lookup(key, 1500, 200009) == 1500);
    for (unsigned n = 0; n < path_mtu_capacity; n++) {
        other = key;
        other.destination = address(10 + n);
        assert(cache.learn(other, 1500, 1400, 300000 + n) == 1400);
    }
    other.destination = address(10);
    assert(cache.lookup(other, 1500, 300100) == 1400);
    other.destination = address(99);
    assert(cache.learn(other, 1500, 1300, 300101) == 1300);
    other.destination = address(11);
    assert(cache.lookup(other, 1500, 300102) == 1500);
    other.destination = address(10);
    assert(cache.lookup(other, 1500, 300103) == 1400);
    cache.discard();
    assert(cache.lookup(other, 1500, 300104) == 1500);
    assert(cache.learn(key, 1500, 1280, UINT64_MAX - 100) == 1280);
    assert(cache.lookup(key, 1500, UINT64_MAX - 1) == 1280);
    assert(cache.lookup(key, 1500, UINT64_MAX) == 1500);
}

static std::vector<uint8_t> quote(uint8_t protocol = 17, size_t extensions = 0) {
    std::vector<uint8_t> bytes(56 + extensions);
    bytes[0] = 2;
    bytes[6] = 5;
    bytes[8] = 0x60;
    bytes[12] = 5;
    bytes[13] = 0x1c;
    bytes[14] = extensions ? 60 : protocol;
    auto source = address(2), destination = address(1);
    memcpy(bytes.data() + 16, source.bytes, 16);
    memcpy(bytes.data() + 32, destination.bytes, 16);
    if (extensions) {
        bytes[48] = protocol;
        bytes[49] = extensions / 8 - 1;
    }
    bytes[48 + extensions] = 0xb7;
    bytes[49 + extensions] = 0x98;
    return bytes;
}

static void quotes() {
    ErrorQuote value;
    auto bytes = quote();
    assert(error_quote(bytes.data(), bytes.size(), value));
    assert(value.type == 2 && value.error == 90 && !value.hard && value.information == 1280 &&
           value.protocol == 17 && value.transport == bytes.data() + 48 &&
           value.source == address(2) && value.destination == address(1));
    for (unsigned type = 1; type <= 4; type++)
        for (unsigned code = 0; code < 256; code++) {
            bytes[0] = type;
            bytes[1] = code;
            assert(error_quote(bytes.data(), bytes.size(), value));
            assert(value.type == type && value.code == code);
            if (type == 1 && code == 4)
                assert(value.hard && value.error == 111);
            if (type == 3)
                assert(!value.hard && value.error == 113);
            if (type == 4)
                assert(value.hard && value.error == 71);
        }
    for (auto protocol : {17, 58})
        for (size_t size : {0, 8, 16, 128}) {
            bytes = quote(protocol, size);
            assert(error_quote(bytes.data(), bytes.size(), value));
            assert(value.protocol == protocol && value.transport == bytes.data() + 48 + size);
            for (size_t length = 0; length < bytes.size(); length++) {
                value.error = 777;
                assert(!error_quote(bytes.data(), length, value));
                assert(value.error == 777);
            }
        }
    bytes = quote(17, 8);
    bytes[14] = 44;
    assert(error_quote(bytes.data(), bytes.size(), value));
    bytes[51] = 1; // A complete first fragment can quote its transport header.
    assert(error_quote(bytes.data(), bytes.size(), value));
    bytes[51] = 8;
    assert(!error_quote(bytes.data(), bytes.size(), value));
    bytes = quote();
    bytes[13] = 7;
    bytes[12] = 0;
    assert(!error_quote(bytes.data(), bytes.size(), value));
    for (unsigned protocol : {17, 58}) {
        bytes = quote(protocol, 40);
        bytes[14] = 43;
        bytes[50] = 4;
        bytes[51] = 1;
        bytes[52] = 1;
        memcpy(bytes.data() + 56, address(71).bytes, 16);
        assert(error_quote(bytes.data(), bytes.size(), value));
        assert(value.destination == address(1) &&
               value.transport_destination == address(protocol == 17 ? 71 : 1));
        bytes[52] = 3;
        assert(error_quote(bytes.data(), bytes.size(), value));
        assert(value.transport_destination == address(1));
        bytes[52] = 0;
        // Reduced SRH: one on-wire segment remains outside the stored list.
        bytes[49] = 2;
        bytes.erase(bytes.begin() + 72, bytes.begin() + 88);
        assert(error_quote(bytes.data(), bytes.size(), value));
        assert(value.transport_destination == address(protocol == 17 ? 71 : 1));
        auto tail = bytes;
        bytes = quote(protocol, 48);
        bytes[14] = 43;
        bytes[48] = 43;
        bytes[49] = 2;
        bytes[50] = 2;
        bytes[51] = 1;
        memcpy(bytes.data() + 72, tail.data() + 48, 24);
        assert(error_quote(bytes.data(), bytes.size(), value));
        assert(value.transport_destination == address(1));
    }
    uint32_t random = 0x638a21f5;
    for (unsigned n = 0; n < 20000; n++) {
        std::vector<uint8_t> damaged(n % 512);
        for (auto& byte : damaged) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = random;
        }
        if (error_quote(damaged.data(), damaged.size(), value))
            assert(value.transport >= damaged.data() + 48 &&
                   value.transport + 8 <= damaged.data() + damaged.size());
    }
}

int main() {
    cache();
    retained_metrics();
    quotes();
    puts("IPv6 path MTU cache, bounded quotes and 20000 malformed inputs passed");
}
