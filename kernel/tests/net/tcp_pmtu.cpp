// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/icmp.hpp"
#include "net/tcp/connection.hpp"
#include "net/ipv4_wire.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <utility>
#include <vector>

namespace {
using Quote = std::array<uint8_t, 36>;
// Minimum quote retained from an independently captured Linux PMTU exchange.
constexpr Quote captured = {0x03, 0x04, 0xd9, 0x51, 0x00, 0x00, 0x02, 0x40, 0x45, 0x00, 0x05, 0xdc,
                            0x6e, 0x95, 0x40, 0x00, 0x40, 0x06, 0xb0, 0x56, 0x0a, 0x17, 0x01, 0x02,
                            0x0a, 0x17, 0x01, 0x01, 0xe3, 0x13, 0xab, 0xe0, 0xb7, 0xe2, 0xda, 0x92};

void seal(Quote& value, bool inner = false) {
    if (inner) {
        ax::ip4::put16(value.data() + 18, 0);
        ax::ip4::put16(value.data() + 18, ax::ip4::checksum(value.data() + 8, 20));
    }
    ax::ip4::put16(value.data() + 2, 0);
    ax::ip4::put16(value.data() + 2, ax::ip4::checksum(value.data(), value.size()));
}

bool expect(const char* name, const Quote& bytes, bool wanted, int error = 0,
            size_t size = captured.size()) {
    ax::tcp::IcmpError value;
    bool decoded = ax::tcp::decode_icmp_error(bytes.data(), size, value);
    bool owned = value.local == 0x0a170102 && value.peer == 0x0a170101 && value.source == 58131 &&
                 value.destination == 44000 && value.sequence == 3085097618u;
    bool passed = decoded == wanted && (!wanted || (owned && value.error == error));
    if (!passed)
        std::printf("TCP_PMTU_QUOTE_FAIL name=%s decoded=%d error=%d\n", name, decoded,
                    value.error);
    return passed;
}

namespace tcp = ax::tcp;

struct Packet {
    uint32_t sequence;
    uint16_t flags;
    std::vector<uint8_t> bytes;
};

Packet take(tcp::Connection& connection, uint64_t now) {
    tcp::Segment segment;
    assert(connection.next(now, segment));
    Packet result{segment.sequence, segment.flags, {}};
    if (segment.length)
        result.bytes.assign(segment.payload, segment.payload + segment.length);
    connection.emitted(now);
    return result;
}

void acknowledge(tcp::Connection& connection, uint32_t sequence, uint64_t now,
                 uint16_t window = 32768) {
    tcp::Segment response{};
    response.sequence = connection.next_receive();
    response.acknowledgment = sequence;
    response.window = window;
    response.flags = tcp::ack;
    connection.input(response, now);
}

uint32_t establish(tcp::Connection& connection, uint16_t fresh = 536, uint16_t limit = 1460) {
    assert(connection.segment_size() == fresh);
    connection.active(UINT32_MAX - 2048, 0, limit);
    assert(connection.segment_size() == limit);
    auto syn = take(connection, 0);
    assert(syn.flags == tcp::syn);
    tcp::Segment response{};
    response.sequence = UINT32_MAX - 200;
    response.acknowledgment = syn.sequence + 1;
    response.maximum_segment = 1460;
    response.window = 32768;
    response.flags = tcp::syn | tcp::ack;
    connection.input(response, 10);
    assert(connection.state() == tcp::State::established);
    assert(connection.segment_size() == limit);
    auto ack = take(connection, 10);
    assert(ack.flags == tcp::ack && ack.bytes.empty());
    connection.nodelay(true);
    return syn.sequence + 1;
}

std::array<uint8_t, 4096> data() {
    std::array<uint8_t, 4096> result;
    for (size_t at = 0; at < result.size(); at++)
        result[at] = uint8_t((at * 29) ^ (at >> 7));
    return result;
}

uint32_t prepare(tcp::Connection& connection, bool finish = false) {
    uint32_t origin = establish(connection);
    auto bytes = data();
    assert(connection.write(bytes.data(), bytes.size(), 20) == bytes.size());
    if (finish)
        connection.close_write();
    tcp::Segment segment;
    size_t sent = 0;
    while (connection.next(20, segment)) {
        assert(segment.sequence == origin + uint32_t(sent));
        if (segment.length) {
            assert(segment.length <= 1460 && sent + segment.length <= bytes.size());
            assert(
                std::equal(segment.payload, segment.payload + segment.length, bytes.data() + sent));
            sent += segment.length;
        } else
            assert(finish && (segment.flags & tcp::fin));
        connection.emitted(20);
    }
    assert(sent == bytes.size() && connection.queued() == bytes.size());
    assert(connection.next_send() == origin + uint32_t(bytes.size()) + unsigned(finish));
    return origin;
}

void check_bytes(const Packet& packet, uint32_t origin, size_t maximum) {
    auto expected = data();
    size_t offset = uint32_t(packet.sequence - origin);
    assert(!packet.bytes.empty() && packet.bytes.size() <= maximum);
    assert(offset + packet.bytes.size() <= expected.size());
    assert(std::equal(packet.bytes.begin(), packet.bytes.end(), expected.data() + offset));
}

void repacketization() {
    tcp::Connection connection;
    uint32_t origin = prepare(connection, true);
    uint32_t end = connection.next_send();
    assert(end < origin); // Both the owned flight and its FIN cross sequence wrap.
    assert(connection.reduce_mss(origin, 536));
    assert(connection.segment_size() == 536);
    assert(connection.next_send() == end && connection.queued() == 4096);
    assert(!connection.error() && !connection.network_error());
    auto first = take(connection, 30);
    assert(first.sequence == origin && first.bytes.size() == 536);
    check_bytes(first, origin, 536);
    tcp::Segment absent;
    assert(!connection.next(31, absent));
    acknowledge(connection, origin + 536, 32);
    size_t offset = 536, packets = 0;
    bool fin = false;
    while (connection.next(33, absent)) {
        assert(++packets < 20);
        auto packet = take(connection, 33);
        assert(packet.sequence == origin + uint32_t(offset));
        if (!packet.bytes.empty()) {
            check_bytes(packet, origin, 536);
            offset += packet.bytes.size();
        } else {
            assert(!fin && offset == 4096 && (packet.flags & tcp::fin));
            fin = true;
        }
    }
    assert(offset == 4096 && fin && packets > 2);
    assert(connection.next_send() == end && connection.queued() == 4096 - 536);
    acknowledge(connection, end, 34);
    assert(!connection.queued() && connection.state() == tcp::State::fin_wait_2);
    assert(!connection.reduce_mss(origin, 256));
    tcp::Segment finish{};
    finish.sequence = connection.next_receive();
    finish.acknowledgment = end;
    finish.flags = tcp::fin | tcp::ack;
    finish.window = 32768;
    connection.input(finish, 35);
    assert(connection.state() == tcp::State::time_wait);
    assert(take(connection, 35).bytes.empty());
    assert(!connection.reduce_mss(end, 128) && !connection.next(36, absent));
}

void original_ack_remains_owned() {
    tcp::Connection connection;
    uint32_t origin = prepare(connection);
    uint32_t end = connection.next_send();
    assert(connection.reduce_mss(origin, 536));
    take(connection, 30);
    acknowledge(connection, end, 31); // An original packet can arrive before its resized copy.
    assert(!connection.queued() && connection.next_send() == end);
    assert(connection.state() == tcp::State::established && !connection.error());
    auto bytes = data();
    assert(connection.write(bytes.data(), 16, 32) == 16);
    auto next = take(connection, 33);
    assert(next.sequence == end && next.bytes.size() == 16);
    assert(std::equal(next.bytes.begin(), next.bytes.end(), bytes.begin()));
}

void hints_and_failed_enqueue() {
    tcp::Connection connection;
    uint32_t origin = prepare(connection);
    uint32_t end = connection.next_send();
    assert(!connection.reduce_mss(origin - 1, 536));
    assert(!connection.reduce_mss(end + 1, 536));
    assert(!connection.reduce_mss(origin, 0));
    assert(!connection.reduce_mss(origin, 1460));
    assert(!connection.reduce_mss(origin, 2000));
    assert(connection.reduce_mss(end,
                                 536)); // The existing Linux quoted-error upper edge is inclusive.
    tcp::Segment pending;
    assert(connection.next(30, pending) && pending.sequence == origin && pending.length == 536);
    assert(connection.reduce_mss(origin, 256));
    connection.emitted(30); // The invalidated, never-enqueued 536-byte candidate owns nothing.
    auto first = take(connection, 31);
    assert(first.sequence == origin && first.bytes.size() == 256);
    check_bytes(first, origin, 256);
    acknowledge(connection, origin + 100, 32);
    auto partial = take(connection, 33);
    assert(partial.sequence == origin + 100 && partial.bytes.size() == 256);
    check_bytes(partial, origin, 256);
    assert(!connection.reduce_mss(origin + 99, 128));
    assert(connection.reduce_mss(end, 128));
    auto smaller = take(connection, 34);
    assert(smaller.sequence == origin + 100 && smaller.bytes.size() == 128);
    check_bytes(smaller, origin, 128);
    assert(!connection.reduce_mss(end, 128) && !connection.reduce_mss(end, 256));
    assert(connection.next_send() == end && connection.queued() == 4096 - 100);
    assert(!connection.next(35, pending));
}

void clocks() {
    tcp::Connection connection;
    uint32_t origin = prepare(connection);
    assert(connection.reduce_mss(origin, 536));
    take(connection, 30);
    tcp::Segment absent;
    assert(!connection.next(1019, absent));
    auto retry = take(connection, 1020); // The original one-second RTO still expires.
    assert(retry.sequence == origin && retry.bytes.size() == 536);
    assert(connection.reduce_mss(origin, 256));
    take(connection, 1250);
    assert(!connection.next(3019, absent));
    retry = take(connection, 3020); // Resizing cannot restart the backed-off RTO.
    assert(retry.sequence == origin && retry.bytes.size() == 256);

    tcp::Connection bounded;
    origin = prepare(bounded);
    bounded.user_timeout(100);
    for (auto [now, size] : {std::pair<uint64_t, uint16_t>{30, 536}, {60, 256}, {100, 128}}) {
        assert(bounded.reduce_mss(origin, size));
        take(bounded, now);
    }
    assert(!bounded.next(119, absent));
    assert(!bounded.next(120, absent));
    assert(bounded.state() == tcp::State::closed && bounded.error() == 110);
    assert(!bounded.reduce_mss(origin, 64));
}

void windows_and_congestion() {
    tcp::Connection connection;
    uint32_t origin = prepare(connection);
    acknowledge(connection, origin, 21, 0);
    assert(connection.reduce_mss(origin, 536));
    tcp::Segment absent;
    assert(!connection.next(30, absent));
    auto probe = take(connection, 1021);
    assert(probe.sequence == origin && probe.bytes.size() == 1);
    acknowledge(connection, origin, 1022, 256);
    auto first = take(connection, 1023);
    assert(first.sequence == origin && first.bytes.size() == 256);
    acknowledge(connection, origin + 256, 1024, 256);
    auto next = take(connection, 1025);
    assert(next.sequence == origin + 256 && next.bytes.size() == 256);
    acknowledge(connection, origin + 512, 1026, 2048);
    size_t emitted = 0;
    while (connection.next(1027, absent)) {
        auto packet = take(connection, 1027);
        check_bytes(packet, origin, 536);
        assert(uint32_t(packet.sequence - origin) >= 512);
        assert(uint32_t(packet.sequence - origin) + packet.bytes.size() <= 512 + 2048);
        emitted += packet.bytes.size();
        assert(emitted <= 2048);
    }
    assert(emitted > 536);

    tcp::Congestion congestion(1460);
    auto window = congestion.window();
    congestion.segment_size(536);
    assert(congestion.window() == window);
    congestion.duplicate(4096);
    congestion.duplicate(4096);
    assert(congestion.duplicate(4096) && congestion.recovery());
    window = congestion.window();
    auto threshold = congestion.threshold();
    congestion.segment_size(256);
    assert(congestion.window() == window && congestion.threshold() == threshold &&
           congestion.recovery());
    congestion.segment_size(0);
    assert(congestion.window() == window && congestion.recovery());
    congestion.acknowledged(256);
    congestion.idle();
    assert(congestion.window() <= 4 * 256);
}

void trusted_path_changes() {
    for (auto family : {tcp::Family::ipv4, tcp::Family::ipv6}) {
        tcp::Connection before_open(family);
        before_open.active(12345, 0, 1440);
        assert(before_open.path_mss(1200));
        auto syn = take(before_open, 0);
        tcp::Segment response{};
        response.flags = tcp::syn | tcp::ack;
        response.sequence = 54321;
        response.acknowledgment = syn.sequence + 1;
        response.maximum_segment = 1440;
        response.window = 32768;
        before_open.input(response, 10);
        assert(before_open.segment_size() == 1200);
        take(before_open, 10);

        tcp::Connection unsent(family);
        uint32_t origin = establish(unsent, family == tcp::Family::ipv6 ? 1220 : 536);
        auto bytes = data();
        assert(unsent.write(bytes.data(), bytes.size(), 20) == bytes.size());
        tcp::Segment candidate;
        assert(unsent.next(20, candidate) && candidate.length == 1460);
        assert(unsent.path_mss(1220));
        assert(unsent.next_send() == origin);
        auto packet = take(unsent, 20);
        assert(packet.sequence == origin && packet.bytes.size() == 1220);
        check_bytes(packet, origin, 1220);
        assert(!unsent.path_mss(1500) && !unsent.path_mss(0));
        assert(unsent.segment_size() == 1220);

        tcp::Connection pending(family);
        origin = establish(pending, family == tcp::Family::ipv6 ? 1220 : 536);
        pending.user_timeout(250);
        assert(pending.write(bytes.data(), bytes.size(), 20) == bytes.size());
        while (pending.next(20, candidate))
            pending.emitted(20);
        assert(pending.path_mss(1220));
        // An unrelated path notification caps later packets without pretending
        // that this connection's already emitted bytes were quoted or lost.
        assert(!pending.next(21, candidate));
        assert(!pending.path_mss(1220) && !pending.path_mss(1440));
        pending.next(269, candidate);
        assert(pending.state() == tcp::State::established);
        pending.next(270, candidate);
        assert(pending.state() == tcp::State::closed && pending.error() == 110);

        tcp::Connection baseline_timer(family), changed_timer(family);
        establish(baseline_timer, family == tcp::Family::ipv6 ? 1220 : 536);
        establish(changed_timer, family == tcp::Family::ipv6 ? 1220 : 536);
        for (auto connection : {&baseline_timer, &changed_timer}) {
            assert(connection->write(bytes.data(), bytes.size(), 20) == bytes.size());
            while (connection->next(20, candidate))
                connection->emitted(20);
        }
        assert(changed_timer.path_mss(1220));
        uint64_t baseline_retry = 0, changed_retry = 0;
        for (uint64_t now = 21; now <= 5000 && (!baseline_retry || !changed_retry); now++) {
            if (!baseline_retry && baseline_timer.next(now, candidate)) {
                assert(candidate.length == 1460);
                baseline_retry = now;
            }
            if (!changed_retry && changed_timer.next(now, candidate)) {
                assert(candidate.length == 1220);
                changed_retry = now;
            }
        }
        assert(baseline_retry && baseline_retry == changed_retry);

        tcp::Connection dropped(family);
        origin = establish(dropped, family == tcp::Family::ipv6 ? 1220 : 536);
        assert(dropped.write(bytes.data(), bytes.size(), 20) == bytes.size());
        while (dropped.next(20, candidate))
            dropped.emitted(20);
        assert(dropped.path_mss(1220, true));
        packet = take(dropped, 21);
        assert(packet.sequence == origin && packet.bytes.size() == 1220);
        check_bytes(packet, origin, 1220);
    }
    puts("TCP_PATH_MSS_PASS families=2 pre_handshake prepared_copy unquoted_RTO "
         "owned_drop original_deadline no_increase");
}

void quote_policy() {
    tcp::IcmpError quote;
    assert(ax::tcp::decode_icmp_error(captured.data(), captured.size(), quote));
    assert(quote.too_big && quote.next_hop_mtu == 576 && quote.quoted_length == 1500);
    assert(ax::tcp::quoted_path_mtu(quote) == 576);
    quote.next_hop_mtu = 68;
    assert(ax::tcp::quoted_path_mtu(quote) == 68);
    quote.next_hop_mtu = 67;
    assert(!ax::tcp::quoted_path_mtu(quote));
    quote.next_hop_mtu = 1500;
    assert(!ax::tcp::quoted_path_mtu(quote));
    quote.next_hop_mtu = 0;
    unsigned steps = 0;
    while (auto next = ax::tcp::quoted_path_mtu(quote)) {
        assert(next >= 68 && next < quote.quoted_length && ++steps <= 11);
        quote.quoted_length = next;
    }
    assert(quote.quoted_length == 68);
    quote.too_big = false;
    assert(!ax::tcp::quoted_path_mtu(quote));
}
} // namespace

int main() {
    bool passed = true;
    auto ordinary = captured;
    ordinary[1] = 3;
    ordinary[6] = ordinary[7] = 0;
    seal(ordinary);
    passed &= expect("ordinary-port-unreachable", ordinary, true, 111);
    passed &= expect("fragmentation-needed-576", captured, true);
    auto legacy = captured;
    legacy[6] = legacy[7] = 0;
    seal(legacy);
    passed &= expect("fragmentation-needed-legacy-zero", legacy, true);
    auto corrupted = captured;
    corrupted[2] ^= 1;
    passed &= expect("bad-outer-checksum", corrupted, false);
    corrupted = captured;
    corrupted[18] ^= 1;
    seal(corrupted);
    passed &= expect("bad-inner-checksum", corrupted, false);
    passed &= expect("truncated-minimum-quote", captured, false, 0, 35);
    corrupted = captured;
    corrupted[17] = 17;
    seal(corrupted, true);
    passed &= expect("non-TCP-quote", corrupted, false);
    if (passed)
        std::puts("TCP_PMTU_QUOTE_PASS checks=7");
    if (passed) {
        trusted_path_changes();
        quote_policy();
        repacketization();
        original_ack_remains_owned();
        hints_and_failed_enqueue();
        clocks();
        windows_and_congestion();
        std::puts(
            "TCP_PMTU_STATE_PASS wrap FIN queues clocks windows congestion hints partial-ACK");
    }
    return passed ? 0 : 1;
}
