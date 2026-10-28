// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast.hpp"
#include "net/ipv4_wire.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ax::ip4;
constexpr uint32_t group = 0xef7f2a01, a = 0xc0000201, b = a + 1, c = a + 2, d = a + 3;

struct Record {
    unsigned type;
    std::vector<uint32_t> sources;
    bool operator==(const Record&) const = default;
};

struct Sink {
    std::vector<Record> records;
    unsigned mtu = 1500, stop_after = ~0U, attempts = 0;

    static bool emit(void* opaque, unsigned index, uint32_t destination, const uint8_t* bytes,
                     size_t length) {
        auto& sink = *static_cast<Sink*>(opaque);
        sink.attempts++;
        if (sink.records.size() == sink.stop_after)
            return false;
        assert(index == 1 && length + 24 <= sink.mtu && !checksum(bytes, length));
        if (bytes[0] != 0x22) {
            assert(length == 8 && get32(bytes + 4) == group);
            assert(destination == (bytes[0] == 0x17 ? 0xe0000002 : group));
            sink.records.push_back({bytes[0], {}});
            return true;
        }
        assert(destination == 0xe0000016 && length >= 16 && get16(bytes + 6) == 1);
        assert(get32(bytes + 12) == group && length == 16 + size_t(get16(bytes + 10)) * 4);
        Record record{bytes[8], {}};
        for (unsigned n = 0; n < get16(bytes + 10); n++)
            record.sources.push_back(get32(bytes + 16 + n * 4));
        sink.records.push_back(record);
        return true;
    }

    void expect(std::initializer_list<Record> wanted) {
        assert(records == std::vector<Record>(wanted));
        records.clear();
    }
};

static void settle(MulticastHost& host, Sink& sink, uint64_t now) {
    host.poll(now, Sink::emit, &sink);
    host.poll(now + 100, Sink::emit, &sink);
}

static void query(MulticastHost& host, uint64_t now, const std::vector<uint32_t>& sources = {}) {
    std::vector<uint8_t> bytes(12 + sources.size() * 4);
    bytes[0] = 0x11;
    bytes[1] = 10;
    put32(bytes.data() + 4, group);
    bytes[8] = 2;
    bytes[9] = 125;
    put16(bytes.data() + 10, sources.size());
    for (unsigned n = 0; n < sources.size(); n++)
        put32(bytes.data() + 12 + n * 4, sources[n]);
    put16(bytes.data() + 2, checksum(bytes.data(), bytes.size()));
    host.receive(1, group, bytes.data(), bytes.size(), true, now);
}

static void native_settled_transitions() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1, sink.mtu);
    assert(!host.source(owner, 1, group, 1, true, a, 64, 1));
    settle(host, sink, 1);
    sink.expect({{5, {a}}, {5, {a}}});
    assert(!host.source(owner, 1, group, 1, true, b, 64, 1000));
    settle(host, sink, 1000);
    sink.expect({{5, {b}}, {5, {b}}});
    assert(!host.source(owner, 1, group, 1, false, a, 64, 2000));
    settle(host, sink, 2000);
    sink.expect({{6, {a}}, {6, {a}}});
    const uint32_t blocked[] = {c};
    assert(!host.replace(owner, 1, group, 0, blocked, 1, 64, 3000));
    settle(host, sink, 3000);
    sink.expect({{4, {c}}, {4, {c}}});
    assert(!host.source(owner, 1, group, 0, true, d, 64, 4000));
    settle(host, sink, 4000);
    sink.expect({{6, {d}}, {6, {d}}});
    assert(!host.source(owner, 1, group, 0, false, c, 64, 5000));
    settle(host, sink, 5000);
    sink.expect({{5, {c}}, {5, {c}}});
    assert(!host.leave(owner, 1, group, 6000));
    settle(host, sink, 6000);
    sink.expect({{3, {}}, {3, {}}});
}

static void native_overlapping_changes() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1, sink.mtu);
    assert(!host.join(owner, 1, group, 1));
    host.poll(1, Sink::emit, &sink);
    sink.expect({{4, {}}});
    assert(!host.source(owner, 1, group, 0, true, a, 64, 2));
    host.poll(2, Sink::emit, &sink);
    sink.expect({{4, {a}}});
    host.poll(102, Sink::emit, &sink);
    sink.expect({{6, {a}}});
    assert(!host.source(owner, 1, group, 0, false, a, 64, 1000));
    assert(!host.source(owner, 1, group, 0, true, a, 64, 1000));
    settle(host, sink, 1000);
    sink.expect({{6, {a}}, {6, {a}}});
    assert(!host.source(owner, 1, group, 0, true, b, 64, 2000));
    assert(!host.source(owner, 1, group, 0, false, b, 64, 2000));
    settle(host, sink, 2000);
    sink.expect({{5, {b}}, {5, {b}}});
    assert(!host.source(owner, 1, group, 0, true, b, 64, 3000));
    host.poll(3000, Sink::emit, &sink);
    sink.expect({{6, {b}}});
    assert(!host.source(owner, 1, group, 0, false, b, 64, 3001));
    settle(host, sink, 3001);
    sink.expect({{5, {b}}, {5, {b}}});
}

static std::vector<uint32_t> addresses(unsigned start, unsigned count = 64) {
    std::vector<uint32_t> result;
    for (unsigned n = 0; n < count; n++)
        result.push_back(a + start + n);
    return result;
}

static void complete_parts(Sink& sink, const std::vector<uint32_t>& wanted, unsigned type,
                           unsigned rounds) {
    unsigned part = 0;
    for (unsigned repeat = 0; repeat < rounds; repeat++) {
        std::vector<uint32_t> actual;
        while (actual.size() < wanted.size()) {
            assert(part < sink.records.size() && sink.records[part].type == type);
            const auto& sources = sink.records[part++].sources;
            assert(!sources.empty() && sources.size() <= (sink.mtu - 40) / 4);
            actual.insert(actual.end(), sources.begin(), sources.end());
        }
        assert(actual == wanted);
    }
    assert(part == sink.records.size());
    sink.records.clear();
}

static void mtu_and_refused_output() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    sink.mtu = 68;
    host.link(1, true, 1, sink.mtu);
    auto all = addresses(0);
    assert(!host.join(owner, 1, group, 1));
    assert(!host.replace(owner, 1, group, 1, all.data(), all.size(), 64, 1));
    sink.stop_after = 2;
    host.poll(1, Sink::emit, &sink);
    assert(sink.records.size() == 2 && sink.attempts == 3);
    sink.stop_after = ~0U;
    host.poll(2, Sink::emit, &sink);
    assert(sink.records.size() == 10);
    host.poll(102, Sink::emit, &sink);
    complete_parts(sink, all, 3, 2);
    query(host, 1000);
    host.poll(1100, Sink::emit, &sink);
    complete_parts(sink, all, 1, 1);
    assert(!host.replace(owner, 1, group, 0, all.data(), all.size(), 64, 2000));
    settle(host, sink, 2000);
    std::vector<uint32_t> prefix(all.begin(), all.begin() + 7);
    sink.expect({{4, prefix}, {4, prefix}});
    query(host, 3000);
    host.poll(3100, Sink::emit, &sink);
    sink.expect({{2, prefix}});
    // A live MTU change keeps the membership and permits the complete record.
    sink.mtu = 1500;
    host.link(1, true, 3200, sink.mtu);
    query(host, 3200);
    host.poll(3300, Sink::emit, &sink);
    sink.expect({{2, all}});
}

static void hidden_history_and_final_close() {
    MulticastHost host;
    MulticastMembership owner, mask;
    Sink sink;
    host.link(1, true, 1, sink.mtu);
    auto first = addresses(0), second = addresses(64), third = addresses(128);
    assert(!host.join(owner, 1, group, 1));
    assert(!host.replace(owner, 1, group, 1, first.data(), first.size(), 64, 1));
    settle(host, sink, 1);
    sink.records.clear();
    assert(!host.replace(owner, 1, group, 1, second.data(), second.size(), 64, 1000));
    assert(!host.join(mask, 1, group, 1000));
    auto before = owner;
    assert(host.replace(owner, 1, group, 1, third.data(), third.size(), 64, 1000) == -105);
    assert(!std::memcmp(&before, &owner, sizeof(owner)));
    host.close(mask, 1000);
    assert(!host.filter(mask, 1, group));
    settle(host, sink, 1000);
    sink.expect({{3, second}, {3, second}});
    host.close(owner, 2000);
    assert(!host.member(1, group) && !host.filter(owner, 1, group));
    settle(host, sink, 2000);
    sink.expect({{6, second}, {6, second}});
}

static void rfc_queries_and_changes() {
    for (bool exclude : {false, true}) {
        MulticastHost host;
        MulticastMembership owner;
        Sink sink;
        host.link(1, true, 1, sink.mtu);
        if (exclude)
            assert(!host.join(owner, 1, group, 1));
        assert(!host.source(owner, 1, group, exclude ? 0 : 1, true, a, 64, 1));
        settle(host, sink, 1);
        sink.records.clear();
        query(host, 1000, {a, c});
        host.poll(1100, Sink::emit, &sink);
        sink.expect({{1, {exclude ? c : a}}});
        query(host, 1200, {exclude ? a : c});
        host.poll(1300, Sink::emit, &sink);
        sink.expect({});
    }
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1, sink.mtu);
    assert(!host.source(owner, 1, group, 1, true, a, 64, 1));
    settle(host, sink, 1);
    sink.records.clear();
    query(host, 1000, {a, c});
    assert(!host.source(owner, 1, group, 1, true, c, 64, 1001));
    host.poll(1101, Sink::emit, &sink);
    host.poll(1201, Sink::emit, &sink);
    host.poll(1202, Sink::emit, &sink);
    sink.expect({{5, {c}}, {5, {c}}, {1, {a, c}}});
    // Query overflow uses the real INCLUDE filter, never EXCLUDE{}.
    query(host, 2000, addresses(0, 65));
    host.poll(2100, Sink::emit, &sink);
    sink.expect({{1, {a, c}}});
}

static void legacy_source_change_preserves_join() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1, sink.mtu);
    uint8_t general[8] = {0x11, 1};
    put16(general + 2, checksum(general, sizeof(general)));
    host.receive(1, 0xe0000001, general, sizeof(general), true, 1);
    assert(!host.join(owner, 1, group, 2));
    host.poll(2, Sink::emit, &sink);
    sink.expect({{0x16, {}}});
    assert(!host.source(owner, 1, group, 0, true, a, 64, 3));
    host.poll(1002, Sink::emit, &sink);
    if (sink.records.empty()) {
        std::puts("IGMP_LEGACY_SOURCE_CHANGE_FAIL pending_join_retransmission_lost=1");
        std::fflush(stdout);
    }
    sink.expect({{0x16, {}}});
}

int main() {
    native_settled_transitions();
    native_overlapping_changes();
    mtu_and_refused_output();
    hidden_history_and_final_close();
    rfc_queries_and_changes();
    legacy_source_change_preserves_join();
    std::puts("IPv4 production source reports, RFC queries, MTU, backpressure, ownership and "
              "legacy PASS");
}
