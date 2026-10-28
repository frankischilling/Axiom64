// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast.hpp"
#include "net/ipv4_wire.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ax::ip4;
constexpr uint32_t group = 0xef6a4307;

struct Report {
    unsigned index;
    uint32_t destination;
    std::vector<uint8_t> bytes;
};

struct Sink {
    std::vector<Report> reports;
    bool available = true;

    static bool emit(void* context, unsigned index, uint32_t destination, const uint8_t* bytes,
                     size_t length) {
        auto& sink = *static_cast<Sink*>(context);
        if (!sink.available)
            return false;
        assert(length + 24 <= 68);
        assert(!checksum(bytes, length));
        sink.reports.push_back({index, destination, {bytes, bytes + length}});
        return true;
    }
};

static void settle(MulticastHost& host, Sink& sink, uint64_t now = 1) {
    host.poll(now, Sink::emit, &sink);
    host.poll(now + 100, Sink::emit, &sink);
}

static std::vector<uint8_t> query(uint32_t address = 0, std::vector<uint32_t> sources = {},
                                  unsigned code = 10) {
    std::vector<uint8_t> bytes(12 + sources.size() * 4);
    bytes[0] = 0x11;
    bytes[1] = code;
    put32(bytes.data() + 4, address);
    bytes[8] = 2;
    bytes[9] = 125;
    put16(bytes.data() + 10, sources.size());
    for (unsigned n = 0; n < sources.size(); n++)
        put32(bytes.data() + 12 + 4 * n, sources[n]);
    put16(bytes.data() + 2, checksum(bytes.data(), bytes.size()));
    return bytes;
}

static std::array<uint8_t, 8> legacy(uint8_t type, uint32_t address = 0, uint8_t maximum = 1) {
    std::array<uint8_t, 8> bytes{type, maximum};
    put32(bytes.data() + 4, address);
    put16(bytes.data() + 2, checksum(bytes.data(), bytes.size()));
    return bytes;
}

static void ownership() {
    MulticastHost host;
    MulticastMembership first, second, observer;
    host.link(1, true, 1);
    host.link(2, true, 1);
    observer.all = false;
    assert(host.join(first, 1, 0x0a010203, 1) == -22);
    assert(host.join(first, 0, group, 1) == -19);
    assert(host.join(first, 16, group, 1) == -19);
    assert(host.leave(first, 1, group, 1) == -99);
    assert(host.join(first, 1, group, 1) == 0);
    assert(host.join(first, 1, group, 1) == -98);
    assert(host.accepts(first, 1, group));
    assert(!host.accepts(first, 2, group));
    assert(!host.accepts(observer, 1, group));
    observer.all = true;
    assert(host.accepts(observer, 1, group));
    assert(host.join(second, 1, group, 1) == 0);
    assert(host.join(first, 2, group, 1) == 0);
    assert(host.leave(first, 1, group, 1) == 0);
    assert(host.member(1, group));
    host.close(second, 1);
    assert(!host.member(1, group));
    assert(!host.accepts(observer, 1, group));
    assert(host.member(2, group));
    host.close(first, 1);
    assert(!host.member(2, group));
    assert(host.member(1, 0xe0000001));
    assert(!host.member(1, 0xe0000016));
}

static void bounds() {
    MulticastHost host;
    MulticastMembership owner;
    host.link(1, true, 1);
    for (unsigned n = 0; n < owner.capacity; n++)
        assert(host.join(owner, 1, group + n, 1) == 0);
    auto before = owner;
    assert(host.join(owner, 1, group + 100, 1) == -105);
    assert(!std::memcmp(&before, &owner, sizeof(owner)));
    host.close(owner, 1);
    Sink sink;
    settle(host, sink);
    std::array<MulticastMembership, 8> owners;
    for (unsigned n = 0; n < host.group_capacity; n++)
        assert(host.join(owners[n / 20], 1, group + n, 1000) == 0);
    before = owners[7];
    assert(host.join(owners[7], 1, group + 1000, 1000) == -105);
    assert(!std::memcmp(&before, &owners[7], sizeof(before)));
    assert(host.leave(owners[0], 1, group, 1000) == 0);
    settle(host, sink, 1000);
    assert(host.join(owners[7], 1, group + 1000, 1200) == 0);
}

static void reports() {
    MulticastHost host;
    MulticastMembership owner, shared;
    Sink sink;
    host.link(1, true, 1);
    assert(host.join(owner, 1, group, 1) == 0);
    sink.available = false;
    host.poll(1, Sink::emit, &sink);
    assert(sink.reports.empty());
    sink.available = true;
    host.poll(2, Sink::emit, &sink);
    assert(sink.reports.size() == 1);
    const auto first = sink.reports[0];
    assert(first.index == 1 && first.destination == 0xe0000016);
    assert(first.bytes.size() == 16 && first.bytes[0] == 0x22 && first.bytes[8] == 4);
    assert(get16(first.bytes.data() + 6) == 1 && get16(first.bytes.data() + 10) == 0);
    assert(get32(first.bytes.data() + 12) == group);
    assert(host.join(shared, 1, group, 2) == 0);
    host.poll(2, Sink::emit, &sink);
    assert(sink.reports.size() == 1);
    host.poll(102, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.poll(10000, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.close(owner, 10000);
    host.poll(10000, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.close(shared, 10000);
    assert(!host.member(1, group));
    settle(host, sink, 10000);
    assert(sink.reports.size() == 4 && sink.reports[2].bytes[8] == 3 &&
           sink.reports[3].bytes[8] == 3);
    assert(host.join(owner, 1, 0xe0000001, 11000) == 0);
    settle(host, sink, 11000);
    assert(sink.reports.size() == 4);
}

static void queries() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1);
    assert(host.join(owner, 1, group, 1) == 0);
    settle(host, sink);
    auto bytes = query();
    host.receive(1, 0xe0000001, bytes.data(), bytes.size(), false, 1000);
    host.poll(1100, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    auto broken = bytes;
    broken[2] ^= 1;
    host.receive(1, 0xe0000001, broken.data(), broken.size(), true, 1000);
    host.poll(1100, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.receive(2, 0xe0000001, bytes.data(), bytes.size(), true, 1000);
    host.poll(1100, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.receive(1, 0xe0000001, bytes.data(), bytes.size(), true, 1200);
    host.poll(1200, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.poll(1300, Sink::emit, &sink);
    assert(sink.reports.size() == 3 && sink.reports.back().bytes[8] == 2);
    bytes = query(group, {0x0a010201, 0x0a010202});
    host.receive(1, group, bytes.data(), bytes.size(), true, 1400);
    auto more = query(group, {0x0a010202, 0x0a010203});
    host.receive(1, group, more.data(), more.size(), true, 1400);
    host.poll(1500, Sink::emit, &sink);
    assert(sink.reports.size() == 4 && sink.reports.back().bytes[8] == 1);
    assert(get16(sink.reports.back().bytes.data() + 10) == 3);
    for (unsigned n = 0; n < 3; n++)
        assert(get32(sink.reports.back().bytes.data() + 16 + n * 4) == 0x0a010201 + n);
    // A later full-group query coalesces with an earlier source-specific query.
    host.receive(1, group, bytes.data(), bytes.size(), true, 1600);
    more = query(group);
    host.receive(1, group, more.data(), more.size(), true, 1600);
    host.poll(1700, Sink::emit, &sink);
    assert(sink.reports.back().bytes[8] == 2 && sink.reports.back().bytes.size() == 16);
    // Malformed declared source counts cannot create a pending response.
    bytes.pop_back();
    put16(bytes.data() + 2, 0);
    put16(bytes.data() + 2, checksum(bytes.data(), bytes.size()));
    host.receive(1, group, bytes.data(), bytes.size(), true, 1800);
    host.poll(1900, Sink::emit, &sink);
    assert(sink.reports.size() == 5);
    // Reserved query bits are ignored on reception (RFC 9776 section 4.1.5).
    bytes = query(group);
    bytes[8] |= 0xf0;
    put16(bytes.data() + 2, 0);
    put16(bytes.data() + 2, checksum(bytes.data(), bytes.size()));
    host.receive(1, group, bytes.data(), bytes.size(), true, 2000);
    host.poll(2100, Sink::emit, &sink);
    assert(sink.reports.size() == 6 && sink.reports.back().bytes[8] == 2);
    std::vector<uint32_t> many;
    for (unsigned n = 0; n < 64; n++)
        many.push_back(0x0a020001 + n);
    bytes = query(group, many);
    host.receive(1, group, bytes.data(), bytes.size(), true, 2200);
    for (unsigned n = 0; n < 10; n++)
        host.poll(2300 + n, Sink::emit, &sink);
    assert(sink.reports.size() == 16);
    unsigned checked = 0;
    for (unsigned n = 6; n < sink.reports.size(); n++) {
        const auto& report = sink.reports[n].bytes;
        assert(report[8] == 1);
        unsigned count = get16(report.data() + 10);
        assert(count && count <= 7 && report.size() == 16 + count * 4);
        for (unsigned source = 0; source < count; source++)
            assert(get32(report.data() + 16 + source * 4) == many[checked++]);
    }
    assert(checked == many.size());
    many.push_back(0x0a020041);
    bytes = query(group, many);
    host.receive(1, group, bytes.data(), bytes.size(), true, 2400);
    host.poll(2500, Sink::emit, &sink);
    assert(sink.reports.size() == 26);
    checked = 0;
    for (unsigned n = 16; n < sink.reports.size(); n++) {
        const auto& report = sink.reports[n].bytes;
        assert(report[8] == 1);
        unsigned count = get16(report.data() + 10);
        assert(count && count <= 7 && report.size() == 16 + count * 4);
        for (unsigned source = 0; source < count; source++)
            assert(get32(report.data() + 16 + source * 4) == many[checked++]);
    }
    assert(checked == many.size());
}

static void compatibility() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    host.link(1, true, 1);
    auto bytes = legacy(0x11);
    host.receive(1, 0xe0000001, bytes.data(), bytes.size(), true, 1);
    assert(host.join(owner, 1, group, 2) == 0);
    host.poll(2, Sink::emit, &sink);
    assert(sink.reports.size() == 1 && sink.reports.back().bytes[0] == 0x16);
    bytes = legacy(0x16, group, 0);
    host.receive(1, group, bytes.data(), bytes.size(), true, 3);
    host.poll(2000, Sink::emit, &sink);
    assert(sink.reports.size() == 1);
    host.close(owner, 2000);
    host.poll(2000, Sink::emit, &sink);
    assert(sink.reports.size() == 1); // Another host was the last reporter.
    assert(host.join(owner, 1, group, 2001) == 0);
    host.poll(2001, Sink::emit, &sink);
    host.close(owner, 2002);
    host.poll(2002, Sink::emit, &sink);
    assert(sink.reports.back().bytes[0] == 0x17 && sink.reports.back().destination == 0xe0000002);
    bytes = legacy(0x11, 0, 0);
    host.receive(1, 0xe0000001, bytes.data(), bytes.size(), false, 2100);
    assert(host.join(owner, 1, group, 2101) == 0);
    host.poll(2101, Sink::emit, &sink);
    assert(sink.reports.back().bytes[0] == 0x12);
    auto count = sink.reports.size();
    host.close(owner, 2102);
    host.poll(2102, Sink::emit, &sink);
    assert(sink.reports.size() == count);
    assert(host.join(owner, 1, group, 30000) == 0);
    host.poll(30000, Sink::emit, &sink);
    assert(sink.reports.back().bytes[0] == 0x22);
}

static void links() {
    MulticastHost host;
    MulticastMembership owner;
    Sink sink;
    assert(host.join(owner, 1, group, 1) == 0);
    assert(!host.member(1, group));
    host.link(1, true, 10);
    settle(host, sink, 10);
    assert(sink.reports.size() == 2 && host.member(1, group));
    host.link(1, false, 200);
    assert(!host.member(1, group) && !host.member(1, 0xe0000001));
    host.poll(1000, Sink::emit, &sink);
    assert(sink.reports.size() == 2);
    host.link(1, true, 1001);
    settle(host, sink, 1001);
    assert(sink.reports.size() == 4 && host.member(1, group));
    host.link(1, false, 2000);
    host.close(owner, 2000);
    host.link(1, true, 2001);
    settle(host, sink, 2001);
    assert(sink.reports.size() == 4 && !host.member(1, group));
}

int main() {
    ownership();
    bounds();
    reports();
    queries();
    compatibility();
    links();
    std::puts("IPv4 multicast ownership, bounds, reports, queries, compatibility and links passed");
}
