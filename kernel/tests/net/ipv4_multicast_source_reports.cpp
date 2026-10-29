// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_reports.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using ax::ip4::MulticastSourceReports;
constexpr uint32_t a = 0xc0000201, b = a + 1, c = a + 2, d = a + 3;

struct Record {
    unsigned type;
    std::vector<uint32_t> sources;
    bool operator==(const Record&) const = default;
};

struct Sink {
    std::vector<Record> records;
    unsigned accepted = 0, attempts = 0, stop_after = ~0U;

    static bool emit(void* context, unsigned type, const uint32_t* sources, unsigned count) {
        auto& sink = *static_cast<Sink*>(context);
        sink.attempts++;
        if (sink.accepted == sink.stop_after)
            return false;
        sink.records.push_back({type, {sources, sources + count}});
        sink.accepted++;
        return true;
    }

    void expect(std::initializer_list<Record> expected) {
        assert(records == std::vector<Record>(expected));
        records.clear();
    }
};

static void round(MulticastSourceReports& reports, Sink& sink, unsigned maximum = 365) {
    assert(reports.transmit(maximum, Sink::emit, &sink));
}

static void settled_native_sequence() {
    MulticastSourceReports reports;
    Sink sink;
    const uint32_t first[] = {a}, both[] = {a, b}, second[] = {b}, blocked[] = {c},
                   extra[] = {c, d}, last[] = {d};
    for (auto step : {0U, 1U, 2U, 3U, 4U, 5U, 6U}) {
        const uint32_t* lists[] = {first, both, second, blocked, extra, last, nullptr};
        const unsigned counts[] = {1, 2, 1, 1, 2, 1, 0}, modes[] = {1, 1, 1, 0, 0, 0, 1};
        assert(!reports.change(modes[step], lists[step], counts[step], 2));
        assert(reports.pending());
        round(reports, sink);
        assert(reports.pending());
        round(reports, sink);
        assert(!reports.pending());
        const Record expected[] = {{5, {a}}, {5, {b}}, {6, {a}}, {4, {c}},
                                   {6, {d}}, {5, {c}}, {3, {}}};
        sink.expect({expected[step], expected[step]});
    }
}

static void native_overlapping_rounds() {
    MulticastSourceReports reports;
    Sink sink;
    const uint32_t first[] = {a}, both[] = {a, b};
    assert(!reports.change(0, nullptr, 0, 2));
    round(reports, sink);
    sink.expect({{4, {}}});
    assert(!reports.change(0, first, 1, 2));
    round(reports, sink);
    sink.expect({{4, {a}}});
    assert(reports.pending());
    round(reports, sink);
    sink.expect({{6, {a}}});
    assert(!reports.pending());
    assert(!reports.change(0, nullptr, 0, 2));
    assert(!reports.change(0, first, 1, 2));
    round(reports, sink);
    round(reports, sink);
    sink.expect({{6, {a}}, {6, {a}}});
    assert(!reports.change(0, both, 2, 2));
    assert(!reports.change(0, first, 1, 2));
    round(reports, sink);
    round(reports, sink);
    sink.expect({{5, {b}}, {5, {b}}});
    assert(!reports.change(0, both, 2, 2));
    round(reports, sink);
    sink.expect({{6, {b}}});
    assert(!reports.change(0, first, 1, 2));
    round(reports, sink);
    round(reports, sink);
    sink.expect({{5, {b}}, {5, {b}}});
    assert(!reports.pending());
}

static void minimum_mtu_and_refused_output() {
    MulticastSourceReports reports;
    Sink sink;
    std::array<uint32_t, 64> addresses;
    for (unsigned n = 0; n < addresses.size(); n++)
        addresses[n] = a + n;
    assert(!reports.change(0, nullptr, 0, 2));
    assert(!reports.change(1, addresses.data(), addresses.size(), 2));
    sink.stop_after = 2;
    assert(!reports.transmit(7, Sink::emit, &sink));
    assert(sink.records.size() == 2 && sink.attempts == 3 && reports.pending());
    auto before = sink.records;
    assert(!reports.transmit(7, Sink::emit, &sink));
    assert(sink.records == before);
    sink.stop_after = ~0U;
    round(reports, sink, 7);
    assert(sink.records.size() == 10 && reports.pending());
    round(reports, sink, 7);
    assert(sink.records.size() == 20 && !reports.pending());
    for (unsigned repeat = 0; repeat < 2; repeat++) {
        std::vector<uint32_t> actual;
        for (unsigned n = repeat * 10; n < (repeat + 1) * 10; n++) {
            assert(sink.records[n].type == 3 && sink.records[n].sources.size() <= 7);
            actual.insert(actual.end(), sink.records[n].sources.begin(),
                          sink.records[n].sources.end());
        }
        assert(actual == std::vector<uint32_t>(addresses.begin(), addresses.end()));
    }
    sink.records.clear();
    assert(!reports.change(0, addresses.data(), addresses.size(), 2));
    round(reports, sink, 7);
    round(reports, sink, 7);
    std::vector<uint32_t> prefix(addresses.begin(), addresses.begin() + 7);
    sink.expect({{4, prefix}, {4, prefix}});
}

static void finite_history_and_unfailing_final_close() {
    MulticastSourceReports reports;
    Sink sink;
    std::array<uint32_t, 64> first, second, third;
    for (unsigned n = 0; n < 64; n++) {
        first[n] = a + n;
        second[n] = a + 64 + n;
        third[n] = a + 128 + n;
    }
    assert(!reports.change(1, first.data(), 64, 2));
    assert(!reports.change(1, second.data(), 64, 2));
    std::array<unsigned char, sizeof(reports)> before;
    std::memcpy(before.data(), &reports, sizeof(reports));
    assert(reports.change(1, third.data(), 64, 2) == -105);
    assert(!std::memcmp(before.data(), &reports, sizeof(reports)));
    assert(!reports.change(1, nullptr, 0, 2));
    round(reports, sink);
    round(reports, sink);
    std::vector<uint32_t> all(first.begin(), first.end());
    all.insert(all.end(), second.begin(), second.end());
    sink.expect({{6, all}, {6, all}});
    assert(!reports.pending());
    assert(!reports.change(1, third.data(), 64, 2));
}

static void cancel_restart_and_invalid_input() {
    MulticastSourceReports reports;
    Sink sink;
    const uint32_t sources[] = {a, b}, repeated[] = {a, a};
    assert(!reports.change(1, sources, 2, 7));
    reports.cancel();
    assert(!reports.pending());
    assert(!reports.restart(2));
    round(reports, sink);
    round(reports, sink);
    sink.expect({{5, {a, b}}, {5, {a, b}}});
    assert(!reports.pending());
    assert(reports.change(2, nullptr, 0, 2) == -22);
    assert(reports.change(1, nullptr, 1, 2) == -22);
    assert(reports.change(1, repeated, 2, 2) == -22);
    assert(reports.change(1, sources, 2, 0) == -22);
    assert(reports.restart(8) == -22);
    assert(!reports.pending() && !reports.transmit(0, Sink::emit, &sink));
    assert(!reports.change(0, sources, 2, 2));
    reports.cancel();
    assert(!reports.pending());
    assert(!reports.restart(2));
    round(reports, sink);
    round(reports, sink);
    sink.expect({{4, {a, b}}, {4, {a, b}}});
}

static void hidden_owner_reservations() {
    ax::ip4::MulticastSourceAggregate aggregate;
    MulticastSourceReports reports;
    Sink sink;
    std::array<uint32_t, 64> first, second, third;
    for (unsigned n = 0; n < 64; n++) {
        first[n] = a + n;
        second[n] = a + 64 + n;
        third[n] = a + 128 + n;
    }
    ax::ip4::MulticastSourceView include_first{true, 1, first.data(), 64};
    ax::ip4::MulticastSourceView include_second{true, 1, second.data(), 64};
    ax::ip4::MulticastSourceView include_third{true, 1, third.data(), 64};
    ax::ip4::MulticastSourceView asm_owner{true, 0, nullptr, 0};
    assert(!aggregate.update({}, include_first));
    assert(!reports.change(aggregate, 2));
    round(reports, sink);
    round(reports, sink);
    sink.records.clear();
    assert(!aggregate.update(include_first, include_second));
    assert(!reports.change(aggregate, 2));
    assert(!aggregate.update({}, asm_owner));
    assert(!reports.change(aggregate, 2));
    auto candidate = aggregate;
    assert(!candidate.update(include_second, include_third));
    std::array<unsigned char, sizeof(reports)> before;
    std::memcpy(before.data(), &reports, sizeof(reports));
    // Effective EXCLUDE{} is unchanged, but accepting hidden third sources
    // would let final close require 64 unavailable report-history slots.
    int result = reports.change(candidate, 2);
    if (result != -105) {
        std::printf("IGMP_HIDDEN_RESERVATION_FAIL admitted=%d expected=-105\n", result);
        std::fflush(stdout);
    }
    assert(result == -105);
    assert(!std::memcmp(before.data(), &reports, sizeof(reports)));
    assert(!aggregate.update(asm_owner, {}));
    assert(!reports.change(aggregate, 2));
    round(reports, sink);
    round(reports, sink);
    std::vector<uint32_t> expected(second.begin(), second.end());
    sink.expect({{3, expected}, {3, expected}});
    assert(!reports.pending());
}

static void hidden_update_during_refused_source_round() {
    ax::ip4::MulticastSourceAggregate aggregate;
    MulticastSourceReports reports;
    Sink sink;
    const uint32_t before[] = {a, b}, after[] = {b, c}, high[] = {d + 100}, low[] = {a - 1};
    ax::ip4::MulticastSourceView old_filter{true, 0, before, 2};
    ax::ip4::MulticastSourceView new_filter{true, 0, after, 2};
    ax::ip4::MulticastSourceView old_hidden{true, 1, high, 1};
    ax::ip4::MulticastSourceView new_hidden{true, 1, low, 1};
    assert(!aggregate.update({}, old_filter));
    assert(!aggregate.update({}, old_hidden));
    assert(!reports.change(aggregate, 2));
    round(reports, sink);
    round(reports, sink);
    sink.records.clear();
    assert(!aggregate.update(old_filter, new_filter));
    assert(!reports.change(aggregate, 2));
    sink.stop_after = sink.accepted + 1;
    assert(!reports.transmit(1, Sink::emit, &sink));
    // This hidden-only edit reorders the retained table while a source round
    // is partly accepted. Its next address and counters must remain intact.
    assert(!aggregate.update(old_hidden, new_hidden));
    assert(!reports.change(aggregate, 2));
    sink.stop_after = ~0U;
    round(reports, sink, 1);
    sink.expect({{5, {a}}, {6, {c}}});
    round(reports, sink, 1);
    sink.expect({{5, {a}}, {6, {c}}});
    assert(!reports.pending());
}

int main() {
    hidden_update_during_refused_source_round();
    hidden_owner_reservations();
    settled_native_sequence();
    native_overlapping_rounds();
    minimum_mtu_and_refused_output();
    finite_history_and_unfailing_final_close();
    cancel_restart_and_invalid_input();
    std::puts("IPv4 source report native transitions, overlapping counters, MTU splitting, output "
              "refusal and final close PASS");
}
