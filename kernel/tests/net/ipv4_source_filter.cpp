// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_filter.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace ax::ip4;
constexpr uint32_t a = 0xc0000201, b = a + 1, c = a + 2;

static void state(const MulticastSourceFilter& filter, unsigned mode, const uint32_t* expected,
                  unsigned count) {
    assert(filter.present() && filter.mode() == mode);
    uint32_t output[64]{};
    assert(filter.sources(output, 64) == count);
    for (unsigned n = 0; n < count; n++)
        assert(output[n] == expected[n]);
    output[0] = 0x12345678;
    assert(filter.sources(output, 0) == count && output[0] == 0x12345678);
    if (count) {
        assert(filter.sources(output, 1) == count && output[0] == expected[0]);
        assert(filter.accepts(expected[0]) == bool(mode));
    }
    assert(filter.accepts(0x0a010203) == !mode);
}

static void observed_empty_list_transitions() {
    MulticastSourceFilter filter;
    assert(filter.replace(1, nullptr, 0, 10) == -99);
    assert(filter.replace(0, nullptr, 0, 10) == -22);
    assert(filter.source(0, true, a, 10) == -22);
    assert(filter.join() == 0 && filter.join() == -98);
    assert(filter.source(1, false, a, 10) == -99);
    state(filter, 1, nullptr, 0);
    assert(filter.source(0, true, b, 10) == 0);
    state(filter, 0, &b, 1);
    assert(filter.source(0, false, b, 10) == 0);
    auto before = filter;
    assert(filter.source(1, false, a, 10) == -22);
    assert(!std::memcmp(&before, &filter, sizeof(filter)));
    state(filter, 0, nullptr, 0);
    assert(filter.replace(0, nullptr, 0, 10) == 0);
    assert(filter.source(0, false, a, 10) == -99);
    state(filter, 0, nullptr, 0);
    assert(filter.source(1, false, a, 10) == -99);
    state(filter, 1, nullptr, 0);
    assert(filter.source(1, true, c, 10) == 0);
    state(filter, 1, &c, 1);
    assert(filter.source(1, false, c, 10) == 0 && !filter.present());
    assert(!filter.accepts(c));
}

static void ordered_duplicates_and_limits() {
    MulticastSourceFilter filter;
    assert(filter.join() == 0);
    const uint32_t original[] = {a, a, c};
    assert(filter.replace(0, original, 3, 64) == 0);
    state(filter, 0, original, 3);
    assert(filter.source(0, false, a, 64) == 0);
    const uint32_t remaining[] = {a, c};
    state(filter, 0, remaining, 2);
    assert(filter.source(0, false, a, 64) == 0);
    state(filter, 0, &c, 1);
    assert(filter.source(0, false, a, 64) == -99);
    assert(filter.leave() == 0);
    uint32_t expected[64];
    for (unsigned n = 0; n < 64; n++)
        expected[n] = a + n;
    for (unsigned n = 0; n < 10; n++)
        assert(filter.source(1, true, expected[n], 10) == 0);
    auto before = filter;
    assert(filter.source(1, true, a, 10) == -105);
    assert(!std::memcmp(&before, &filter, sizeof(filter)));
    assert(filter.source(1, false, expected[4], 10) == 0);
    assert(filter.source(1, true, a, 10) == -99);
    assert(filter.source(1, true, a + 19, 10) == 0);
    for (unsigned n = 4; n < 9; n++)
        expected[n] = expected[n + 1];
    expected[9] = a + 19;
    state(filter, 1, expected, 10);
    for (unsigned n = 0; n < 64; n++)
        expected[n] = a + n;
    assert(filter.replace(1, expected, 64, 64) == 0);
    state(filter, 1, expected, 64);
    before = filter;
    assert(filter.source(1, true, 0, 64) == -105);
    assert(filter.replace(0, expected, 65, 64) == -105);
    assert(filter.replace(2, expected, 1, 64) == -22);
    assert(!std::memcmp(&before, &filter, sizeof(filter)));
    // Source values are Linux ABI inputs, including values that cannot be
    // legitimate unicast packet origins; they still round-trip unchanged.
    const uint32_t special[] = {0, 0xe0000001, 0xffffffff};
    assert(filter.replace(1, special, 3, 64) == 0);
    state(filter, 1, special, 3);
}

static void aggregate_rollback_and_final_close() {
    MulticastSourceAggregate aggregate;
    MulticastSourceFilter hidden, all;
    uint32_t sources[64];
    for (unsigned n = 0; n < 64; n++)
        sources[n] = a + n;
    assert(hidden.join() == 0 && hidden.replace(1, sources, 64, 64) == 0);
    assert(all.join() == 0);
    assert(aggregate.update({}, hidden.view()) == 0);
    assert(aggregate.update({}, all.view()) == 0);
    auto before = hidden;
    auto candidate = hidden;
    const uint32_t overflow[] = {0x0a000001};
    assert(candidate.replace(1, overflow, 1, 64) == 0);
    // Removing one complete owner's contribution releases its old slots.
    assert(aggregate.update(hidden.view(), candidate.view()) == 0);
    hidden = candidate;
    assert(aggregate.update({}, before.view()) == -105);
    assert(aggregate.mode() == 0 && aggregate.accepts(0x0a010203));
    assert(aggregate.update(all.view(), {}) == 0);
    assert(all.leave() == 0);
    assert(aggregate.mode() == 1 && aggregate.accepts(overflow[0]));
    assert(!aggregate.accepts(a));
    assert(aggregate.update(hidden.view(), {}) == 0 && aggregate.owners() == 0);
}

int main() {
    observed_empty_list_transitions();
    ordered_duplicates_and_limits();
    aggregate_rollback_and_final_close();
    std::puts("IPv4 per-socket source state, native empty-list/error order, capacity and aggregate "
              "rollback PASS");
}
