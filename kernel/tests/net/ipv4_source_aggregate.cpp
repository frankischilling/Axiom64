// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_aggregate.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <initializer_list>

using ax::ip4::MulticastSourceAggregate;
using ax::ip4::MulticastSourceView;
constexpr uint32_t a = 0xc0000201, b = a + 1, c = a + 2, d = a + 3, e = a + 4, f = a + 5;

static void list(const MulticastSourceAggregate& value, unsigned mode,
                 std::initializer_list<uint32_t> expected) {
    std::array<uint32_t, MulticastSourceAggregate::capacity> output{};
    assert(value.mode() == mode);
    assert(value.sources(output.data(), output.size()) == expected.size());
    unsigned at = 0;
    for (uint32_t address : expected)
        assert(output[at++] == address);
    assert(value.sources(nullptr, 0) == expected.size());
}

static void lifecycle() {
    MulticastSourceAggregate value;
    constexpr uint32_t first[] = {a, b, c, d}, second[] = {b, c, d, e}, included[] = {d, e, f};
    MulticastSourceView one{true, 0, first, 4}, two{true, 0, second, 4},
        three{true, 1, included, 3};
    MulticastSourceView asm_owner{true, 0, nullptr, 0};
    assert(!value.accepts(a) && !value.owners());
    assert(!value.update({}, one) && !value.update({}, two) && !value.update({}, three));
    assert(value.owners() == 3);
    list(value, 0, {b, c});
    assert(value.accepts(a) && !value.accepts(b) && !value.accepts(c) && value.accepts(d));
    assert(!value.update({}, asm_owner));
    list(value, 0, {});
    assert(value.accepts(b) && value.accepts(c));
    assert(!value.update(asm_owner, {}));
    list(value, 0, {b, c});
    assert(!value.update(one, {}) && !value.update(two, {}));
    list(value, 1, {d, e, f});
    assert(!value.accepts(a) && value.accepts(d));
    assert(!value.update(three, {}));
    list(value, 1, {});
    assert(!value.owners() && !value.accepts(d));
}

static void capacity_and_rollback() {
    MulticastSourceAggregate value;
    std::array<uint32_t, 64> addresses;
    for (unsigned n = 0; n < addresses.size(); n++)
        addresses[n] = a + n;
    MulticastSourceView hidden{true, 1, addresses.data(), addresses.size()},
        asm_owner{true, 0, nullptr, 0};
    assert(!value.update({}, hidden) && !value.update({}, asm_owner));
    list(value, 0, {});
    uint32_t overflow = a + 64;
    MulticastSourceView extra{true, 1, &overflow, 1};
    assert(value.update({}, extra) == -105 && value.owners() == 2);
    list(value, 0, {});
    assert(!value.update(asm_owner, {}));
    assert(value.mode() == 1 && value.sources(nullptr, 0) == 64);
    for (auto address : addresses)
        assert(value.accepts(address));
    assert(!value.accepts(overflow));
    assert(value.update(hidden, {true, 2, &overflow, 1}) == -22);
    assert(value.sources(nullptr, 0) == 64 && value.owners() == 1);
    assert(value.update(hidden, {true, 1, nullptr, 1}) == -22);
    assert(value.update({}, {true, 1, addresses.data(), 65}) == -22);
    assert(value.update(extra, {}) == -22 && value.owners() == 1);
    assert(!value.update(hidden, extra));
    list(value, 1, {overflow});
    assert(!value.update(extra, {}) && !value.owners());
    assert(!value.update({}, hidden));
    uint32_t prefix = 0;
    assert(value.sources(&prefix, 1) == 64 && prefix == a);
    MulticastSourceAggregate atomic;
    MulticastSourceView prefix_owner{true, 1, addresses.data(), 63};
    MulticastSourceView tail_owner{true, 1, addresses.data() + 63, 1};
    const uint32_t replacement[] = {a + 64, a + 65};
    assert(!atomic.update({}, prefix_owner) && !atomic.update({}, tail_owner));
    assert(atomic.update(tail_owner, {true, 1, replacement, 2}) == -105);
    assert(atomic.owners() == 2 && atomic.sources(nullptr, 0) == 64);
    for (auto address : addresses)
        assert(atomic.accepts(address));
    assert(!atomic.accepts(replacement[0]) && !atomic.accepts(replacement[1]));
    assert(!atomic.update(tail_owner, {}));
    assert(atomic.sources(nullptr, 0) == 63 && !atomic.accepts(addresses[63]));
    MulticastSourceAggregate only_exclude;
    MulticastSourceView empty_include{true, 1, nullptr, 0};
    assert(!only_exclude.update({}, asm_owner));
    assert(only_exclude.update(empty_include, {}) == -22 && only_exclude.owners() == 1);
}

static void duplicates() {
    MulticastSourceAggregate value;
    constexpr uint32_t repeated[] = {a, a, c}, other[] = {a, c};
    MulticastSourceView one{true, 0, repeated, 3}, two{true, 0, other, 2};
    assert(!value.update({}, one) && !value.update({}, two));
    list(value, 0, {a, c});
    assert(!value.accepts(a) && value.accepts(b));
    assert(!value.update(one, {}));
    list(value, 0, {a, c});
    assert(!value.update(two, {}) && !value.owners());
}

static bool accepts(MulticastSourceView view, uint32_t address) {
    if (!view.present)
        return false;
    bool found = false;
    for (unsigned n = 0; n < view.count; n++)
        found |= view.addresses[n] == address;
    return view.mode ? found : !found;
}

static void union_matches(const MulticastSourceAggregate& value,
                          const std::array<MulticastSourceView, 3>& owners) {
    unsigned count = 0, excluded = 0;
    for (auto view : owners) {
        count += view.present;
        excluded += view.present && !view.mode;
    }
    assert(value.owners() == count && value.mode() == (excluded ? 0U : 1U));
    for (uint32_t address : {0U, a, b, 0xffffffffU}) {
        bool wanted = false;
        for (auto view : owners)
            wanted |= accepts(view, address);
        assert(value.accepts(address) == wanted);
    }
    std::array<uint32_t, 64> sources{};
    unsigned listed = value.sources(sources.data(), sources.size());
    for (uint32_t address : {a, b}) {
        bool included = false;
        for (unsigned n = 0; n < listed; n++)
            included |= sources[n] == address;
        bool received = value.accepts(address);
        assert(included == (value.mode() ? received : !received));
    }
}

static unsigned exhaustive_updates() {
    constexpr uint32_t aa[] = {a}, bb[] = {b}, ab[] = {a, b};
    const std::array<MulticastSourceView, 8> states{{{},
                                                     {true, 1, aa, 1},
                                                     {true, 1, bb, 1},
                                                     {true, 1, ab, 2},
                                                     {true, 0, nullptr, 0},
                                                     {true, 0, aa, 1},
                                                     {true, 0, bb, 1},
                                                     {true, 0, ab, 2}}};
    unsigned checked = 0;
    for (unsigned x = 0; x < states.size(); x++)
        for (unsigned y = 0; y < states.size(); y++)
            for (unsigned z = 0; z < states.size(); z++) {
                std::array<MulticastSourceView, 3> owners{states[x], states[y], states[z]};
                MulticastSourceAggregate value;
                for (auto view : owners)
                    assert(!value.update({}, view));
                union_matches(value, owners);
                for (unsigned changed = 0; changed < owners.size(); changed++)
                    for (auto next : states) {
                        auto copy = value;
                        auto after = owners;
                        assert(!copy.update(after[changed], next));
                        after[changed] = next;
                        union_matches(copy, after);
                        assert(!copy.update(next, owners[changed]));
                        union_matches(copy, owners);
                        checked++;
                    }
            }
    return checked;
}

int main() {
    lifecycle();
    capacity_and_rollback();
    duplicates();
    printf("IPv4 source aggregation PASS transitions=%u\n", exhaustive_updates());
}
