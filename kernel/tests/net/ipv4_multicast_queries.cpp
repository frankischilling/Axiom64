// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/query_sources.hpp"
#include "net/ipv4_wire.hpp"
#include "ipv4_multicast_memory.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <utility>
#include <vector>

using namespace ax::ip4;

static std::vector<uint8_t> wire(const std::vector<uint32_t>& addresses) {
    std::vector<uint8_t> bytes(addresses.size() * 4);
    for (size_t n = 0; n < addresses.size(); n++)
        put32(bytes.data() + n * 4, addresses[n]);
    return bytes;
}

static bool merge(MulticastQuerySources& sources, MulticastQueryBudget& budget,
                  const std::vector<uint32_t>& addresses) {
    auto bytes = wire(addresses);
    return sources.merge(bytes.data(), addresses.size(), budget);
}

static void expect(const MulticastQuerySources& sources, std::vector<uint32_t> wanted) {
    std::sort(wanted.begin(), wanted.end());
    wanted.erase(std::unique(wanted.begin(), wanted.end()), wanted.end());
    assert(sources.size() == wanted.size());
    for (unsigned n = 0; n < sources.size(); n++)
        assert(sources.data()[n] == wanted[n]);
}

static void set_union_and_copy() {
    for (unsigned count = 1; count <= 257; count++) {
        MulticastQueryBudget budget;
        {
            MulticastQuerySources sources;
            std::vector<uint32_t> first, second, expected;
            for (unsigned n = 0; n < count; n++) {
                first.push_back(0xc0000201 + (count - n - 1) * 2);
                second.push_back(0xc0000201 + n);
            }
            assert(merge(sources, budget, first));
            expect(sources, first);
            expected = first;
            expected.insert(expected.end(), second.begin(), second.end());
            assert(merge(sources, budget, second));
            expect(sources, expected);
            assert(multicast_test::live_allocations() == 1);
            const auto* original = sources.data();
            multicast_test::allocation_limit(0);
            assert(merge(sources, budget, expected));
            assert(sources.data() == original);
            multicast_test::allocation_limit(UINT32_MAX);
        }
        assert(budget.used == 0 && multicast_test::live_allocations() == 0);
    }
    MulticastQueryBudget budget;
    MulticastQuerySources sources;
    auto bytes = wire({9, 2, 9, 3});
    assert(sources.merge(bytes.data(), 4, budget));
    std::fill(bytes.begin(), bytes.end(), 0);
    expect(sources, {2, 3, 9});
}

static void pressure_and_lifetime() {
    MulticastQueryBudget budget{48};
    {
        MulticastQuerySources first, second;
        assert(merge(first, budget, {1, 2, 3, 4}));
        assert(merge(second, budget, {5, 6, 7, 8}));
        assert(budget.used == 32);
        const auto* before = first.data();
        assert(!merge(first, budget, {9}));
        assert(first.data() == before && budget.used == 32);
        expect(first, {1, 2, 3, 4});
        second.clear();
        assert(budget.used == 16);
        multicast_test::allocation_limit(0);
        assert(!merge(first, budget, {9}));
        assert(first.data() == before && budget.used == 16);
        expect(first, {1, 2, 3, 4});
        multicast_test::allocation_limit(UINT32_MAX);
        assert(merge(first, budget, {9}));
        expect(first, {1, 2, 3, 4, 9});
        assert(budget.used == 20);
        MulticastQuerySources moved(std::move(first));
        assert(first.size() == 0);
        expect(moved, {1, 2, 3, 4, 9});
        second = std::move(moved);
        assert(moved.size() == 0 && budget.used == 20);
        second = {};
        assert(budget.used == 0);
    }
    assert(multicast_test::live_allocations() == 0);
}

static void full_ip_query_and_accumulation() {
    MulticastQueryBudget budget;
    {
        MulticastQuerySources sources;
        std::vector<uint32_t> first, second, expected;
        for (unsigned n = 0; n < 16374; n++) {
            first.push_back(0xc0000201 + 16373 - n);
            second.push_back(0xc0000201 + n + 16000);
        }
        assert(merge(sources, budget, first));
        expect(sources, first);
        expected = first;
        expected.insert(expected.end(), second.begin(), second.end());
        assert(merge(sources, budget, second));
        expect(sources, expected);
        assert(sources.size() == 32374);
        std::vector<uint32_t> third(16374);
        for (unsigned n = 0; n < third.size(); n++)
            third[n] = 0xc0010201 + n;
        const auto* before = sources.data();
        assert(!merge(sources, budget, third));
        assert(sources.data() == before);
        expect(sources, expected);
        assert(!sources.merge(nullptr, 1, budget));
        assert(!sources.merge(nullptr, UINT32_MAX, budget));
        expect(sources, expected);
    }
    assert(budget.used == 0 && multicast_test::live_allocations() == 0);
}

int main() {
    set_union_and_copy();
    pressure_and_lifetime();
    full_ip_query_and_accumulation();
    assert(multicast_test::live_allocations() == 0);
    std::puts(
        "IPV4_MULTICAST_QUERIES_PASS union copy maximum_ip_query pressure rollback moves lifetime");
}
