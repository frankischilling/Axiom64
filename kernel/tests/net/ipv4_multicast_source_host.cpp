// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace ax::ip4;
constexpr uint32_t group = 0xef7f2a01, a = 0xc0000201, b = a + 1, c = a + 2;

static void shared_sources_and_links() {
    MulticastHost host;
    MulticastMembership first, second, observer;
    host.link(1, true, 1);
    host.link(2, true, 1);
    assert(host.source(first, 1, group, 1, true, a, 64, 1) == 0);
    assert(host.member(1, group));
    assert(host.accepts(first, 1, group, a) && !host.accepts(first, 1, group, b));
    assert(host.accepts(observer, 1, group, a) && !host.accepts(observer, 1, group, b));
    observer.all = false;
    assert(!host.accepts(observer, 1, group, a));
    observer.all = true;
    assert(host.join(second, 1, group, 1) == 0);
    assert(host.accepts(observer, 1, group, b) && !host.accepts(first, 1, group, b));
    assert(host.source(second, 1, group, 0, true, a, 64, 1) == 0);
    assert(host.accepts(observer, 1, group, a));
    assert(!host.accepts(second, 1, group, a) && host.accepts(second, 1, group, b));
    host.close(first, 1);
    assert(!host.accepts_source(1, group, a) && host.accepts_source(1, group, b));
    assert(host.source(first, 2, group, 1, true, a, 64, 1) == 0);
    assert(host.accepts_source(2, group, a) && !host.accepts_source(2, group, b));
    host.link(1, false, 2);
    assert(!host.accepts(second, 1, group, b) && host.accepts(first, 2, group, a));
    host.link(1, true, 3);
    assert(!host.accepts(second, 1, group, a) && host.accepts(second, 1, group, b));
    host.close(second, 4);
    assert(!host.member(1, group) && host.member(2, group));
    host.close(first, 4);
    assert(!host.member(2, group));
}

static void native_error_state_and_order() {
    MulticastHost host;
    MulticastMembership owner;
    host.link(1, true, 1);
    assert(host.source(owner, 1, group, 0, true, a, 10, 1) == -22);
    assert(!host.member(1, group));
    assert(host.replace(owner, 1, group, 1, nullptr, 0, 10, 1) == -99);
    assert(host.replace(owner, 1, group, 0, nullptr, 0, 10, 1) == -22);
    assert(host.join(owner, 1, group, 1) == 0);
    assert(host.source(owner, 1, group, 1, false, a, 10, 1) == -99);
    auto filter = host.filter(owner, 1, group);
    assert(filter && filter->mode() == 1 && filter->sources(nullptr, 0) == 0);
    assert(host.member(1, group) && !host.accepts_source(1, group, a));
    assert(host.source(owner, 1, group, 0, true, b, 10, 1) == 0);
    assert(host.source(owner, 1, group, 0, false, b, 10, 1) == 0);
    assert(host.source(owner, 1, group, 1, false, a, 10, 1) == -22);
    assert(host.filter(owner, 1, group)->mode() == 0 && host.accepts_source(1, group, a));
    const uint32_t duplicates[] = {a, a, c};
    assert(host.replace(owner, 1, group, 0, duplicates, 3, 10, 1) == 0);
    assert(host.source(owner, 1, group, 0, false, a, 10, 1) == 0);
    uint32_t actual[3]{};
    assert(host.filter(owner, 1, group)->sources(actual, 3) == 2);
    assert(actual[0] == a && actual[1] == c && !host.accepts_source(1, group, a));
    assert(host.source(owner, 1, group, 0, false, a, 10, 1) == 0);
    assert(host.accepts_source(1, group, a) && !host.accepts_source(1, group, c));
    assert(host.replace(owner, 1, group, 1, nullptr, 0, 10, 1) == 0);
    assert(!host.filter(owner, 1, group) && !host.member(1, group));
}

static void capacity_rollback_and_hidden_close() {
    MulticastHost host;
    MulticastMembership first, last, mask, rejected;
    host.link(1, true, 1);
    uint32_t sources[64];
    for (unsigned n = 0; n < 64; n++)
        sources[n] = a + n;
    assert(host.join(first, 1, group, 1) == 0);
    assert(host.replace(first, 1, group, 1, sources, 63, 64, 1) == 0);
    assert(host.source(last, 1, group, 1, true, sources[63], 64, 1) == 0);
    assert(host.join(mask, 1, group, 1) == 0);
    const uint32_t replacement[] = {a + 64, a + 65};
    auto before = last;
    assert(host.replace(last, 1, group, 1, replacement, 2, 64, 1) == -105);
    assert(!std::memcmp(&before, &last, sizeof(last)));
    auto vacant = rejected;
    assert(host.source(rejected, 1, group, 1, true, a + 64, 64, 1) == -105);
    assert(!std::memcmp(&vacant, &rejected, sizeof(rejected)));
    // ASM hides the active sources but must retain their admission slots.
    host.close(mask, 1);
    for (auto source : sources)
        assert(host.accepts_source(1, group, source));
    assert(!host.accepts_source(1, group, replacement[0]));
    host.close(first, 1);
    assert(!host.accepts_source(1, group, sources[0]));
    assert(host.accepts_source(1, group, sources[63]));
    assert(host.source(rejected, 1, group, 1, true, a + 64, 64, 1) == 0);
    assert(host.accepts_source(1, group, a + 64));
    host.close(last, 1);
    host.close(rejected, 1);
    assert(!host.member(1, group));
}

static void membership_slots_and_invalid_requests() {
    MulticastHost host;
    MulticastMembership owner;
    host.link(1, true, 1);
    assert(host.source(owner, 0, group, 1, true, a, 64, 1) == -19);
    assert(host.source(owner, 1, a, 1, true, a, 64, 1) == -22);
    assert(host.source(owner, 1, group, 2, true, a, 64, 1) == -22);
    for (unsigned n = 0; n < owner.capacity; n++)
        assert(host.source(owner, 1, group + n, 1, true, a, 64, 1) == 0);
    auto before = owner;
    assert(host.source(owner, 1, group + 100, 1, true, a, 64, 1) == -105);
    assert(!std::memcmp(&before, &owner, sizeof(owner)));
    host.close(owner, 1);
    for (unsigned n = 0; n < owner.capacity; n++)
        assert(!host.member(1, group + n));
}

int main() {
    shared_sources_and_links();
    native_error_state_and_order();
    capacity_rollback_and_hidden_close();
    membership_slots_and_invalid_requests();
    std::puts("IPv4 source ownership, two-interface reception, failed-update rollback and final "
              "close PASS");
}
