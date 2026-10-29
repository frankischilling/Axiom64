// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/path_mtu.hpp"
#include <cassert>
#include <cstdio>
#include <initializer_list>

using namespace ax::ip4;

static PathKey path(unsigned number = 1) {
    return {0x0a170102, 0x0a170100 + number, 0x0a170101, 1};
}

static void ownership() {
    PathMtuCache cache;
    auto key = path();
    assert(cache.lookup(key, 1500, 0).mtu == 1500);
    assert(cache.learn(key, 1500, 900, 1200, 0).mtu == 900);
    assert(cache.lookup(key, 1500, 1).mtu == 900);
    for (unsigned part = 0; part < 5; part++) {
        auto other = key;
        if (part == 0)
            other.source++;
        else if (part == 1)
            other.destination++;
        else if (part == 2)
            other.next_hop++;
        else if (part == 3)
            other.index++;
        else
            other.route_owner++;
        assert(cache.lookup(other, 1500, 2).mtu == 1500);
        cache.learn(other, 1500, 1000, 1200, 2);
        assert(cache.lookup(key, 1500, 3).mtu == 900);
    }
    assert(cache.lookup(key, 800, 4).mtu == 800);
    assert(cache.lookup(key, 9000, 5).mtu == 900);
    cache.discard(2);
    assert(cache.lookup(key, 1500, 6).mtu == 900);
    cache.discard(1);
    assert(cache.lookup(key, 1500, 7).mtu == 1500);
}

static void deadlines() {
    PathMtuCache cache;
    auto key = path();
    cache.learn(key, 1500, 900, 1200, 100);
    // Sustained traffic, invalid notifications and a backward clock do not renew it.
    for (uint64_t now = 100; now < 60100; now += 100)
        assert(cache.lookup(key, 1500, now).mtu == 900);
    assert(cache.lookup(key, 1500, 0).mtu == 900);
    cache.learn(key, 1500, 1000, 1200, 60099);
    cache.learn(key, 1500, 900, 900, 60099);
    assert(cache.lookup(key, 1500, 60099).mtu == 900);
    assert(cache.lookup(key, 1500, 60100).mtu == 1500);
    cache.learn(key, 1500, 900, 1200, 100000);
    cache.learn(key, 1500, 900, 1200, 100001);
    assert(cache.lookup(key, 1500, 160000).mtu == 1500);
    cache.learn(key, 1500, 900, 1200, 200000);
    cache.learn(key, 1500, 900, 1200, 230000);
    assert(cache.lookup(key, 1500, 260000).mtu == 900);
    assert(cache.lookup(key, 1500, 290000).mtu == 1500);
    cache.learn(key, 1500, 900, 1200, UINT64_MAX - 10);
    assert(cache.lookup(key, 1500, UINT64_MAX - 1).mtu == 900);
    assert(cache.lookup(key, 1500, UINT64_MAX).mtu == 1500);
}

static void floor_and_validation() {
    for (uint16_t hint : {uint16_t(0), uint16_t(68), uint16_t(551)}) {
        PathMtuCache cache;
        auto value = cache.learn(path(), 1500, hint, 1200, 100);
        assert(value.mtu == 552 && value.locked);
        cache.learn(path(), 1500, 1000, 1200, 50000);
        value = cache.lookup(path(), 1500, 60099);
        assert(value.mtu == 552 && value.locked);
        assert(cache.lookup(path(), 1500, 60100).mtu == 1500);
    }
    PathMtuCache cache;
    auto value = cache.learn(path(), 1500, 552, 1200, 0);
    assert(value.mtu == 552 && !value.locked);
    value = cache.learn(path(), 500, 300, 1200, 0);
    assert(value.mtu == 500 && value.locked);
    cache.discard();
    for (uint16_t hint : {uint16_t(1200), uint16_t(1500), uint16_t(65535)})
        assert(cache.learn(path(), 1500, hint, 1200, 0).mtu == 1500);
    assert(cache.learn(path(), 1500, 900, 27, 0).mtu == 1500);
    auto invalid = path();
    invalid.source = 0;
    cache.learn(invalid, 1500, 900, 1200, 0);
    assert(cache.lookup(path(), 1500, 1).mtu == 1500);
    invalid = path();
    invalid.destination = 0xe0000001;
    assert(cache.learn(invalid, 1500, 900, 1200, 0).mtu == 1500);
    invalid = path();
    invalid.index = 0;
    assert(cache.learn(invalid, 1500, 900, 1200, 0).mtu == 1500);
}

static void pressure() {
    PathMtuCache cache;
    for (unsigned n = 1; n <= path_mtu_capacity; n++)
        cache.learn(path(n), 1500, 900, 1200, n);
    // A useful old path survives pressure; using it does not extend its expiry.
    cache.lookup(path(1), 1500, 1000);
    cache.learn(path(100), 1500, 800, 1200, 1001);
    assert(cache.lookup(path(1), 1500, 1002).mtu == 900);
    assert(cache.lookup(path(2), 1500, 1002).mtu == 1500);
    assert(cache.lookup(path(100), 1500, 1002).mtu == 800);
    assert(cache.lookup(path(1), 1500, 60001).mtu == 1500);
    assert(cache.lookup(path(100), 1500, 60001).mtu == 800);
    cache.learn(path(200), 1500, 700, 1200, 60002);
    assert(cache.lookup(path(100), 1500, 60002).mtu == 800);
    cache.discard();
    assert(cache.lookup(path(100), 1500, 60003).mtu == 1500);
}

static void retained_deadlines() {
    PathMtuCache cache;
    bool updated = false;
    auto value = cache.learn(path(), 1500, 900, 1200, 100, &updated);
    assert(updated && value.expires == 60100);
    assert(cache.lookup(path(), 1500, 200).expires == 60100);
    value = cache.learn(path(), 1500, 1000, 1200, 200, &updated);
    assert(!updated && value.mtu == 900 && value.expires == 60100);
    value = cache.learn(path(), 1500, 900, 1200, 200, &updated);
    assert(!updated && value.expires == 60100);
    value = cache.learn(path(), 1500, 900, 1200, 30100, &updated);
    assert(updated && value.expires == 90100);
    assert(cache.lookup(path(), 1500, 90100).expires == 0);
}

static void link_limits() {
    PathMtuCache cache;
    auto key = path(), other = path();
    other.index = 2;
    cache.learn(key, 1500, 900, 1200, 100);
    cache.learn(other, 1500, 800, 1200, 100);
    cache.update_mtu(1, 1500, 1200);
    auto value = cache.lookup(key, 1200, 200);
    assert(value.mtu == 900 && value.expires == 60100 && !value.locked);
    cache.update_mtu(1, 1200, 1500);
    assert(cache.lookup(key, 1500, 300).mtu == 900);
    cache.update_mtu(1, 1500, 600);
    value = cache.lookup(key, 600, 400);
    assert(value.mtu == 600 && value.expires == 60100 && !value.locked);
    assert(cache.lookup(other, 1500, 400).mtu == 800);
    cache.update_mtu(1, 600, 1500);
    value = cache.lookup(key, 1500, 60099);
    assert(value.mtu == 1500 && value.expires == 60100 && !value.locked);
    assert(cache.lookup(key, 1500, 60100).expires == 0);

    for (uint32_t reduced : {552u, 500u}) {
        cache.discard();
        cache.learn(key, 1500, 68, 1200, 100);
        cache.update_mtu(1, 1500, 600);
        value = cache.lookup(key, 600, 200);
        assert(value.mtu == 552 && value.locked && value.expires == 60100);
        cache.update_mtu(1, 600, 1500);
        value = cache.lookup(key, 1500, 300);
        assert(value.mtu == 552 && value.locked && value.expires == 60100);
        cache.update_mtu(1, 1500, reduced);
        value = cache.lookup(key, reduced, 400);
        assert(value.mtu == reduced && !value.locked && value.expires == 60100);
        cache.update_mtu(1, reduced, 1500);
        value = cache.lookup(key, 1500, 60099);
        assert(value.mtu == 1500 && !value.locked && value.expires == 60100);
        assert(cache.lookup(key, 1500, 60100).expires == 0);
    }
}

int main() {
    ownership();
    deadlines();
    floor_and_validation();
    pressure();
    retained_deadlines();
    link_limits();
    std::puts("IPV4_PATH_MTU_PASS ownership expiry refresh floor lock pressure clocks");
}
