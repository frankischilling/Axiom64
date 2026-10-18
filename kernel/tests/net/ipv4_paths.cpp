// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/inet.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace ax {
uint64_t ticks = 100;

void* alloc(size_t length) {
    return std::malloc(length);
}

void release(void* bytes) {
    std::free(bytes);
}

void log(const char*, ...) {
}

void inet_reclaim(InetSocket*, size_t) {
    assert(false && "path selection must not own a socket output");
}

void inet_failed(InetSocket*, int) {
    assert(false && "path selection must not deliver a socket error");
}
} // namespace ax

using namespace ax;

static void poll(NetAdapter&) {
}

static int transmit(NetAdapter&, const void*, size_t) {
    assert(false && "path queries must not transmit frames");
    return -5;
}

static uint32_t mtu(unsigned index, uint32_t destination) {
    Ipv4Path result;
    assert(ipv4_path(0, destination, index, result) == 0);
    return result.mtu;
}

static void learn(unsigned index, uint32_t peer, uint16_t limit) {
    assert(ipv4_learn_pmtu(ipv4_config(index)->address, peer, index, limit, 1128) == limit);
}

static void unrelated_routes() {
    constexpr uint32_t peer = 0x0a1701be;
    learn(1, peer, 900);
    Ipv4Route unrelated{0x0a630000, 0xffffff00, 0, 1};
    assert(ipv4_route(unrelated, false) == 0);
    assert(mtu(1, peer) == 900);
    assert(ipv4_route(unrelated, true) == 0);
    assert(mtu(1, peer) == 900);
    Ipv4Route gateway{peer, 0xffffffff, 0x0a170101, 1};
    assert(ipv4_route(gateway, false) == 0);
    assert(mtu(1, peer) == 1500);
    learn(1, peer, 700);
    assert(mtu(1, peer) == 700);
    assert(ipv4_route(gateway, true) == 0);
    assert(mtu(1, peer) == 900);
    assert(ipv4_route(gateway, false) == 0);
    assert(mtu(1, peer) == 1500);
    assert(ipv4_route(gateway, true) == 0);
    assert(mtu(1, peer) == 900);
}

static void shared_next_hop() {
    constexpr uint32_t peer = 0x0a1701be;
    Ipv4Route broad{0x0a170180, 0xffffff80, 0, 1};
    Ipv4Route narrow{peer, 0xffffffff, 0, 1};
    assert(ipv4_route(broad, false) == 0);
    assert(mtu(1, peer) == 1500);
    learn(1, peer, 800);
    assert(ipv4_route(narrow, false) == 0);
    assert(mtu(1, peer) == 800);
    learn(1, peer, 700);
    assert(ipv4_route(narrow, true) == 0);
    assert(mtu(1, peer) == 700);
    // Prefixes can share a next hop; priority, protocol and scope distinguish owners.
    for (unsigned field = 0; field < 3; field++) {
        auto different = narrow;
        if (field == 0)
            different.metric = 1;
        else if (field == 1)
            different.protocol = 4;
        else
            different.scope = 254;
        assert(ipv4_route(different, false) == 0);
        assert(mtu(1, peer) == 1500);
        learn(1, peer, 600);
        assert(ipv4_route(different, true) == 0);
        assert(mtu(1, peer) == 700);
    }
    assert(ipv4_route(broad, true) == 0);
    assert(mtu(1, peer) == 900);
}

static void route_pressure() {
    constexpr uint32_t peer = 0x0a1701ce;
    learn(1, peer, 900);
    Ipv4Route routes[32];
    for (unsigned n = 0; n < 32; n++) {
        routes[n] = {0x0a640000 + n * 256, 0xffffff00, 0, 2};
        assert(ipv4_route(routes[n], false) == 0);
        assert(mtu(1, peer) == 900);
    }
    assert(ipv4_route(routes[0], false) == -17);
    Ipv4Route extra{0x0a650000, 0xffffff00, 0, 2};
    assert(ipv4_route(extra, false) == -105);
    assert(ipv4_route(extra, true) == -3);
    assert(mtu(1, peer) == 900);
    for (const auto& route : routes) {
        assert(ipv4_route(route, true) == 0);
        assert(mtu(1, peer) == 900);
    }
}

static void address_aliases() {
    constexpr uint32_t first = 0x0a170102, alias = 0x0a170103, peer = 0x0a1701be;
    constexpr uint32_t other = 0x0a170302;
    learn(1, peer, 900);
    Ipv4Config secondary{alias, 0xffffff00, 0x0a1701ff};
    Ipv4Config independent{other, 0xffffff00, 0x0a1703ff};
    assert(ipv4_address_add(1, "eth0:blue", secondary) == 0);
    assert(ipv4_address_add(1, "eth0:red", independent) == 0);
    assert(ipv4_address_add(1, "independent", {other + 1, 0xffffff00, 0x0a1703ff}) == 0);
    assert(ipv4_address_remove(1, other + 1, 0xffffff00) == 0);
    assert(ipv4_address_add(1, "eth0:duplicate", secondary) == -17);
    assert(ipv4_local(alias) && ipv4_local(other));
    Ipv4Path path;
    assert(ipv4_path(alias, peer, 1, path) == 0 && path.source == alias && path.mtu == 900);
    assert(ipv4_path(0, 0x0a170301, 1, path) == 0 && path.source == other);
    assert(ipv4_learn_pmtu(alias, peer, 1, 700, 1128) == 700);
    assert(mtu(1, peer) == 700);
    assert(ipv4_address_remove(1, alias, 0xffff0000) == -99);
    assert(ipv4_address_remove(1, alias, 0xffffff00) == 0);
    assert(mtu(1, peer) == 700);
    assert(ipv4_address_add(1, "eth0:blue", secondary) == 0);
    Ipv4Route gateway{0x0a630000, 0xffffff00, 0x0a170301};
    assert(ipv4_route(gateway, false) == 0);
    assert(ipv4_path(0, 0x0a630001, 0, path) == 0 && path.index == 1 && path.source == other);
    assert(ipv4_route(gateway, true) == 0);
    assert(ipv4_address_remove(1, first, 0xffffff00) == 0);
    assert(!ipv4_local(first) && !ipv4_local(alias) && ipv4_local(other));
    assert(!ipv4_label(1, "eth0") && !ipv4_label(1, "eth0:blue"));
    assert(ipv4_path(0, 0x0a170301, 1, path) == 0 && path.source == other);
    assert(ipv4_path(alias, peer, 1, path) == -99);
    assert(ipv4_configure(1, {first, 0xffffff00, 0}) == 0);
    assert(mtu(1, peer) == 1500);
    assert(ipv4_address_remove(1, other, 0xffffff00) == 0);
}

static void link_lifecycle() {
    constexpr uint32_t first = 0x0a1701d0, second = 0x0a1702d0;
    learn(1, first, 900);
    learn(2, second, 800);
    assert(net_configure(1, true, 1500) == 0);
    assert(mtu(1, first) == 900);
    assert(net_configure(1, true, 600) == 0);
    assert(mtu(1, first) == 600);
    assert(mtu(2, second) == 800);
    assert(net_configure(1, true, 1500) == 0);
    assert(mtu(1, first) == 1500);
    learn(1, first, 900);
    assert(net_configure(1, true, 1501) == -22);
    assert(mtu(1, first) == 900);
    assert(net_configure(1, false, 1500) == 0);
    Ipv4Path path;
    assert(ipv4_path(0, first, 1, path) == -100);
    assert(net_configure(1, true, 1500) == 0);
    assert(mtu(1, first) == 900);
    assert(ipv4_configure(1, {0x0a170103, 0xffffff00, 0}) == 0);
    assert(mtu(1, first) == 1500);
    assert(mtu(2, second) == 800);
    learn(1, first, 900);
    ticks = 60099;
    assert(mtu(1, first) == 900);
    assert(mtu(2, second) == 800);
    ticks = 60100;
    assert(mtu(1, first) == 1500);
    assert(mtu(2, second) == 1500);
}

int main() {
    NetAdapter adapters[2];
    for (unsigned index = 1; index <= 2; index++) {
        auto& adapter = adapters[index - 1];
        adapter.info.mac[0] = 2;
        adapter.info.mac[5] = uint8_t(index);
        adapter.info.live = adapter.info.administrative = adapter.info.carrier = true;
        adapter.poll = adapter.stop = poll;
        adapter.send = transmit;
        assert(net_register(adapter) == index);
        assert(ipv4_configure(index, {0x0a170002 + index * 256, 0xffffff00, 0}) == 0);
    }
    unrelated_routes();
    shared_next_hop();
    route_pressure();
    address_aliases();
    link_lifecycle();
    ipv4_shutdown();
    std::puts("IPV4_PATHS_PASS route-ownership restoration sharing pressure links expiry");
}
