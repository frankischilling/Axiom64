// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/routes.hpp"
#include <cassert>
#include <cstdio>

using namespace ax;

int main() {
    {
        ip4::RouteTable aliases;
        Ipv4Route first{0xcb007100, 0xffffff00, 0, 1, 7, 3, 253};
        auto second = first;
        second.protocol = 4;
        assert(aliases.insert(first, true) == 0 && aliases.insert(second, false) == 0);
        assert(aliases.insert(second, false) == -17 && aliases.insert(second, true) == -17);
        uint64_t owner = aliases.at(0)->owner, other = aliases.at(1)->owner, removed = 0;
        assert(owner != other && aliases.erase(first, true, removed) == 0 && removed == owner);
        assert(!aliases.owns(owner) && aliases.owns(other));
        assert(aliases.erase(second, true, removed) == 0 && removed == other &&
               !aliases.owns(other));
    }
    ip4::AddressBook addresses;
    ip4::RouteTable routes;
    for (unsigned n = 0; n < ipv4_address_capacity; n++) {
        char label[16];
        std::snprintf(label, sizeof(label), "prefix%u", n);
        assert(addresses.add(1, label, {0x0a000001 + n * 256, 0xffffff00, 0}) == 0);
    }
    assert(routes.synchronize(addresses) == 0);
    uint64_t automatic[ipv4_address_capacity];
    for (unsigned n = 0; n < ipv4_address_capacity; n++) {
        const auto entry = routes.at(n);
        assert(entry && entry->automatic && entry->owner &&
               entry->preferred_source == 0x0a000001 + n * 256);
        automatic[n] = entry->owner;
    }
    assert(routes.synchronize(addresses) == 0);
    for (unsigned n = 0; n < ipv4_address_capacity; n++)
        assert(routes.at(n)->owner == automatic[n]);
    uint64_t shared = 0;
    for (unsigned n = 0; n < ip4::RouteTable::explicit_capacity; n++) {
        Ipv4Route route{0xcb007100 + n, 0xffffffff, 0, 1, 7, 4, 253};
        assert(routes.insert(route, true) == 0);
        const auto entry = routes.at(ipv4_address_capacity + n);
        assert(entry && !entry->automatic && !entry->preferred_source);
        if (n)
            assert(entry->owner == shared);
        else
            shared = entry->owner;
    }
    Ipv4Route overflow{0xcb0071fe, 0xffffffff, 0, 1, 7, 4, 253};
    assert(routes.insert(overflow, true) == -105);
    assert(routes.at(ip4::RouteTable::capacity - 1) && !routes.at(ip4::RouteTable::capacity));
    Ipv4Route prefix{0x0a000000, 0xffffff00, 0, 1, 0, 2, 253};
    uint64_t removed = 0;
    assert(routes.erase(prefix, true, removed) == 0 && removed == automatic[0]);
    assert(!routes.owns(removed) && routes.owns(shared));
    assert(routes.synchronize(addresses) == 0 && !routes.owns(removed));
    assert(routes.insert(prefix, true) == -105);
    for (unsigned n = 0; n < ip4::RouteTable::explicit_capacity; n++) {
        Ipv4Route route{0xcb007100 + n, 0xffffffff, 0, 1, 7, 4, 253};
        assert(routes.erase(route, true, removed) == 0 && removed == shared);
        assert(routes.owns(shared) == (n + 1 < ip4::RouteTable::explicit_capacity));
    }
    assert(routes.insert(prefix, true) == 0);
    const auto restored = routes.at(ipv4_address_capacity - 1);
    assert(restored && restored->owner != automatic[0] && !routes.owns(automatic[0]));
    assert(routes.erase(prefix, true, removed) == 0);
    assert(addresses.remove(1, 0x0a000001, 0xffffff00) == 0);
    assert(routes.synchronize(addresses) == 0);
    assert(addresses.add(1, "prefix0", {0x0a000001, 0xffffff00, 0}) == 0);
    assert(routes.synchronize(addresses) == 0);
    assert(routes.at(ipv4_address_capacity - 1)->preferred_source == 0x0a000001 &&
           routes.at(ipv4_address_capacity - 1)->owner != automatic[0]);
    auto previous_owner = routes.at(0)->owner;
    Ipv4Route other_device{0xcb007100, 0xffffff00, 0, 2, 10, 4, 253};
    assert(routes.insert(other_device, true) == 0);
    routes.withdraw(1);
    assert(routes.at(0) && routes.at(0)->value.index == 2 && !routes.at(1));
    assert(!routes.owns(previous_owner));
    assert(routes.synchronize(addresses, 0) == 0 && !routes.at(1));
    assert(routes.synchronize(addresses) == 0);
    assert(routes.at(0)->owner != previous_owner && !routes.owns(previous_owner));
    assert(routes.at(ipv4_address_capacity)->value.index == 2);
    std::puts(
        "IPV4_ROUTES_PASS separate-capacities shared-owner prefix-deletion refresh recreation");
}
