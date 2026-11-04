// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/addresses.hpp"
#include <cassert>
#include <cstdio>

using namespace ax;

static Ipv4Config config(uint32_t address, uint32_t mask = 0xffffff00) {
    return {address, mask, address | ~mask};
}

static void labels_and_lifetimes() {
    ip4::AddressBook book;
    char label[] = "eth0:blue";
    assert(book.add(1, "eth0", config(0x0a170102)) == 0);
    assert(book.add(1, label, config(0x0a170103)) == 0);
    label[5] = 'x';
    assert(book.label(1, "eth0:blue")); // The inventory owns its label bytes.
    assert(book.add(1, "eth0:red", config(0x0a170202)) == 0);
    assert(!book.at(0)->secondary && !book.at(1)->secondary && book.at(2)->secondary);
    assert(book.label(1, "eth0:blue")->secondary);
    assert(book.preferred(1, 0x0a170201)->config.address == 0x0a170202);
    assert(book.remove(1, 0x0a170102, 0xffff0000) == -99);
    assert(book.remove(1, 0x0a170102, 0xffffff00) == 0);
    assert(!book.label(1, "eth0") && !book.label(1, "eth0:blue"));
    assert(book.label(1, "eth0:red") && !book.at(1));
    assert(book.remove(1, 0x0a170202, 0xffffff00) == 0);
    assert(!book.at(0));
}

static void failure_atomicity() {
    ip4::AddressBook book;
    assert(book.add(1, "eth0", config(0x0a170102)) == 0);
    assert(book.add(1, "eth0:blue", config(0x0a170103)) == 0);
    assert(book.add(1, "eth0:red", config(0x0a170202)) == 0);
    assert(book.set(1, "eth0", config(0x0a170104, 0xff00ff00)) == -22);
    assert(book.add(1, "0123456789abcdef", config(0x0a170104)) == -22);
    assert(book.add(0, "eth0", config(0x0a170104)) == -22);
    assert(book.add(max_net_devices + 1, "eth0", config(0x0a170104)) == -22);
    assert(book.add(1, "eth0:bad", config(0x7f000002)) == -22);
    assert(book.add(1, "eth0:bad", config(0xe0000001)) == -22);
    assert(book.add(1, "eth0:bad", config(0)) == -22);
    assert(book.label(1, "eth0")->config.address == 0x0a170102);
    assert(book.label(1, "eth0:blue") && book.at(2) && !book.at(3));
    assert(book.set(1, "eth0", config(0x0a170202)) == -17);
    assert(!book.label(1, "eth0") && !book.label(1, "eth0:blue"));
    assert(book.label(1, "eth0:red") && !book.at(1));
    assert(book.set(1, "eth0", config(0x0a170104)) == 0);
    assert(!book.label(1, "eth0:blue") && book.label(1, "eth0:red"));
    assert(book.set(1, "eth0:missing", config(0)) == 0);
    assert(book.set(1, "eth0:red", config(0)) == 0);
    assert(book.label(1, "eth0") && !book.at(1));
}

static void repeated_labels_and_capacity() {
    ip4::AddressBook book;
    for (unsigned n = 0; n < ipv4_address_capacity; n++)
        assert(book.add(1, "eth0", config(0x0a170102 + n * 256)) == 0);
    assert(book.add(1, "eth0:extra", config(0x0a630002)) == -105);
    assert(book.add(1, "eth0", config(0x0a170102)) == -17);
    assert(book.label(1, "eth0", 0x0a170802)->config.address == 0x0a170802);
    assert(book.label(1, "eth0", 0x0a990002)->config.address == 0x0a170102);
    assert(book.set(1, "eth0", config(0x0a630002)) == 0);
    assert(book.at(ipv4_address_capacity - 1) && !book.at(ipv4_address_capacity));
    assert(book.remove(1, 0x0a170802, 0xffffff00) == 0);
    assert(book.add(2, "eth1", config(0x0a170802)) == 0);
    assert(book.remove(1, 0x0a170802, 0xffffff00) == -99);
    assert(book.label(2, "eth1"));
}

static void finite_deadlines_and_renewal() {
    ip4::AddressBook book;
    const auto value = config(0x0a170102);
    assert(!book.add(1, "eth0", value, 200, {1, 3}));
    auto entry = book.label(1, "eth0");
    auto cached = book.cache(*entry, 200);
    assert(!entry->flags && cached.preferred == 1 && cached.valid == 3 && cached.created == 200 &&
           cached.updated == 200);
    assert(!book.expire(299) && !entry->flags);
    assert(book.expire(300) == 1 && entry->flags == 0x20);
    cached = book.cache(*entry, 300);
    assert(!cached.preferred && cached.valid == 2 && cached.created == 200);

    auto different = value;
    different.broadcast = 0;
    assert(!book.add(1, "ignored-label", different, 350, {2, 5}, true));
    entry = book.label(1, "eth0");
    assert(entry && !book.label(1, "ignored-label") && !entry->flags &&
           entry->config.broadcast == value.broadcast);
    cached = book.cache(*entry, 350);
    assert(cached.preferred == 2 && cached.valid == 5 && cached.created == 200 &&
           cached.updated == 350);
    assert(!book.expire(549) && book.expire(550) == 1 && entry->flags == 0x20);
    assert(book.add(1, "eth0", value, 600, {2, 8}) == -17);
    assert(book.add(1, "eth0", value, 650, {6, 5}, true) == -22);
    cached = book.cache(*entry, 650);
    assert(cached.created == 200 && cached.updated == 350 && cached.valid == 2 &&
           !cached.preferred);
    assert(!book.add(1, "eth0", value, 700, {}, true));
    cached = book.cache(*entry, 700);
    assert(entry->flags == 0x80 && cached.preferred == UINT32_MAX && cached.valid == UINT32_MAX &&
           cached.created == 200 && cached.updated == 700);
    auto permanent = book;
    assert(!permanent.expire(UINT64_MAX) && permanent.label(1, "eth0"));

    assert(!book.add(2, "eth1", value, 1000, {2, 5}));
    auto retired = *book.label(2, "eth1");
    assert(book.expire(1499) == 2 && book.label(2, "eth1"));
    assert(book.cache(*book.label(2, "eth1"), 1499).valid == 1);
    assert(book.expire(1500) == 2 && !book.label(2, "eth1"));
    assert(!book.cache(retired, 1500).valid && book.label(1, "eth0"));
}

static void permanent_and_wrapped_stamps() {
    ip4::AddressBook book;
    assert(!book.add(1, "finite-pref", config(0x0a170102), 12, {2, UINT32_MAX}));
    assert(!book.add(1, "deprecated", config(0x0a170202), 13, {0, UINT32_MAX}));
    assert(!book.expire(20000));
    auto finite_preferred = book.label(1, "finite-pref");
    auto deprecated = book.label(1, "deprecated");
    assert(finite_preferred->flags == 0x80 && deprecated->flags == 0xa0);
    auto cached = book.cache(*finite_preferred, 20000);
    assert(cached.preferred == UINT32_MAX && cached.valid == UINT32_MAX);
    cached = book.cache(*deprecated, 20000);
    assert(cached.preferred == UINT32_MAX && cached.valid == UINT32_MAX);

    uint64_t now = uint64_t(UINT32_MAX) + 95;
    assert(!book.add(2, "eth1", config(0x0a170102), now, {1, 2}));
    auto wrapped = book.label(2, "eth1");
    cached = book.cache(*wrapped, now - 1);
    assert(cached.created == 94 && cached.updated == 94 && cached.valid == 2);
    assert(!book.add(2, "eth1", wrapped->config, now + 30, {1, 2}, true));
    cached = book.cache(*wrapped, now + 30);
    assert(cached.created == 94 && cached.updated == 124);
    assert(book.expire(now + 229) == 2 && book.label(2, "eth1"));
    assert(book.expire(now + 230) == 2 && !book.label(2, "eth1"));

    auto before = book;
    assert(book.add(1, "zero", config(0x0a170302), 30000, {0, 0}) == -22);
    assert(book.add(1, "long-preferred", config(0x0a170302), 30000, {8, 7}) == -22);
    assert(!book.label(1, "zero") && !book.label(1, "long-preferred"));
    assert(book.cache(*book.at(0), 30000).updated == before.cache(*before.at(0), 30000).updated);
}

static ip4::AddressBook expiring_primary() {
    ip4::AddressBook book;
    assert(!book.add(1, "eth0", config(0x0a170102), 100, {1, 2}));
    assert(!book.add(1, "eth0:blue", config(0x0a170103), 101));
    assert(!book.add(1, "eth0:red", config(0x0a170104), 102));
    assert(!book.add(1, "eth0:other", config(0x0a170202), 103));
    assert(!book.add(2, "eth1", config(0x0a170102), 104));
    return book;
}

static void expiry_cascade_and_promotion() {
    auto cascade = expiring_primary();
    assert(cascade.expire(300) == 1);
    assert(!cascade.label(1, "eth0") && !cascade.label(1, "eth0:blue") &&
           !cascade.label(1, "eth0:red"));
    assert(cascade.label(1, "eth0:other") && cascade.label(2, "eth1"));
    auto promoted = expiring_primary();
    assert(promoted.expire(300, 1) == 1);
    assert(!promoted.label(1, "eth0") && !promoted.label(1, "eth0:blue")->secondary &&
           promoted.label(1, "eth0:red")->secondary);
    assert(promoted.preferred(1)->config.address == 0x0a170202);
    assert(promoted.preferred(1, 0x0a170199)->config.address == 0x0a170103);
    auto cached = promoted.cache(*promoted.label(1, "eth0:blue"), 300);
    assert(cached.created == 101 && cached.updated == 101);
    assert(!promoted.remove(1, 0x0a170103, 0xffffff00, true));
    assert(!promoted.label(1, "eth0:red")->secondary);
    assert(promoted.label(2, "eth1") && promoted.label(1, "eth0:other"));

    ip4::AddressBook secondary;
    assert(!secondary.add(1, "eth0", config(0x0a170102), 100));
    assert(!secondary.add(1, "eth0:short", config(0x0a170103), 101, {0, 1}));
    assert(secondary.expire(201, 1) == 1 && !secondary.label(1, "eth0:short"));
    assert(secondary.label(1, "eth0") && !secondary.label(1, "eth0")->secondary);
}

static void borrowed_insertion_values() {
    ip4::AddressBook book;
    assert(!book.add(1, "eth0", config(0x0a170102)));
    assert(!book.add(1, "eth0:blue", config(0x0a170103)));
    assert(!book.add(2, "eth1", config(0x0a170202)));
    const auto& borrowed = *book.label(2, "eth1");
    assert(!book.add(1, borrowed.label, borrowed.config, 500, {2, 5}));
    assert(book.label(1, "eth1")->config.address == 0x0a170202);
    assert(book.label(2, "eth1")->config.address == 0x0a170202);
    assert(book.label(1, "eth0:blue")->secondary);
}

int main() {
    labels_and_lifetimes();
    failure_atomicity();
    repeated_labels_and_capacity();
    finite_deadlines_and_renewal();
    permanent_and_wrapped_stamps();
    expiry_cascade_and_promotion();
    borrowed_insertion_values();
    std::puts("IPV4_ADDRESSES_PASS labels lifetimes replacement invalid-inputs capacity isolation");
}
