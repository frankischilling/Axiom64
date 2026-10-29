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

int main() {
    labels_and_lifetimes();
    failure_atomicity();
    repeated_labels_and_capacity();
    std::puts("IPV4_ADDRESSES_PASS labels lifetimes replacement invalid-inputs capacity isolation");
}
