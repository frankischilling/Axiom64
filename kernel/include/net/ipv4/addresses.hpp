// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4.hpp"

namespace ax::ip4 {
// Labels identify addresses, never devices. A prefix has one primary address;
// deleting it also removes its secondaries, as with promote_secondaries=0.
// Invalid requests preserve the inventory. Replacement removes the previous
// prefix before insertion, including when a duplicate prevents reinsertion.
// No borrowed input survives.
class AddressBook {
  public:
    const Ipv4Address* at(unsigned position) const;

    const Ipv4Address* label(unsigned index, const char*, uint32_t hint = 0) const;

    const Ipv4Address* preferred(unsigned index, uint32_t destination = 0) const;

    int add(unsigned index, const char* label, const Ipv4Config&);

    int set(unsigned index, const char* label, const Ipv4Config&);

    int remove(unsigned index, uint32_t address, uint32_t mask);

  private:
    Ipv4Address entries[ipv4_address_capacity]{};
    unsigned count = 0;

    void erase(unsigned position);
};
} // namespace ax::ip4
