// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4.hpp"

namespace ax::ip4 {
// Labels identify addresses, never devices. A prefix has one primary address;
// deleting it also removes its secondaries, as with promote_secondaries=0.
// Explicit promotion retains them and places their new primary after the other
// primaries on that device. Expire advances the owner's 100 Hz monotonic clock
// before observations; cache replies use the same clock and Linux centiseconds.
// Invalid requests preserve the inventory. Replacement removes the previous
// prefix before insertion, including when a duplicate prevents reinsertion.
// No borrowed input survives.
class AddressBook {
  public:
    const Ipv4Address* at(unsigned position) const;

    const Ipv4Address* label(unsigned index, const char*, uint32_t hint = 0) const;

    const Ipv4Address* preferred(unsigned index, uint32_t destination = 0) const;

    int add(unsigned index, const char* label, const Ipv4Config&, uint64_t now = 0,
            Ipv4AddressLifetimes = {}, bool replace = false);

    int set(unsigned index, const char* label, const Ipv4Config&, uint64_t now = 0,
            bool promote = false);

    int remove(unsigned index, uint32_t address, uint32_t mask, bool promote = false);

    // Return the devices whose address inventory or deprecation state changed.
    uint16_t expire(uint64_t now, uint16_t promote_interfaces = 0);

    Ipv4AddressCacheInfo cache(const Ipv4Address&, uint64_t now) const;

  private:
    struct Slot {
        Ipv4Address value;
        Ipv4AddressLifetimes lifetime;
        uint64_t created = 0, updated = 0;
    };

    Slot entries[ipv4_address_capacity]{};
    unsigned count = 0;

    static void renew(Slot&, Ipv4AddressLifetimes, uint64_t now);
    void erase(unsigned position, bool promote);
};
} // namespace ax::ip4
