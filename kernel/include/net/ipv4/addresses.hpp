// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/addresses.hpp
 * @brief   IPv4 address inventory interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines IPv4 address records and declares assignment, removal, and selection
 * operations.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
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

    const Ipv4Address* find(unsigned index, uint32_t address, uint32_t mask) const;

    const Ipv4Address* label(unsigned index, const char*, uint32_t hint = 0) const;

    const Ipv4Address* preferred(unsigned index, uint32_t destination = 0) const;

    int add(unsigned index, const char* label, const Ipv4Config&, uint64_t now = 0,
            Ipv4AddressLifetimes = {}, bool replace = false, bool suppress_prefix_route = false);

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
