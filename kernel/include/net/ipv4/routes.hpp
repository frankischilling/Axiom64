// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/routes.hpp
 * @brief   IPv4 route selection interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines route records and declares lookup and update operations for IPv4
 * forwarding decisions.
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
#include "net/ipv4/addresses.hpp"

namespace ax::ip4 {
// Validated main-table routes share next-hop owners. A deleted automatic prefix
// remains absent until its primary address or device is reactivated.
class RouteTable {
  public:
    static constexpr unsigned explicit_capacity = 32;
    static constexpr unsigned capacity = ipv4_address_capacity + explicit_capacity;

    struct Entry {
        Ipv4Route value{};
        uint64_t owner = 0;
        uint32_t preferred_source = 0;
        bool automatic = false;
    };

    // Borrowed entries remain valid only until the next mutation.
    const Entry* at(unsigned position) const;
    bool owns(uint64_t owner) const;
    int insert(const Ipv4Route&, bool exclusive);
    int erase(const Ipv4Route&, bool control, uint64_t& removed_owner);
    int synchronize(const AddressBook&, uint16_t active_interfaces = UINT16_MAX);
    void withdraw(unsigned index);

  private:
    struct Slot {
        Entry entry{};
        bool installed = false;
    };

    Slot entries[capacity]{};
    uint64_t next_owner = 0;
};
} // namespace ax::ip4
