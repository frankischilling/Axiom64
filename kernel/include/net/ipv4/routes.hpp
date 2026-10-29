// SPDX-License-Identifier: GPL-3.0-or-later
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
