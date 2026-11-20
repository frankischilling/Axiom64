// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/source_filter.hpp
 * @brief   IPv4 multicast source filter interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines include and exclude rules and the operations used to evaluate them.
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
#include "net/ipv4/source_aggregate.hpp"

namespace ax::ip4 {
// One socket's interest in one group on one interface. Keep the ABI's ordered
// list (including bulk duplicates) separate from the aggregate's unique set.
// The caller submits old/new views to the interface aggregate before committing
// a candidate. A failed source removal can still change an unallocated empty
// filter's mode, as observed on Linux; do not discard that state transition.
class MulticastSourceFilter {
  public:
    static constexpr unsigned capacity = MulticastSourceAggregate::capacity;
    int join();
    int leave();
    int source(unsigned mode, bool add, uint32_t address, unsigned limit);
    int replace(unsigned mode, const uint32_t* sources, unsigned count, unsigned limit);

    bool present() const {
        return active;
    }

    unsigned mode() const {
        return filter_mode;
    }

    unsigned sources(uint32_t* output, unsigned available) const;
    bool accepts(uint32_t source) const;

    MulticastSourceView view() const {
        return {active, filter_mode, addresses, count};
    }

  private:
    uint32_t addresses[capacity]{};
    unsigned count = 0, filter_mode = 0;
    // UNBLOCK of the final EXCLUDE source retains an allocated empty list.
    // Explicit replacement with EXCLUDE{} frees it and permits a mode switch.
    bool active = false, list_allocated = false;
};
} // namespace ax::ip4
