// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/query_sources.hpp
 * @brief   IGMP query source tracking.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the bounded source set used for source-specific multicast queries.
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
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
struct MulticastQueryBudget {
    size_t limit = 262144;
    size_t used = 0;
};

// A pending source query owns a sorted unique set, independent of the socket
// filter's capacity. The budget outlives every set using it. Serialized callers
// can merge complete validated wire lists; refusal preserves the previous set.
class MulticastQuerySources {
  public:
    MulticastQuerySources() = default;
    MulticastQuerySources(const MulticastQuerySources&) = delete;
    MulticastQuerySources& operator=(const MulticastQuerySources&) = delete;
    MulticastQuerySources(MulticastQuerySources&&);
    MulticastQuerySources& operator=(MulticastQuerySources&&);
    ~MulticastQuerySources();

    bool merge(const uint8_t* addresses, unsigned count, MulticastQueryBudget&);
    void clear();

    unsigned size() const {
        return count;
    }

    const uint32_t* data() const {
        return addresses;
    }

  private:
    MulticastQueryBudget* budget = nullptr;
    uint32_t* addresses = nullptr;
    size_t allocated = 0;
    unsigned count = 0;
    bool contains(uint32_t) const;
};
} // namespace ax::ip4
