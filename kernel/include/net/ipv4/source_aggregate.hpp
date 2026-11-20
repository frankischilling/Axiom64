// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/source_aggregate.hpp
 * @brief   IPv4 multicast source aggregation.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the source filter state that combines per-socket membership for an
 * interface.
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
#include <cstdint>

namespace ax::ip4 {
struct MulticastSourceView {
    bool present = false;
    unsigned mode = 1;
    const uint32_t* addresses = nullptr;
    unsigned count = 0;
};

// Interface reception is the union of the socket interests in RFC 9776 section
// 3.2. Preserve even sources hidden by an EXCLUDE owner: final close may expose
// them without being able to return an allocation error. Updates are atomic.
// The caller owns the per-socket views and serializes updates with packet input.
class MulticastSourceAggregate {
  public:
    static constexpr unsigned capacity = 64;
    int update(MulticastSourceView before, MulticastSourceView after);

    unsigned owners() const {
        return owner_count;
    }

    unsigned mode() const {
        return exclude_count ? 0 : 1;
    }

    bool accepts(uint32_t source) const;
    // Return the complete count; copy only the caller's available prefix.
    unsigned sources(uint32_t* output, unsigned available) const;
    // Reserve every contributor, including sources hidden by other owners.
    // Removing an owner can expose these without an allocation failure.
    unsigned retained_sources(uint32_t* output, unsigned available) const;

  private:
    struct Source {
        uint32_t address = 0;
        unsigned included = 0, excluded = 0;
    };

    Source entries[capacity]{};
    unsigned used = 0, owner_count = 0, exclude_count = 0;
    int apply(MulticastSourceView, bool add);
    bool effective(const Source&) const;
};
} // namespace ax::ip4
