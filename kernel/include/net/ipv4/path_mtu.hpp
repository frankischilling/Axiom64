// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/path_mtu.hpp
 * @brief   IPv4 path MTU interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines cached IPv4 path MTU state and declares lookup, update, and expiry
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
#include <cstdint>

namespace ax::ip4 {
constexpr unsigned path_mtu_capacity = 64;
constexpr uint32_t path_mtu_floor = 552;
constexpr uint64_t path_mtu_lifetime = 60000; // Ten minutes on the 100 Hz kernel clock.

struct PathKey {
    uint32_t source = 0, destination = 0, next_hop = 0;
    unsigned index = 0;
    uint64_t route_owner = 0;

    bool operator==(const PathKey&) const = default;
};

struct PathMtu {
    uint32_t mtu;
    bool locked = false;
    uint64_t expires = 0;
};

// Callers validate packet checksums and transport ownership before learning.
// Keys and device MTUs describe an already selected unicast Ethernet path.
// Lookups never renew a deadline. A sub-floor report locks WANT output without
// DF until expiry; DO still requires DF. No packet or socket storage is retained.
class PathMtuCache {
  public:
    PathMtu lookup(const PathKey&, uint32_t device_mtu, uint64_t now);
    // updated reports an accepted cache write, including a permitted deadline refresh.
    PathMtu learn(const PathKey&, uint32_t device_mtu, uint16_t announced_mtu,
                  uint16_t quoted_length, uint64_t now, bool* updated = nullptr);
    // Link changes adjust device-bound limits without renewing their deadlines.
    void update_mtu(unsigned index, uint32_t previous, uint32_t current);

    // Retiring an interface discards one index. Removing a route's last owner
    // only releases that owner's entries; unrelated routes retain their deadlines.
    void discard(unsigned index = 0);

    void discard_route(uint64_t route_owner);

    void discard_source(unsigned index, uint32_t preferred_source);

  private:
    struct Entry {
        PathKey key;
        uint32_t mtu = 0;
        bool locked = false;
        uint64_t expires = 0, touched = 0;
    };

    Entry entries[path_mtu_capacity]{};
    Entry* find(const PathKey&, uint64_t now);
};
} // namespace ax::ip4
