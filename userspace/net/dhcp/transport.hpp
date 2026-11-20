// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/dhcp/transport.hpp
 * @brief   DHCP transport interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the socket and packet operations used to exchange DHCP traffic.
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
#include "net/dhcp/state.hpp"
#include <poll.h>

namespace ax::dhcp {
struct Interface {
    char name[16]{};
    unsigned index = 0;
    Identity identity;
    bool up = false;
    // Linux IFF_RUNNING: operational carrier requires administrative UP.
    bool carrier = false;
};

// Positive errno on failure; neither function changes interface configuration.
int query_interface(unsigned index, Interface&);

// An absent or concurrently withdrawn address returns a zero address/mask.
// Other errors leave both caller outputs unchanged.
int query_address(const char* interface, uint32_t& address, uint32_t& mask);

enum class Received : uint8_t { empty, ignored, reply, conflict };

class Transport {
  public:
    Transport() = default;

    ~Transport();

    Transport(const Transport&) = delete;

    Transport& operator=(const Transport&) = delete;

    int open(const Interface&);

    int close();

    int configured(uint32_t address);

    int transmit(const Action&);

    int receive(uint32_t transaction, uint32_t candidate, bool probing, Reply&, Received&);

    int carrier(bool&);

    size_t descriptors(pollfd*, size_t) const;

  private:
    Interface interface_;
    int control_ = -1, packet_ = -1, broadcast_ = -1, unicast_ = -1;
    uint32_t address_ = 0;
    unsigned cursor_ = 0;
    uint8_t local_macs_[8][6]{};
    size_t local_count_ = 0;

    int udp(uint32_t address);
};
} // namespace ax::dhcp
