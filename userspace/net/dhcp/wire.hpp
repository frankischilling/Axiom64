// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/dhcp/wire.hpp
 * @brief   DHCP message codec interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines DHCP wire fields and declares message encoding and validation.
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
#include <stddef.h>
#include <stdint.h>

namespace ax::dhcp {
constexpr size_t max_payload = 1472, max_routes = 24, max_dns = 3;

enum class Type : uint8_t { discover = 1, offer, request, decline, ack, nak, release, inform };
enum class Mode : uint8_t { discover, selecting, reboot, renew, rebind, decline, release, inform };

struct Identity {
    uint8_t mac[6]{};
    char hostname[64]{};
};

struct Request {
    Identity identity;
    Mode mode = Mode::discover;
    uint32_t transaction = 0, address = 0, requested = 0, server = 0;
    uint16_t seconds = 0;
};

struct Route {
    uint32_t destination, mask, gateway;
};

struct Parameters {
    bool has_mask = false, has_lease = false, has_renewal = false, has_rebinding = false;
    bool classless = false;
    uint32_t mask = 0, router = 0, lease = 0, renewal = 0, rebinding = 0;
    uint32_t dns[max_dns]{};
    size_t dns_count = 0, route_count = 0;
    Route routes[max_routes]{};
    char domain[254]{}, search[512]{};
};

struct Reply {
    Type type = Type::nak;
    uint32_t transaction = 0, address = 0, server = 0, source = 0, destination = 0;
    uint8_t source_mac[6]{};
    Parameters parameters;
};

// Address values are in host order. Invalid input leaves a reply unchanged.
size_t encode_message(const Request&, void*, size_t);

bool decode_message(const void*, size_t, const Identity&, uint32_t transaction, Reply&);

size_t encode_frame(const Request&, uint32_t destination, const uint8_t destination_mac[6], void*,
                    size_t);

bool decode_frame(const void*, size_t, const Identity&, uint32_t transaction, Reply&);

size_t encode_arp(const Identity&, uint32_t address, bool announcement, void*, size_t);

bool conflicting_arp(const void*, size_t, const Identity&, uint32_t address, bool probing);
} // namespace ax::dhcp
