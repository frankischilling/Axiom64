// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/netlink.hpp
 * @brief   Netlink socket interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares netlink endpoint operations and routing message support used by
 * userspace configuration tools.
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
#include "net/ipv6.hpp"

namespace ax {
struct Task;
struct NetlinkSocket;

struct NetlinkAddress {
    uint16_t family = 16, padding = 0;
    uint32_t port = 0, groups = 0;
};

struct NetlinkHeader {
    uint32_t length;
    uint16_t type, flags;
    uint32_t sequence, port;
};

static_assert(sizeof(NetlinkAddress) == 12 && sizeof(NetlinkHeader) == 16);
constexpr size_t netlink_max_request = 4096, netlink_family_reply = 4176,
                 netlink_address_reply = 4412, netlink_ipv6_route_reply = 6144,
                 netlink_max_reply = 12288;

struct NetlinkFrame {
    NetlinkAddress source;
    uint32_t credentials[3]{};
    size_t length, reserved;
};

inline const uint8_t* netlink_bytes(const NetlinkFrame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

// Caller reserves this capacity before invoking route mutation/reply generation.
size_t routing_capacity(const NetlinkHeader&, const void* request = nullptr);

size_t routing_reply(const void*, uint32_t port, bool capped, void* output, bool privileged,
                     bool strict = false);

constexpr bool routing_dump(uint16_t type) {
    return type == 18 || type == 22 || type == 26;
}

int netlink_inventory_reply(const void*, const NetlinkHeader&, uint32_t port, void*, bool strict,
                            size_t& size);

int netlink_address_change(const void*, const NetlinkHeader&);

int netlink_link_change(const void*, const NetlinkHeader&);

int netlink_ipv6_address_change(const void*, const NetlinkHeader&);

int netlink_ipv6_route(const void*, const NetlinkHeader&, uint32_t port, void*, size_t capacity,
                       size_t& size, bool strict);

void netlink_close(NetlinkSocket*);

bool netlink_ready(NetlinkSocket*, bool write);

const NetlinkFrame* netlink_front(NetlinkSocket*);

void netlink_consume(NetlinkSocket*);

size_t netlink_available(NetlinkSocket*);
int netlink_error(NetlinkSocket*, bool consume = false);
int netlink_reserve_delivery(NetlinkSocket*, size_t, NetlinkFrame*&);
void netlink_publish_delivery(NetlinkSocket*, NetlinkFrame*);
void netlink_broadcast_uevent(const void*, size_t);
size_t netlink_receive_control(Task&, NetlinkSocket*, const NetlinkFrame&, uint64_t address,
                               uint64_t capacity, uint32_t& flags);

int netlink_target(Task&, NetlinkSocket*, const NetlinkAddress&);

int64_t netlink_send(Task&, NetlinkSocket*, const void*, size_t,
                     const NetlinkAddress* destination = nullptr);

int64_t netlink_read(NetlinkSocket*, void*, size_t);

int64_t netlink_syscall(Task&, const Frame&);
} // namespace ax
