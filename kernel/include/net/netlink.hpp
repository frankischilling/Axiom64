// SPDX-License-Identifier: GPL-3.0-or-later
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
                 netlink_ipv6_route_reply = 6144, netlink_max_reply = 12288;

struct NetlinkFrame {
    NetlinkAddress source;
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

int netlink_target(const NetlinkAddress&);

int64_t netlink_send(NetlinkSocket*, unsigned process, const void*, size_t);

int64_t netlink_read(NetlinkSocket*, void*, size_t);

int64_t netlink_syscall(Task&, const Frame&);
} // namespace ax
