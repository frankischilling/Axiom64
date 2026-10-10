// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4.hpp"

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
constexpr size_t netlink_max_request = 4096, netlink_max_reply = 4116;

struct NetlinkFrame {
    NetlinkAddress source;
    size_t length, reserved;
};

inline const uint8_t* netlink_bytes(const NetlinkFrame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

// Caller reserves this capacity before invoking route mutation/reply generation.
size_t routing_capacity(const NetlinkHeader&);

size_t routing_reply(const void*, uint32_t port, bool capped, void* output, bool privileged);

int netlink_address_change(const void*, const NetlinkHeader&);

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
