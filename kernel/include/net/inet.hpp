// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;
struct InetSocket;

struct InetAddress {
    uint16_t family, port;
    uint32_t address;
    uint8_t padding[8];
};

static_assert(sizeof(InetAddress) == 16);

struct InetFrame {
    InetAddress source;
    size_t length;
};

inline const uint8_t* inet_bytes(const InetFrame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

void inet_close(InetSocket*);

bool inet_payload(InetSocket*);

bool inet_ready(InetSocket*, bool write);

const InetFrame* inet_front(InetSocket*);

void inet_consume(InetSocket*);

InetAddress inet_peer(InetSocket*);

int inet_target(InetSocket*, InetAddress&, bool named);

unsigned inet_shutdown(InetSocket*);

size_t inet_available(InetSocket*);

int inet_error(InetSocket*, bool clear = false);

void inet_failed(InetSocket*, int error);

void inet_icmp_error(unsigned index, const uint8_t* quote, int error);

void inet_reclaim(InetSocket*, size_t length);

void inet_deliver(unsigned index, uint32_t source, uint32_t destination, uint8_t protocol,
                  const void*, size_t);

bool inet_datagram_deliver(unsigned index, uint32_t source, uint32_t destination,
                           uint16_t source_port, uint16_t destination_port, bool broadcast,
                           const void*, size_t);

int64_t inet_send(InetSocket*, const InetAddress&, const void*, size_t);

int64_t inet_read(InetSocket*, void*, size_t);

int64_t inet_syscall(Task&, const Frame&);
} // namespace ax
