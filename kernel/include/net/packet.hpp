// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ethernet.hpp"

namespace ax {
struct Task;
struct PacketSocket;

struct PacketAddress {
    uint16_t family, protocol;
    int32_t index;
    uint16_t hardware;
    uint8_t type, length, address[8];
};

static_assert(sizeof(PacketAddress) == 20);

struct PacketFrame {
    PacketAddress source;
    size_t length;
    uint64_t realtime_ticks;
};

inline const uint8_t* packet_bytes(const PacketFrame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

void packet_close(PacketSocket*);

bool packet_ready(PacketSocket*, bool write);

const PacketFrame* packet_front(PacketSocket*);

void packet_consume(PacketSocket*);

// Capture admission time belongs to the queued bytes, including delayed reads.
void packet_observed(PacketSocket*, const PacketFrame&);
// The first query enables recording on the shared socket description.
int packet_timestamp(PacketSocket*, int64_t (&value)[2], bool nanoseconds);

unsigned packet_interface(PacketSocket*);

void packet_deliver(const NetInfo&, const void*, size_t, unsigned type, const void* sender);

int64_t packet_read(PacketSocket*, void*, size_t);

int64_t packet_write(PacketSocket*, const void*, size_t);

int64_t packet_syscall(Task&, const Frame&);

size_t packet_available(PacketSocket*);
} // namespace ax
