// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/packet.hpp
 * @brief   Packet socket interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares link-layer packet socket operations and frame observation hooks.
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
