// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_peer.hpp
 * @brief   AX201 peer station and management transmit queue commands.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_scan.hpp"

namespace ax::IntelWifi {
inline constexpr unsigned management_queue_entries = 16;
inline constexpr unsigned transmit_byte_count_bytes = (256 + 64) * sizeof(uint16_t);
inline constexpr unsigned peer_station_bytes = 48, remove_peer_bytes = 4;
inline constexpr unsigned scheduler_command_bytes = 36;
inline constexpr uint8_t management_tid = 15;
inline constexpr uint8_t non_qos_tid = 0;

struct PeerQueueMemory {
    uint64_t descriptor_ring = 0;
    uint64_t byte_counts = 0;
};

struct PeerQueue {
    uint16_t id = 0;
    uint8_t write_pointer = 0;
};

bool valid_peer_queue_memory(PeerQueueMemory);
bool prepare_peer_station(const AccessPoint&, uint8_t station, uint8_t (&wire)[peer_station_bytes]);
void prepare_remove_peer(uint8_t station, uint8_t (&wire)[remove_peer_bytes]);
bool peer_station_added(const FirmwarePacket&);
bool prepare_add_station_queue(PeerQueueMemory, uint8_t station,
                               uint8_t (&wire)[scheduler_command_bytes],
                               uint8_t tid = management_tid);
bool prepare_remove_station_queue(uint8_t station, uint8_t (&wire)[scheduler_command_bytes],
                                  uint8_t tid = management_tid);
bool parse_station_queue(const FirmwarePacket&, PeerQueue&);
bool station_queue_removed(const FirmwarePacket&);
} // namespace ax::IntelWifi
