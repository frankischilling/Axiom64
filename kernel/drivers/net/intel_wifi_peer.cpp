// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_peer.cpp
 * @brief   Encode AX201 peer station and management scheduler requests.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Layouts follow the firmware station and scheduler APIs.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_peer.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr size_t ring_bytes = management_queue_entries * sizeof(CommandDescriptor);
static_assert(ring_bytes == page_size && transmit_byte_count_bytes <= page_size);

void store_le(uint8_t* data, uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; ++i)
        data[i] = uint8_t(value >> (8 * i));
}

uint16_t load16(const uint8_t* data) {
    return uint16_t(data[0] | (unsigned(data[1]) << 8));
}

bool scheduler_reply(const FirmwarePacket& packet) {
    return packet.group == 5 && packet.opcode == 0x17;
}
} // namespace

bool valid_peer_queue_memory(PeerQueueMemory memory) {
    return memory.descriptor_ring && memory.byte_counts &&
           memory.descriptor_ring != memory.byte_counts &&
           !(memory.descriptor_ring & (page_size - 1)) && !(memory.byte_counts & (page_size - 1)) &&
           Dma::fits(memory.descriptor_ring, ring_bytes, Dma::pci) &&
           Dma::fits(memory.byte_counts, transmit_byte_count_bytes, Dma::pci);
}

bool prepare_peer_station(const AccessPoint& peer, uint8_t station,
                          uint8_t (&command)[peer_station_bytes]) {
    uint8_t address_bits = 0;
    for (const auto byte : peer.bssid)
        address_bits |= byte;
    if (!address_bits || (peer.bssid[0] & 1) || station >= 32)
        return false;
    memset(command, 0, sizeof(command));
    command[2] = command[3] = 0xff; // Disable aggregation during authentication.
    memcpy(command + 8, peer.bssid, sizeof(peer.bssid));
    command[16] = station;
    constexpr uint32_t station_flags_mask = (3u << 26) | (3u << 28) | (1u << 17);
    store_le(command + 24, station_flags_mask, 4); // Select 20 MHz, one stream, and no RTS MIMO.
    return true;
}

void prepare_remove_peer(uint8_t station, uint8_t (&command)[remove_peer_bytes]) {
    memset(command, 0, sizeof(command));
    command[0] = station;
}

bool peer_station_added(const FirmwarePacket& packet) {
    return packet.group == 1 && packet.opcode == 0x18 && packet.length == 4 && packet.payload &&
           packet.payload[0] == 1;
}

bool prepare_add_station_queue(PeerQueueMemory memory, uint8_t station,
                               uint8_t (&command)[scheduler_command_bytes], uint8_t tid) {
    if (!valid_peer_queue_memory(memory) || station >= 32 || tid > management_tid)
        return false;
    memset(command, 0, sizeof(command));
    store_le(command + 4, uint32_t(1) << station, 4);
    command[8] = tid;
    command[16] = 1; // log2(16) - 3.
    store_le(command + 20, memory.byte_counts, 8);
    store_le(command + 28, memory.descriptor_ring, 8);
    return true;
}

bool prepare_remove_station_queue(uint8_t station, uint8_t (&command)[scheduler_command_bytes],
                                  uint8_t tid) {
    if (station >= 32 || tid > management_tid)
        return false;
    memset(command, 0, sizeof(command));
    command[0] = 1; // Remove the queue associated with this station and TID.
    store_le(command + 4, uint32_t(1) << station, 4);
    command[8] = tid;
    return true;
}

bool parse_station_queue(const FirmwarePacket& packet, PeerQueue& queue) {
    if (!scheduler_reply(packet) || packet.length != 8 || !packet.payload)
        return false;
    // Gen2 queue allocation uses the assigned queue number and write pointer.
    const auto id = load16(packet.payload);
    if (!id || id >= 512)
        return false;
    queue = {id, uint8_t(load16(packet.payload + 4))}; // QuZ hardware pointer wraps at 256.
    return true;
}

bool station_queue_removed(const FirmwarePacket& packet) {
    return scheduler_reply(packet) && (!packet.length || (packet.length == 8 && packet.payload &&
                                                          !load16(packet.payload + 2)));
}
} // namespace ax::IntelWifi
