// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_command.hpp
 * @brief   AX201 host command and firmware notification formats.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_context.hpp"

namespace ax::IntelWifi {
inline constexpr unsigned command_slot_bytes = 64;
using CommandPayloads = uint8_t[command_ring_entries][command_slot_bytes];

struct FirmwarePacket {
    uint8_t opcode, group;
    uint16_t sequence;
    const uint8_t* payload;
    size_t length;
};

enum class PacketRead { end, packet, malformed };
PacketRead next_firmware_packet(const uint8_t*, size_t bytes, size_t& offset, FirmwarePacket&);

bool prepare_host_command(uint8_t (&slot)[command_slot_bytes], uint64_t dma, CommandDescriptor&,
                          uint16_t index, uint8_t group, uint8_t opcode, const uint8_t* payload,
                          size_t payload_bytes);

struct NvmInfo {
    uint16_t version;
    uint8_t addresses;
    uint8_t channel_count;
    uint8_t bands;
    uint8_t tx_chains, rx_chains;
};

bool read_nvm_v4(const FirmwarePacket&, NvmInfo&);
} // namespace ax::IntelWifi
