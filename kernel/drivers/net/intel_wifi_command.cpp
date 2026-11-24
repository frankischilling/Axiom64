// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_command.cpp
 * @brief   Encode QuZ command descriptors and decode firmware frames.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Formats follow Linux iwlwifi fw/api/cmdhdr.h, fw/api/nvm-reg.h,
 * pcie/tx-gen2.c, and pcie/rx.c.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_command.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
uint16_t load16(const uint8_t* data) {
    return uint16_t(data[0]) | (uint16_t(data[1]) << 8);
}

uint32_t load32(const uint8_t* data) {
    return uint32_t(load16(data)) | (uint32_t(load16(data + 2)) << 16);
}
} // namespace

PacketRead next_firmware_packet(const uint8_t* data, size_t bytes, size_t& offset,
                                FirmwarePacket& output) {
    constexpr unsigned length_bytes = 4, header_bytes = 8, alignment = 64;
    if (!data || offset > bytes || offset % alignment)
        return PacketRead::malformed;
    if (bytes - offset < header_bytes)
        return PacketRead::end;
    const auto* frame = data + offset;
    const uint32_t flags = load32(frame);
    if (!flags || flags == 0x55550000)
        return PacketRead::end;
    const unsigned length = (flags & 0x3fff) + length_bytes;
    const unsigned stride = (length + alignment - 1) & ~(alignment - 1);
    if ((flags & 0x3f0000) || length < header_bytes || stride > bytes - offset)
        return PacketRead::malformed;
    output = {frame[4], frame[5], load16(frame + 6), frame + header_bytes, length - header_bytes};
    offset += stride;
    return PacketRead::packet;
}

bool prepare_host_command(uint8_t (&slot)[command_slot_bytes], uint64_t dma,
                          CommandDescriptor& descriptor, uint16_t index, uint8_t group,
                          uint8_t opcode, const uint8_t* payload, size_t payload_bytes) {
    constexpr unsigned header_bytes = 8;
    if (payload_bytes > sizeof(slot) - header_bytes || (!payload && payload_bytes))
        return false;
    const auto command_bytes = uint16_t(header_bytes + payload_bytes);
    if (!dma || dma % alignof(uint64_t) || !Dma::fits(dma, command_bytes, Dma::pci) ||
        index >= command_ring_entries || !group)
        return false;
    memset(slot, 0, sizeof(slot));
    slot[0] = opcode;
    slot[1] = group;
    slot[2] = uint8_t(index); // Queue zero is reserved for host commands.
    slot[4] = uint8_t(payload_bytes);
    slot[5] = uint8_t(payload_bytes >> 8);
    if (payload_bytes)
        memcpy(slot + header_bytes, payload, payload_bytes);
    descriptor = {};
    constexpr uint16_t first_buffer_bytes = 20;
    if (command_bytes <= first_buffer_bytes) {
        descriptor.buffer_count = 1;
        descriptor.buffers[0] = {command_bytes, dma};
    } else {
        descriptor.buffer_count = 2;
        descriptor.buffers[0] = {first_buffer_bytes, dma};
        descriptor.buffers[1] = {uint16_t(command_bytes - first_buffer_bytes),
                                 dma + first_buffer_bytes};
    }
    return true;
}

bool read_nvm_v4(const FirmwarePacket& packet, NvmInfo& output) {
    constexpr unsigned channels = regulatory_channel_limit, channel_offset = 28;
    if (packet.group != 12 || packet.opcode != 2 || !packet.payload ||
        packet.length != channel_offset + channels * sizeof(uint32_t))
        return false;
    const auto* data = packet.payload;
    const auto count = load32(data + 24);
    const auto bands = load32(data + 8) & 3;
    const auto tx = load32(data + 12), rx = load32(data + 16);
    const auto version = load16(data + 4);
    if ((load32(data) & 1) || !version || !data[7] || !count || count > channels || !bands || !tx ||
        tx > 3 || !rx || rx > 3)
        return false;
    output = {version,     data[7],     uint8_t(count),        uint8_t(bands),
              uint8_t(tx), uint8_t(rx), load32(data + 20) != 0};
    return true;
}

bool read_regulatory_v5(const FirmwarePacket& packet, RegulatoryProfile& output) {
    // The API 77 firmware advertises notification v5 with the 11ax MCC header.
    constexpr unsigned header_bytes = 20, count_offset = 16;
    if (packet.group != 1 || packet.opcode != 0xc8 || !packet.payload ||
        packet.length < header_bytes)
        return false;
    const auto* data = packet.payload;
    const auto count = load32(data + count_offset);
    if (load32(data) > 1 || count > regulatory_channel_limit ||
        packet.length != header_bytes + count * sizeof(uint32_t))
        return false;
    // Some firmware revisions use a zero word for the world domain.
    const auto country = load16(data + 4);
    const char a = country ? char(country >> 8) : '0';
    const char b = country ? char(country) : '0';
    if (country && country != 0x3030 && (a < 'A' || a > 'Z' || b < 'A' || b > 'Z'))
        return false;
    output = {};
    output.country[0] = a;
    output.country[1] = b;
    output.channel_slots = uint8_t(count);
    for (unsigned i = 0; i < count; ++i) {
        output.flags[i] = load16(data + header_bytes + i * sizeof(uint32_t));
        output.valid_channels += bool(output.flags[i] & 1);
    }
    return true;
}
} // namespace ax::IntelWifi
