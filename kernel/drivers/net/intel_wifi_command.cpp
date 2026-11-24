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
                          uint8_t opcode, uint32_t payload) {
    constexpr unsigned header_bytes = 8, command_bytes = header_bytes + sizeof(payload);
    if (!dma || dma % alignof(uint64_t) || !Dma::fits(dma, command_bytes, Dma::pci) ||
        index >= command_ring_entries || !group)
        return false;
    memset(slot, 0, sizeof(slot));
    slot[0] = opcode;
    slot[1] = group;
    slot[2] = uint8_t(index); // Queue zero is reserved for host commands.
    slot[4] = sizeof(payload);
    for (unsigned i = 0; i < sizeof(payload); ++i)
        slot[header_bytes + i] = uint8_t(payload >> (8 * i));
    descriptor = {};
    descriptor.buffer_count = 1;
    descriptor.buffers[0] = {command_bytes, dma};
    return true;
}

bool read_nvm_v4(const FirmwarePacket& packet, NvmInfo& output) {
    constexpr unsigned channels = 110, channel_offset = 28;
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
    output = {version, data[7], uint8_t(count), uint8_t(bands), uint8_t(tx), uint8_t(rx)};
    return true;
}
} // namespace ax::IntelWifi
