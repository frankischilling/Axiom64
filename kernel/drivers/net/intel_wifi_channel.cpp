// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_channel.cpp
 * @brief   Encode AX201 PHY, radio chain, RX FIFO, and binding commands.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Layouts follow the firmware PHY context, data path, smart FIFO, and binding APIs.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_channel.hpp"

namespace ax::IntelWifi {
namespace {
constexpr uint8_t add = 1, remove = 3;

void write_word(uint8_t* bytes, unsigned offset, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        bytes[offset + i] = uint8_t(value >> (i * 8));
}
} // namespace

ChannelCommand channel_command(ChannelStep step, const ScanChannel& channel, uint8_t rx_mask,
                               bool dual_lmac) {
    ChannelCommand command;
    const bool high = channel.frequency_mhz >= 5000;
    const uint8_t lmac = high && dual_lmac ? 1 : 0;
    switch (step) {
    case ChannelStep::add_phy:
    case ChannelStep::remove_phy:
        command.opcode = 8;
        command.size = 32;
        command.bytes[4] = step == ChannelStep::add_phy ? add : remove;
        command.bytes[8] = channel.number;
        command.bytes[12] = high ? 0 : 1; // 20 MHz with the control channel at the center.
        command.bytes[16] = lmac;
        break;
    case ChannelStep::rx_chains: {
        command.group = 5;
        command.opcode = 8;
        command.size = 32;
        const uint32_t chains = rx_mask & (rx_mask - 1) ? 2 : 1;
        const uint32_t selection = (rx_mask & 7) << 1;
        write_word(command.bytes, 4, selection | (chains << 10) | (chains << 12));
        break;
    }
    case ChannelStep::initialize_fifo:
        command.opcode = 0xd1;
        command.size = sizeof(command.bytes);
        command.bytes[0] = 3; // SF_INIT_OFF until the station is associated.
        write_word(command.bytes, 4, 4096);
        write_word(command.bytes, 8, 8192);
        for (unsigned scenario = 0; scenario < 5; ++scenario) {
            const unsigned timer = 8 * scenario;
            write_word(command.bytes, 12 + timer, 1000000);
            write_word(command.bytes, 16 + timer, 1000000);
            write_word(command.bytes, 52 + timer, 400);
            write_word(command.bytes, 56 + timer, 160);
        }
        break;
    case ChannelStep::bind:
    case ChannelStep::unbind:
        command.opcode = 0x2b;
        command.size = 28;
        command.has_status = true;
        command.bytes[4] = step == ChannelStep::bind ? add : remove;
        // Associate MAC context 0 with PHY context 0. Unused MAC IDs are all ones.
        memset(command.bytes + (step == ChannelStep::bind ? 12 : 8), 0xff,
               step == ChannelStep::bind ? 8 : 12);
        command.bytes[24] = lmac;
        break;
    }
    return command;
}

bool binding_succeeded(const FirmwarePacket& packet) {
    if (packet.group != 1 || packet.opcode != 0x2b || packet.length != 4 || !packet.payload)
        return false;
    const auto* bytes = packet.payload;
    return !(bytes[0] | bytes[1] | bytes[2] | bytes[3]);
}
} // namespace ax::IntelWifi
