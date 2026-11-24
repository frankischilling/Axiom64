// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_channel.hpp
 * @brief   AX201 operating channel and station binding commands.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_scan.hpp"

namespace ax::IntelWifi {
enum class ChannelStep { add_phy, rx_chains, initialize_fifo, bind, unbind, remove_phy };

struct ChannelCommand {
    uint8_t group = 1, opcode = 0;
    unsigned size = 0;
    bool has_status = false;
    uint8_t bytes[92]{};
};

ChannelCommand channel_command(ChannelStep, const ScanChannel&, uint8_t rx_mask, bool dual_lmac);
bool binding_succeeded(const FirmwarePacket&);
} // namespace ax::IntelWifi
