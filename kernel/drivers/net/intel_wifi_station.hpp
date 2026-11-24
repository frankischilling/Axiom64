// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_station.hpp
 * @brief   Internal AX201 station packet handling.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_live.hpp"

namespace ax::IntelWifi {
struct StationEvents {
    void* context;
    void (*receive)(void*, const uint8_t*, size_t);
    void (*complete)(void*, size_t, bool);
};

bool is_eapol(const uint8_t*, size_t);
bool allows_station_data(const LiveStation&, const uint8_t*, size_t);
uint64_t station_beacon_timeout(const LiveStation&);
void leave_after_link_loss(LiveScanSession&, uint16_t reason, bool from_ap);
bool observe_station_packet(LiveScanSession&, const FirmwarePacket&, uint64_t now_ms,
                            const StationEvents&);
} // namespace ax::IntelWifi
