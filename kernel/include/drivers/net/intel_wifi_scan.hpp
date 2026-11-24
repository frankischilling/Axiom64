// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_scan.hpp
 * @brief   AX201 passive scan commands and scan results.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_command.hpp"

namespace ax::IntelWifi {
inline constexpr unsigned mac_context_bytes = 148;
inline constexpr unsigned passive_request_bytes = 1940;
inline constexpr uint32_t passive_scan_id = 0;

bool decode_station_address(uint32_t high, uint32_t low, uint8_t (&address)[6]);
void prepare_scan_station(const uint8_t (&address)[6], uint8_t (&command)[mac_context_bytes]);

inline constexpr int16_t scan_signal_unavailable = -128;
inline constexpr unsigned scan_access_point_limit = 32;
inline constexpr unsigned scan_ie_capacity = page_size - 8 - 48 - 36;
static_assert(scan_ie_capacity <= UINT16_MAX);

struct ScanInformationElements {
    uint8_t beacon[scan_ie_capacity];
    uint8_t probe[scan_ie_capacity];
};

struct ScanElementStorage {
    ScanInformationElements records[scan_access_point_limit];
};

struct AccessPoint {
    uint8_t bssid[6]{};
    uint8_t ssid[32]{};
    uint8_t ssid_length = 0;
    uint16_t frequency_mhz = 0;
    uint16_t beacon_interval_tu = 0;
    uint16_t capability = 0;
    uint16_t beacon_ie_bytes = 0;
    uint16_t probe_ie_bytes = 0;
    int16_t signal_dbm = scan_signal_unavailable;
    bool probe_response = false;
};

struct PassiveScan {
    uint8_t station_address[6]{};
    uint8_t channels[51]{};
    uint8_t channel_count = 0;
    AccessPoint access_points[scan_access_point_limit]{};
    ScanElementStorage* elements = nullptr;
    uint8_t access_point_count = 0;
    bool access_points_truncated = false;
    enum class Status { pending, complete, aborted, malformed } status{};
};

bool prepare_passive_scan(const NvmInfo&, const RegulatoryProfile&, PassiveScan&,
                          uint8_t (&request)[passive_request_bytes]);
void observe_passive_scan(PassiveScan&, const FirmwarePacket&);

// The boot diagnostic publishes a completed snapshot after stopping the adapter.
// Its information elements remain owned by the driver for the rest of the boot.
const PassiveScan* passive_scan_snapshot();
unsigned passive_scan_interface();
} // namespace ax::IntelWifi
