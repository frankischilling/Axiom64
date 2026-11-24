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

bool decode_station_address(uint32_t high, uint32_t low, uint8_t (&address)[6]);
void prepare_scan_station(const uint8_t (&address)[6], uint8_t (&command)[mac_context_bytes]);

inline constexpr int16_t scan_signal_unavailable = -128;
inline constexpr unsigned scan_access_point_limit = 32;
inline constexpr unsigned scan_channel_limit = 51;
inline constexpr uint64_t all_scan_channels = (uint64_t(1) << scan_channel_limit) - 1;
inline constexpr unsigned scan_ie_capacity = page_size - 8 - 48 - 36;
static_assert(scan_ie_capacity <= UINT16_MAX);

struct ScanChannel {
    uint16_t frequency_mhz;
    uint8_t number;
    bool allowed, radar, indoor;
};

struct ScanChannelList {
    ScanChannel entries[scan_channel_limit]{};
    unsigned count = 0;
};

ScanChannelList scan_channel_list(const NvmInfo&, const RegulatoryProfile&);

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
    uint32_t id = 0;
    uint8_t station_address[6]{};
    uint8_t channels[scan_channel_limit]{};
    uint8_t channel_count = 0;
    AccessPoint access_points[scan_access_point_limit]{};
    ScanElementStorage* elements = nullptr;
    uint8_t access_point_count = 0;
    bool access_points_truncated = false;
    enum class Status { pending, complete, aborted, malformed } status{};
};

bool prepare_passive_scan(const ScanChannelList&, PassiveScan&,
                          uint8_t (&request)[passive_request_bytes], uint32_t id,
                          uint64_t channels);
void observe_passive_scan(PassiveScan&, const FirmwarePacket&);

enum class ScanOutcome {
    pending,
    complete,
    rejected,
    reply_timeout,
    completion_timeout,
    aborted,
    malformed,
    receive_failed,
};

// The transport supplies timestamps and notifications. Each call returns without waiting.
class PassiveScanExchange {
    PassiveScan& scan;
    uint16_t sequence;
    uint64_t phase_start;
    ScanOutcome result = ScanOutcome::pending;
    bool accepted = false;

  public:
    PassiveScanExchange(PassiveScan& scan, uint16_t sequence, uint64_t started_ms)
        : scan(scan), sequence(sequence), phase_start(started_ms) {
    }

    ScanOutcome outcome() const {
        return result;
    }

    void restart(uint16_t new_sequence, uint64_t now_ms);

    void expire(uint64_t now_ms);
    void observe(const FirmwarePacket&, uint64_t now_ms);
    void receive_failed();
};

// Borrow the most recently published scan while holding the kernel lock.
const PassiveScan* passive_scan_snapshot();
const ScanChannelList& scan_channel_inventory();
unsigned passive_scan_interface();
uint32_t passive_scan_generation();
bool live_scan_available();
int trigger_live_scan(uint64_t channels);
} // namespace ax::IntelWifi
