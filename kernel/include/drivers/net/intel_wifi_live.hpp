// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_live.hpp
 * @brief   Keep an AX201 firmware session open for scans or an open station.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_rx.hpp"

namespace ax::IntelWifi {
struct LiveStation {
    AccessPoint peer{};
    PeerQueue queue{};
    uint8_t channel = 0;
    uint32_t rate = 0;
    uint16_t next_sequence = 0;
    size_t pending_bytes = 0;
    uint64_t transmit_deadline = 0, beacon_deadline = 0;
};

struct StationRequest {
    ScanSsid ssid{};
    uint8_t bssid[6]{};
    uint32_t frequency_mhz = 0;
};

enum class JoinPhase : uint8_t {
    idle,
    phy,
    chains,
    fifo,
    bind,
    select_mac,
    add_peer,
    management_queue,
    protect,
    authenticate,
    associate,
    beacon,
    associated_mac,
    data_queue,
    release_protection,
};

enum class JoinOutcome { idle, pending, connected, rejected, timeout, failed };

struct StationJoin {
    JoinPhase phase = JoinPhase::idle;
    AccessPoint peer{};
    ScanChannel channel{};
    AssociationRequest association{};
    AssociationTiming timing{};
    PeerQueue management{}, data{};
    uint32_t rate = 0;
    uint16_t sequence = 0, command_sequence = 0, aid = 0;
    uint8_t group = 0, opcode = 0;
    bool submitted = false, acknowledged = false, indicated = false;
    uint64_t deadline = 0;
};

struct LiveScanSession {
    ReceiveReader receive;
    ScanChannelList channels{};
    uint8_t station_address[6]{};
    uint16_t next_command = 0;
    uint32_t next_scan_id = 0;
    uint64_t passive_channels = 0;
    bool running = false, active = false;
    PassiveScan scan{};
    PassiveScanExchange exchange{scan, 0, 0};
    LiveStation station{};
    StationJoin join{};
    AntennaMasks antennas{};
    bool dual_lmac = false;
    const FirmwareBootIo& io;

    LiveScanSession(const FirmwareBootIo& io, const FirmwareBootMemory& memory)
        : receive(io, memory), io(io) {
    }

    LiveScanSession(const LiveScanSession&) = delete;
    LiveScanSession& operator=(const LiveScanSession&) = delete;
};

FirmwareBootResult start_live_quz(LiveScanSession&, const AntennaMasks&,
                                  const AuthenticationTarget* open = nullptr,
                                  ScanElementStorage* elements = nullptr, bool dual_lmac = false);
bool stop_live_quz(LiveScanSession&);
int submit_live_scan(LiveScanSession&, ScanElementStorage&, uint64_t now_ms,
                     const ScanRequest& = {});
ScanOutcome poll_live_scan(LiveScanSession&, uint64_t now_ms);
int submit_live_join(LiveScanSession&, const PassiveScan&, const StationRequest&);
JoinOutcome poll_live_join(LiveScanSession&, uint64_t now_ms);
int submit_live_data(LiveScanSession&, const uint8_t*, size_t, uint64_t now_ms);
bool poll_live_station(LiveScanSession&, uint64_t now_ms, void* context,
                       void (*receive)(void*, const uint8_t*, size_t),
                       void (*complete)(void*, size_t, bool));
} // namespace ax::IntelWifi
