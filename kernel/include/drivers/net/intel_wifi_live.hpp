// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_live.hpp
 * @brief   Keep an AX201 firmware session open for passive scans after boot.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_rx.hpp"

namespace ax::IntelWifi {
struct LiveScanSession {
    ReceiveReader receive;
    NvmInfo nvm{};
    RegulatoryProfile regulatory{};
    uint8_t station_address[6]{};
    uint16_t next_command = 0;
    uint32_t next_scan_id = 0;
    bool running = false, active = false;
    PassiveScan scan{};
    PassiveScanExchange exchange{scan, 0, 0};
    const FirmwareBootIo& io;

    LiveScanSession(const FirmwareBootIo& io, const FirmwareBootMemory& memory)
        : receive(io, memory), io(io) {
    }

    LiveScanSession(const LiveScanSession&) = delete;
    LiveScanSession& operator=(const LiveScanSession&) = delete;
};

FirmwareBootResult start_live_quz(LiveScanSession&, const AntennaMasks&);
bool stop_live_quz(LiveScanSession&);
int submit_live_scan(LiveScanSession&, ScanElementStorage&, uint64_t now_ms);
ScanOutcome poll_live_scan(LiveScanSession&, uint64_t now_ms);
} // namespace ax::IntelWifi
