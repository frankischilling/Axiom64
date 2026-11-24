// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi.hpp
 * @brief   Intel AX201 firmware and PCI probe interfaces.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax::IntelWifi {
inline constexpr uint32_t firmware_api = 77;
inline constexpr size_t max_firmware_bytes = 4 * 1024 * 1024;
inline constexpr unsigned max_sections = 64;
inline constexpr uint32_t max_section_bytes = 32 * 1024;

enum Region { lmac, umac, paging, region_count };

struct FirmwareSection {
    const uint8_t* data;
    uint32_t size;
};

struct FirmwareRegion {
    FirmwareSection sections[max_sections];
    unsigned count;
};

struct AntennaMasks {
    uint8_t tx, rx;
};

struct FirmwareImage {
    uint32_t version[3];
    FirmwareRegion regions[region_count];
    uint32_t paging_bytes;
    uint8_t alive_version;
    uint8_t nvm_version;
    uint8_t scan_config_version;
    AntennaMasks antennas;
    bool current_regulatory_profile;
    bool passive_scan_supported;
    bool channel_context_supported;
    bool peer_queue_supported;
    bool dual_lmac;
};

// The returned sections borrow the firmware bytes. A rejected image leaves output intact.
const char* parse_firmware(const uint8_t*, size_t, FirmwareImage&);

enum class FirmwareCheck {
    stage,
    start,
    nvm,
    scan_config,
    regulatory,
    passive_scan,
    rescan,
    channel_context,
    peer_queue,
    live_scan
};
void check_firmware(bool probe_pci, FirmwareCheck);
} // namespace ax::IntelWifi
