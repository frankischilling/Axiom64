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

struct FirmwareImage {
    uint32_t version[3];
    FirmwareRegion regions[region_count];
    uint32_t paging_bytes;
    uint8_t alive_version;
    uint8_t nvm_version;
};

// The returned sections borrow the firmware bytes. A rejected image leaves output intact.
const char* parse_firmware(const uint8_t*, size_t, FirmwareImage&);
void check_firmware(bool probe_pci, bool start = false, bool nvm = false);
} // namespace ax::IntelWifi
