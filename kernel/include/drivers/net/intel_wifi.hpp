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
    uint8_t security_key_version;
    AntennaMasks antennas;
    bool current_regulatory_profile;
    bool passive_scan_supported;
    bool channel_context_supported;
    bool peer_queue_supported;
    bool authentication_supported;
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
    security_key,
    peer_queue,
    authenticate,
    associate,
    data_probe,
    live_scan,
    open_link
};

inline constexpr bool management_exchange(FirmwareCheck check) {
    return check == FirmwareCheck::authenticate || check == FirmwareCheck::associate ||
           check == FirmwareCheck::data_probe || check == FirmwareCheck::open_link;
}

struct AuthenticationTarget {
    uint8_t bssid[6]{};
    uint32_t source_ipv4 = 0, peer_ipv4 = 0;
};

bool parse_authentication_target(const char*, AuthenticationTarget&);
bool parse_data_probe_target(const char*, AuthenticationTarget&);

struct BootFirmware {
    uint8_t* bytes = nullptr;
    size_t size = 0;
};

BootFirmware read_boot_firmware();
void check_firmware(bool probe_pci, FirmwareCheck, const AuthenticationTarget& = {},
                    BootFirmware* = nullptr);
void start_if_available();

struct QueueResponse {
    unsigned bytes = 0;
    uint16_t id = 0, flags = 0;
    uint8_t group = 0, opcode = 0;
};

struct RadioStatus {
    char firmware[128] = "not started";
    const char* failure = "none";
    const char* shutdown = "none";
    const char* recovery = "none";
    unsigned failures = 0;
    unsigned restart_attempts = 0;
    unsigned join_result = 0;
    unsigned peer_status = 0;
    unsigned fault_phase = 0;
    int fault_result = 0;
    QueueResponse queue_response{};
    bool live = false;
    bool authorized = false;
    bool recovery_image = false;
};

RadioStatus radio_status();
} // namespace ax::IntelWifi
