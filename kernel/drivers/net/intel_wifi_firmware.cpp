// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_firmware.cpp
 * @brief   Decode the Intel AX201 unified firmware image.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * The TLV and section layout follows Linux iwlwifi's fw/file.h and pcie/ctxt-info.c.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi.hpp"

namespace ax::IntelWifi {
namespace {
constexpr size_t tlv_file_header = 88, tlv_header = 8;
constexpr uint32_t tlv_magic = 0x0a4c5749;
constexpr uint32_t tlv_runtime_section = 19, tlv_init_section = 20, tlv_phy_sku = 23,
                   tlv_secure_runtime = 24, tlv_secure_init = 25, tlv_cpu_count = 27,
                   tlv_paging_size = 32, tlv_firmware_version = 36, tlv_command_versions = 48;
constexpr uint32_t cpu_separator = 0xffffcccc, paging_separator = 0xaaaabbbb;

uint32_t load32(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) |
           (uint32_t(bytes[3]) << 24);
}

bool append_section(FirmwareImage& image, Region& region, const uint8_t* payload, uint32_t size) {
    if (size <= sizeof(uint32_t))
        return false;
    const uint32_t offset = load32(payload);
    auto& sections = image.regions[region];
    if (offset == cpu_separator || offset == paging_separator) {
        if (size != 8 || !sections.count)
            return false;
        if (offset == cpu_separator && region == lmac) {
            region = umac;
            return true;
        }
        if (offset == paging_separator && region == umac) {
            region = paging;
            return true;
        }
        return false;
    }
    if (sections.count == max_sections || size - sizeof(uint32_t) > max_section_bytes ||
        size - sizeof(uint32_t) > UINT32_MAX - offset)
        return false;
    sections.sections[sections.count++] = {payload + sizeof(uint32_t),
                                           size - uint32_t(sizeof(uint32_t))};
    return true;
}
} // namespace

const char* parse_firmware(const uint8_t* bytes, size_t size, FirmwareImage& output) {
    if (!bytes || size < tlv_file_header || size > max_firmware_bytes || load32(bytes) ||
        load32(bytes + 4) != tlv_magic)
        return "invalid TLV header";

    FirmwareImage image{};
    auto region = lmac;
    bool seen_version = false, seen_cpu_count = false, seen_paging_size = false, seen_alive = false;
    bool seen_nvm = false, seen_phy_sku = false, seen_scan_config = false;
    for (size_t cursor = tlv_file_header; cursor < size;) {
        if (size - cursor < tlv_header)
            return "truncated TLV header";
        const uint32_t type = load32(bytes + cursor);
        const uint32_t length = load32(bytes + cursor + 4);
        cursor += tlv_header;
        const size_t padded = (size_t(length) + 3) & ~size_t(3);
        if (padded > size - cursor)
            return "truncated TLV data";
        const uint8_t* payload = bytes + cursor;
        switch (type) {
        case tlv_firmware_version:
            if (seen_version || length != sizeof(image.version))
                return "invalid firmware version record";
            seen_version = true;
            for (unsigned i = 0; i < 3; ++i)
                image.version[i] = load32(payload + 4 * i);
            break;
        case tlv_cpu_count:
            if (seen_cpu_count || length != 4 || load32(payload) != 2)
                return "invalid MAC CPU count";
            seen_cpu_count = true;
            break;
        case tlv_paging_size:
            if (seen_paging_size || length != 4)
                return "invalid paging record";
            seen_paging_size = true;
            image.paging_bytes = load32(payload);
            break;
        case tlv_phy_sku: {
            if (seen_phy_sku || length != 4)
                return "invalid firmware PHY SKU";
            seen_phy_sku = true;
            const auto phy = load32(payload);
            image.antennas = {uint8_t((phy >> 16) & 0xf), uint8_t((phy >> 20) & 0xf)};
            break;
        }
        case tlv_command_versions:
            if (length % 4)
                return "invalid firmware command versions";
            for (unsigned i = 0; i < length; i += 4) {
                if (payload[i] == 1 && !payload[i + 1]) {
                    if (seen_alive)
                        return "duplicate firmware ALIVE version";
                    seen_alive = true;
                    image.alive_version = payload[i + 3];
                } else if (payload[i] == 2 && payload[i + 1] == 12) {
                    if (seen_nvm)
                        return "duplicate firmware NVM version";
                    seen_nvm = true;
                    image.nvm_version = payload[i + 3];
                } else if (payload[i] == 0xc && payload[i + 1] == 1) {
                    if (seen_scan_config)
                        return "duplicate firmware scan configuration version";
                    seen_scan_config = true;
                    image.scan_config_version = payload[i + 2];
                }
            }
            break;
        case tlv_runtime_section:
            if (!append_section(image, region, payload, length))
                return "invalid firmware section";
            break;
        case tlv_init_section:
        case tlv_secure_runtime:
        case tlv_secure_init:
            return "unsupported firmware image layout";
        }
        cursor += padded;
    }
    if (!seen_version || image.version[0] != firmware_api || load32(bytes + 72) != firmware_api)
        return "incompatible firmware API";
    const auto& pages = image.regions[paging];
    if (!seen_cpu_count || region != paging || pages.count < 2 || !seen_paging_size)
        return "incomplete firmware section groups";

    // The first paging section carries the signature. Only the following sections count as pages.
    size_t paging_data = 0;
    for (unsigned i = 1; i < pages.count; ++i) {
        const uint32_t length = pages.sections[i].size;
        if (length % page_size)
            return "unaligned paging data";
        paging_data += length;
    }
    if (paging_data != image.paging_bytes)
        return "paging size mismatch";
    output = image;
    return nullptr;
}
} // namespace ax::IntelWifi
