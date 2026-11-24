// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_scan.cpp
 * @brief   Encode an AX201 passive scan and count access points from RX frames.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Layouts follow Linux iwlwifi fw/api/scan.h, fw/api/mac.h and fw/api/rx.h.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_scan.hpp"

namespace ax::IntelWifi {
namespace {
// The extended NVM profiles for QuZ put 2.4 GHz first, then 5 GHz.
constexpr uint8_t channel_order[]{
    1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  36,  40,  44,
    48,  52,  56,  60,  64,  68,  72,  76,  80,  84,  88,  92,  96,  100, 104, 108, 112,
    116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177, 181,
};

constexpr unsigned low_band_channels = 14, channel_capacity = 67;
constexpr uint8_t low_band = 1, high_band = 0;
constexpr uint16_t force_passive = 1u << 11, report_beacons = 1u << 1;
constexpr unsigned request_header = 8, general_bytes = 36, channel_header = 4;
constexpr unsigned channel_bytes = 8, schedule_bytes = 12, probe_bytes = 1344;
constexpr unsigned channel_params = request_header + general_bytes;
constexpr unsigned first_channel = channel_params + channel_header;
constexpr unsigned schedule = first_channel + channel_bytes * channel_capacity;
static_assert(schedule + schedule_bytes + probe_bytes == passive_request_bytes);
static_assert(passive_request_bytes + 8 <= command_slot_bytes);
static_assert(sizeof(channel_order) == sizeof(PassiveScan::channels));

uint16_t read16(const uint8_t* data) {
    return uint16_t(data[0] | (uint16_t(data[1]) << 8));
}

bool station_address_valid(const uint8_t* address) {
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < 6; ++i)
        nonzero |= address[i];
    return nonzero && !(address[0] & 1);
}

bool beacon_has_ssid(const uint8_t* frame, unsigned length) {
    constexpr unsigned beacon_header = 36;
    bool seen_ssid = false;
    for (unsigned offset = beacon_header; offset < length;) {
        if (length - offset < 2)
            return false;
        const auto id = frame[offset], bytes = frame[offset + 1];
        offset += 2;
        if (bytes > length - offset)
            return false;
        if (!id) {
            if (seen_ssid || bytes > 32)
                return false;
            seen_ssid = true;
        }
        offset += bytes;
    }
    return seen_ssid;
}

void observe_beacon(PassiveScan& scan, const FirmwarePacket& packet) {
    constexpr unsigned descriptor_bytes = 48, status_offset = 12, channel_offset = 34;
    constexpr unsigned bssid_offset = 16;
    if (packet.length < descriptor_bytes || !packet.payload)
        return;
    const auto* data = packet.payload;
    const auto frame_bytes = read16(data);
    // CRC and overrun status must both be good. Management frames need no padding.
    if ((data[status_offset] & 3) != 3 || (data[3] & 0x20) || frame_bytes < 38 ||
        frame_bytes > packet.length - descriptor_bytes)
        return;
    const uint8_t channel = data[channel_offset];
    bool selected = false;
    for (unsigned i = 0; i < scan.channel_count; ++i)
        selected |= scan.channels[i] == channel;
    const auto* frame = data + descriptor_bytes;
    if (!selected || (frame[0] != 0x80 && frame[0] != 0x50) ||
        !station_address_valid(frame + bssid_offset) || !beacon_has_ssid(frame, frame_bytes))
        return;
    for (unsigned i = 0; i < scan.access_point_count; ++i)
        if (!memcmp(scan.access_points[i], frame + bssid_offset, 6))
            return;
    if (scan.access_point_count == sizeof(scan.access_points) / sizeof(scan.access_points[0])) {
        scan.access_points_truncated = true;
        return;
    }
    memcpy(scan.access_points[scan.access_point_count++], frame + bssid_offset, 6);
}
} // namespace

bool decode_station_address(uint32_t high, uint32_t low, uint8_t (&address)[6]) {
    for (unsigned i = 0; i < 4; ++i)
        address[i] = uint8_t(high >> (24 - i * 8));
    address[4] = uint8_t(low >> 8);
    address[5] = uint8_t(low);
    return station_address_valid(address);
}

void prepare_scan_station(const uint8_t (&address)[6], uint8_t (&command)[mac_context_bytes]) {
    memset(command, 0, sizeof(command));
    command[4] = 1; // Add station MAC context 0 on TSF timer 0.
    command[8] = 5; // Infrastructure station.
    memcpy(command + 16, address, sizeof(address));
    memset(command + 24, 0xff, 6);
    command[32] = 0x0f;                  // CCK basic rates.
    command[36] = 0x15;                  // OFDM basic rates.
    command[52] = (1u << 2) | (1u << 6); // Receive group frames and beacons.
}

bool prepare_passive_scan(const NvmInfo& nvm, const RegulatoryProfile& profile, PassiveScan& scan,
                          uint8_t (&request)[passive_request_bytes]) {
    memset(request, 0, sizeof(request));
    scan = {};
    for (unsigned i = 0; i < profile.channel_slots && i < sizeof(channel_order); ++i) {
        const bool low = i < low_band_channels;
        if (!(profile.flags[i] & 1) || !(nvm.bands & (low ? 1 : 2)))
            continue;
        const uint8_t channel = channel_order[i];
        auto* descriptor = request + first_channel + channel_bytes * scan.channel_count;
        descriptor[4] = channel;
        descriptor[5] = low ? low_band : high_band;
        descriptor[6] = 1; // One pass on each channel.
        scan.channels[scan.channel_count++] = channel;
    }
    if (!scan.channel_count)
        return false;
    const uint16_t scan_flags = force_passive | report_beacons;
    auto* const general = request + request_header;
    request[4] = 6; // Out-of-channel priority for an immediate scan.
    general[0] = uint8_t(scan_flags);
    general[1] = uint8_t(scan_flags >> 8);
    general[28] = 6;
    general[32] = general[33] = 110; // Passive dwell in TU.
    request[channel_params + 1] = scan.channel_count;
    request[schedule + 2] = 1;
    return true;
}

void observe_passive_scan(PassiveScan& scan, const FirmwarePacket& packet) {
    if (scan.status != PassiveScan::Status::pending || packet.group || !(packet.sequence & 0x8000))
        return;
    if (packet.opcode == 0xc1) {
        observe_beacon(scan, packet);
        return;
    }
    if (packet.opcode != 0xf)
        return;
    if (packet.length != 16 || !packet.payload) {
        scan.status = PassiveScan::Status::malformed;
        return;
    }
    constexpr uint32_t id = passive_scan_id;
    if (read16(packet.payload) != (id & 0xffff) || read16(packet.payload + 2) != (id >> 16))
        return;
    const uint8_t status = packet.payload[6];
    if (status == 1)
        scan.status = PassiveScan::Status::complete;
    else if (status == 2)
        scan.status = PassiveScan::Status::aborted;
    else
        scan.status = PassiveScan::Status::malformed;
}
} // namespace ax::IntelWifi
