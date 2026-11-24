// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_scan.cpp
 * @brief   Encode an AX201 passive scan and collect access points from RX frames.
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
constexpr uint16_t channel_valid = 1, channel_radar = 1u << 4, channel_indoor = 1u << 5;
constexpr uint16_t force_passive = 1u << 11, report_beacons = 1u << 1;
constexpr unsigned request_header = 8, general_bytes = 36, channel_header = 4;
constexpr unsigned channel_bytes = 8, schedule_bytes = 12, probe_bytes = 1344;
constexpr unsigned channel_params = request_header + general_bytes;
constexpr unsigned first_channel = channel_params + channel_header;
constexpr unsigned schedule = first_channel + channel_bytes * channel_capacity;
constexpr unsigned beacon_header = 36;
static_assert(schedule + schedule_bytes + probe_bytes == passive_request_bytes);
static_assert(passive_request_bytes + 8 <= command_slot_bytes);
static_assert(sizeof(channel_order) == scan_channel_limit);

uint16_t read16(const uint8_t* data) {
    return uint16_t(data[0] | (uint16_t(data[1]) << 8));
}

bool station_address_valid(const uint8_t* address) {
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < 6; ++i)
        nonzero |= address[i];
    return nonzero && !(address[0] & 1);
}

bool parse_beacon_elements(const uint8_t* frame, unsigned length, AccessPoint& point,
                           uint8_t& advertised_channel) {
    constexpr unsigned ht_operation_bytes = 22;
    bool seen_ssid = false;
    uint8_t ds_channel = 0, ht_channel = 0;
    for (unsigned offset = beacon_header; offset < length;) {
        if (length - offset < 2)
            return false;
        const auto id = frame[offset], bytes = frame[offset + 1];
        offset += 2;
        if (bytes > length - offset)
            return false;
        if (!id) {
            if (seen_ssid || bytes > sizeof(point.ssid))
                return false;
            seen_ssid = true;
            uint8_t nonzero = 0;
            for (unsigned i = 0; i < bytes; ++i)
                nonzero |= frame[offset + i];
            if (nonzero) {
                memcpy(point.ssid, frame + offset, bytes);
                point.ssid_length = bytes;
            }
        } else if (id == 3 && bytes == 1 && !ds_channel) {
            ds_channel = frame[offset];
        } else if (id == 61 && bytes >= ht_operation_bytes && !ht_channel) {
            ht_channel = frame[offset];
        }
        offset += bytes;
    }
    advertised_channel = ds_channel ? ds_channel : ht_channel;
    return seen_ssid;
}

bool scan_selected_channel(const PassiveScan& scan, uint8_t channel) {
    for (unsigned i = 0; i < scan.channel_count; ++i)
        if (scan.channels[i] == channel)
            return true;
    return false;
}

uint16_t channel_frequency(uint8_t channel) {
    if (channel < 14)
        return uint16_t(2407 + 5 * channel);
    if (channel == 14)
        return 2484;
    return uint16_t(5000 + 5 * channel);
}

void store_elements(PassiveScan& scan, unsigned index, bool probe, const uint8_t* elements,
                    uint16_t bytes) {
    if (!scan.elements)
        return;
    auto& point = scan.access_points[index];
    auto& record = scan.elements->records[index];
    if (probe) {
        memcpy(record.probe, elements, bytes);
        point.probe_ie_bytes = bytes;
    } else {
        memcpy(record.beacon, elements, bytes);
        point.beacon_ie_bytes = bytes;
    }
}

void store_access_point(PassiveScan& scan, const AccessPoint& point, const uint8_t* elements,
                        uint16_t element_bytes) {
    for (unsigned i = 0; i < scan.access_point_count; ++i) {
        auto& seen = scan.access_points[i];
        if (seen.frequency_mhz != point.frequency_mhz || memcmp(seen.bssid, point.bssid, 6))
            continue;
        if (seen.ssid_length && point.ssid_length &&
            (seen.ssid_length != point.ssid_length ||
             memcmp(seen.ssid, point.ssid, seen.ssid_length)))
            continue;
        const auto best_signal = max(seen.signal_dbm, point.signal_dbm);
        // Keep the name when a hidden beacon follows a named probe response.
        if ((!seen.ssid_length || point.ssid_length) &&
            (!seen.probe_response || point.probe_response || !seen.ssid_length)) {
            const auto beacon_bytes = seen.beacon_ie_bytes;
            const auto probe_bytes = seen.probe_ie_bytes;
            seen = point;
            seen.beacon_ie_bytes = beacon_bytes;
            seen.probe_ie_bytes = probe_bytes;
        }
        if (!point.probe_response || point.ssid_length || !seen.probe_ie_bytes || !seen.ssid_length)
            store_elements(scan, i, point.probe_response, elements, element_bytes);
        seen.signal_dbm = best_signal;
        return;
    }
    if (scan.access_point_count == sizeof(scan.access_points) / sizeof(scan.access_points[0])) {
        scan.access_points_truncated = true;
        return;
    }
    const unsigned index = scan.access_point_count++;
    scan.access_points[index] = point;
    store_elements(scan, index, point.probe_response, elements, element_bytes);
}

void observe_beacon(PassiveScan& scan, const FirmwarePacket& packet) {
    constexpr unsigned descriptor_bytes = 48, status_offset = 12, channel_offset = 34;
    constexpr unsigned energy_offset = 32, bssid_offset = 16, interval_offset = 32,
                       capability_offset = 34;
    if (packet.length < descriptor_bytes || !packet.payload)
        return;
    const auto* data = packet.payload;
    const auto frame_bytes = read16(data);
    // CRC and overrun status must both be good. Management frames need no padding.
    if ((data[status_offset] & 3) != 3 || (data[3] & 0x20) || frame_bytes < beacon_header + 2 ||
        frame_bytes > packet.length - descriptor_bytes ||
        frame_bytes > beacon_header + scan_ie_capacity)
        return;
    const uint8_t receive_channel = data[channel_offset];
    const auto* frame = data + descriptor_bytes;
    if (!scan_selected_channel(scan, receive_channel) || (frame[0] != 0x80 && frame[0] != 0x50) ||
        !station_address_valid(frame + bssid_offset))
        return;

    AccessPoint point;
    uint8_t advertised_channel = 0;
    if (!parse_beacon_elements(frame, frame_bytes, point, advertised_channel))
        return;
    uint8_t channel = receive_channel;
    if (advertised_channel && advertised_channel != channel) {
        const bool low_band_rx = channel <= low_band_channels;
        if ((advertised_channel <= low_band_channels) == low_band_rx &&
            scan_selected_channel(scan, advertised_channel))
            channel = advertised_channel;
        else if (low_band_rx)
            return;
    }
    memcpy(point.bssid, frame + bssid_offset, sizeof(point.bssid));
    point.frequency_mhz = channel_frequency(channel);
    point.beacon_interval_tu = read16(frame + interval_offset);
    point.capability = read16(frame + capability_offset);
    point.probe_response = frame[0] == 0x50;
    if (channel == receive_channel) {
        for (unsigned i = 0; i < 2; ++i) {
            const uint8_t attenuation = data[energy_offset + i];
            if (attenuation && attenuation < 128)
                point.signal_dbm = max(point.signal_dbm, int16_t(-attenuation));
        }
    }
    store_access_point(scan, point, frame + beacon_header, uint16_t(frame_bytes - beacon_header));
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

ScanChannelList scan_channel_list(const NvmInfo& nvm, const RegulatoryProfile& profile) {
    ScanChannelList list;
    for (unsigned i = 0; i < profile.channel_slots && i < sizeof(channel_order); ++i) {
        if (!(nvm.bands & (i < low_band_channels ? 1 : 2)))
            continue;
        const uint8_t channel = channel_order[i];
        const uint16_t flags = profile.flags[i];
        list.entries[list.count++] = {
            channel_frequency(channel),   channel,
            bool(flags & channel_valid),  bool(flags & channel_radar),
            bool(flags & channel_indoor),
        };
    }
    return list;
}

bool prepare_passive_scan(const ScanChannelList& list, PassiveScan& scan,
                          uint8_t (&request)[passive_request_bytes], uint32_t id,
                          uint64_t channels) {
    memset(request, 0, sizeof(request));
    auto* const elements = scan.elements;
    scan = PassiveScan{};
    scan.elements = elements;
    scan.id = id;
    for (unsigned i = 0; i < 4; ++i)
        request[i] = uint8_t(id >> (8 * i));
    for (unsigned i = 0; i < list.count; ++i) {
        if (!list.entries[i].allowed || !(channels & (uint64_t(1) << i)))
            continue;
        const uint8_t channel = list.entries[i].number;
        auto* descriptor = request + first_channel + channel_bytes * scan.channel_count;
        descriptor[4] = channel;
        descriptor[5] = channel <= low_band_channels ? low_band : high_band;
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
    if (read16(packet.payload) != (scan.id & 0xffff) ||
        read16(packet.payload + 2) != (scan.id >> 16))
        return;
    const uint8_t status = packet.payload[6];
    if (status == 1)
        scan.status = PassiveScan::Status::complete;
    else if (status == 2)
        scan.status = PassiveScan::Status::aborted;
    else
        scan.status = PassiveScan::Status::malformed;
}

void PassiveScanExchange::restart(uint16_t new_sequence, uint64_t now_ms) {
    sequence = new_sequence;
    phase_start = now_ms;
    result = ScanOutcome::pending;
    accepted = false;
}

void PassiveScanExchange::expire(uint64_t now_ms) {
    const unsigned timeout_ms = accepted ? 12000 : 2000;
    if (result == ScanOutcome::pending && now_ms - phase_start >= timeout_ms)
        result = accepted ? ScanOutcome::completion_timeout : ScanOutcome::reply_timeout;
}

void PassiveScanExchange::observe(const FirmwarePacket& packet, uint64_t now_ms) {
    expire(now_ms);
    if (result != ScanOutcome::pending)
        return;
    observe_passive_scan(scan, packet);
    if (!accepted && packet.sequence == sequence) {
        if (packet.group == 0 && packet.opcode == 2) {
            result = ScanOutcome::rejected;
            return;
        }
        if (packet.group == 1 && packet.opcode == 0xd) {
            accepted = true;
            phase_start = now_ms;
        }
    }
    if (!accepted)
        return;
    switch (scan.status) {
    case PassiveScan::Status::pending:
        break;
    case PassiveScan::Status::complete:
        result = ScanOutcome::complete;
        break;
    case PassiveScan::Status::aborted:
        result = ScanOutcome::aborted;
        break;
    case PassiveScan::Status::malformed:
        result = ScanOutcome::malformed;
        break;
    }
}

void PassiveScanExchange::receive_failed() {
    if (result == ScanOutcome::pending)
        result = ScanOutcome::receive_failed;
}
} // namespace ax::IntelWifi
