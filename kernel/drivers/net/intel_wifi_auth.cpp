// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_auth.cpp
 * @brief   Encode an AX201 management TX and decode its authentication result.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Uses the firmware TX v9, TX reply v7, and session protection v1 layouts.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_auth.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned header_bytes = 24, body_bytes = 6;
constexpr unsigned first_tb_bytes = 20, second_tb_bytes = 4 + header_bytes;
constexpr unsigned second_tb_offset = 64, third_tb_offset = 128;

uint16_t read16(const uint8_t* data) {
    return uint16_t(data[0] | (unsigned(data[1]) << 8));
}

uint32_t read32(const uint8_t* data) {
    return read16(data) | (uint32_t(read16(data + 2)) << 16);
}

uint8_t hex_digit(char value) {
    if (value >= '0' && value <= '9')
        return uint8_t(value - '0');
    value |= 0x20;
    return value >= 'a' && value <= 'f' ? uint8_t(value - 'a' + 10) : 0xff;
}

uint16_t transmit_sequence(PeerQueue queue) {
    return uint16_t(((queue.id & 31) << 8) |
                    (queue.write_pointer & (management_queue_entries - 1)));
}
} // namespace

bool parse_authentication_target(const char* text, AuthenticationTarget& target) {
    if (!text || strlen(text) != 17)
        return false;
    AuthenticationTarget parsed;
    uint8_t bits = 0;
    for (unsigned i = 0; i < sizeof(parsed.bssid); ++i) {
        const unsigned offset = 3 * i;
        const auto high = hex_digit(text[offset]), low = hex_digit(text[offset + 1]);
        if (high > 15 || low > 15 || (i < 5 && text[offset + 2] != ':'))
            return false;
        parsed.bssid[i] = uint8_t(high << 4 | low);
        bits |= parsed.bssid[i];
    }
    if (!bits || (parsed.bssid[0] & 1))
        return false;
    target = parsed;
    return true;
}

void prepare_session_protection(bool start, uint8_t (&wire)[session_protection_bytes]) {
    memset(wire, 0, sizeof(wire));
    wire[4] = start ? 1 : 3; // Add or remove association protection for MAC context 0.
    if (start) {
        wire[12] = 0x84; // 900 TU.
        wire[13] = 3;
    }
}

AuthEvent observe_session_protection(const FirmwarePacket& packet) {
    if (packet.group != 3 || packet.opcode != 0xfb || !(packet.sequence & 0x8000))
        return AuthEvent::unrelated;
    if (!packet.payload || packet.length != 16)
        return AuthEvent::malformed;
    const auto* data = packet.payload;
    if (read32(data) || read32(data + 12))
        return AuthEvent::unrelated;
    const auto status = read32(data + 4), start = read32(data + 8);
    if (status > 1 || start > 1)
        return AuthEvent::malformed;
    return !status ? AuthEvent::denied : start ? AuthEvent::accepted : AuthEvent::ended;
}

uint32_t authentication_rate(const uint8_t* ies, unsigned bytes, bool high_band, uint8_t antennas) {
    antennas &= 7;
    if (!antennas || !ies)
        return 0;
    unsigned basic = 0xff, supported = 0xff;
    unsigned basic_index = 0, supported_index = 0;
    for (unsigned offset = 0; offset < bytes;) {
        if (bytes - offset < 2)
            return 0;
        const auto type = ies[offset], length = ies[offset + 1];
        offset += 2;
        if (length > bytes - offset)
            return 0;
        if (type == 1 || type == 50) {
            for (unsigned i = 0; i < length; ++i) {
                const uint8_t entry = ies[offset + i], rate = entry & 0x7f;
                const unsigned first_index = high_band ? scan_cck_rate_count : 0;
                for (unsigned j = first_index; j < sizeof(scan_legacy_rates); ++j) {
                    if (scan_legacy_rates[j] != rate)
                        continue;
                    if (rate < supported) {
                        supported = rate;
                        supported_index = j;
                    }
                    if ((entry & 0x80) && rate < basic) {
                        basic = rate;
                        basic_index = j;
                    }
                }
            }
        }
        offset += length;
    }
    if (supported == 0xff)
        return 0;
    const unsigned index = basic == 0xff ? supported_index : basic_index;
    const unsigned antenna = antennas & (0u - antennas);
    const unsigned rate =
        index < scan_cck_rate_count ? index : 0x100 | (index - scan_cck_rate_count);
    return (antenna << 14) | rate;
}

bool valid_authentication_dma(const AuthenticationDma& dma) {
    return dma.ring && dma.byte_counts && dma.payload && dma.address &&
           !(dma.address & (page_size - 1)) &&
           Dma::fits(dma.address, authentication_dma_bytes, Dma::pci);
}

void prepare_authentication_mac(const uint8_t (&station)[6], const AccessPoint& peer,
                                uint8_t (&command)[mac_context_bytes]) {
    prepare_scan_station(station, command);
    command[4] = 2; // Modify the MAC context with the selected BSSID.
    memcpy(command + 24, peer.bssid, sizeof(peer.bssid));
    command[116] = uint8_t(peer.beacon_interval_tu);
    command[117] = uint8_t(peer.beacon_interval_tu >> 8);
    command[132] = 1; // Listen interval in beacons.
}

bool prepare_authentication_frame(const AuthenticationDma& dma, PeerQueue queue, uint32_t rate,
                                  const uint8_t (&station)[6], const AccessPoint& peer) {
    if (!valid_authentication_dma(dma) || !rate || !queue.id || queue.id >= 512)
        return false;
    memset(dma.payload, 0, authentication_dma_bytes);
    const auto sequence = transmit_sequence(queue);
    dma.payload[0] = 0x1c;
    dma.payload[2] = uint8_t(sequence);
    dma.payload[3] = uint8_t(sequence >> 8);
    dma.payload[4] = header_bytes + body_bytes;
    dma.payload[7] = header_bytes / 2; // Offload MAC header size in words.
    dma.payload[8] = 3;                // Use the command rate and disable encryption.

    auto* rate_field = dma.payload + second_tb_offset;
    for (unsigned i = 0; i < 4; ++i)
        rate_field[i] = uint8_t(rate >> (8 * i));
    auto* header = rate_field + 4;
    header[0] = 0xb0;
    memcpy(header + 4, peer.bssid, sizeof(peer.bssid));
    memcpy(header + 10, station, sizeof(station));
    memcpy(header + 16, peer.bssid, sizeof(peer.bssid));
    dma.payload[third_tb_offset + 2] = 1; // Open-system authentication, transaction one.

    const unsigned slot = queue.write_pointer & (management_queue_entries - 1);
    auto& descriptor = dma.ring[slot];
    descriptor = {};
    descriptor.buffer_count = 3;
    descriptor.buffers[0] = {first_tb_bytes, dma.address};
    descriptor.buffers[1] = {second_tb_bytes, dma.address + second_tb_offset};
    descriptor.buffers[2] = {body_bytes, dma.address + third_tb_offset};
    dma.byte_counts[slot] = (header_bytes + body_bytes + 3) / 4;
    return true;
}

AuthEvent observe_authentication_tx(const FirmwarePacket& packet, PeerQueue queue) {
    if (packet.group || packet.opcode != 0x1c || packet.sequence != transmit_sequence(queue))
        return AuthEvent::unrelated;
    if (!packet.payload || packet.length < 48)
        return AuthEvent::malformed;
    const auto* data = packet.payload;
    if (read16(data + 36) != queue.id)
        return AuthEvent::unrelated;
    if (data[0] != 1 || uint8_t(read32(data + 44)) != uint8_t(queue.write_pointer + 1))
        return AuthEvent::malformed;
    const auto status = data[40];
    return status == 1 || status == 2 ? AuthEvent::accepted : AuthEvent::denied;
}

AuthEvent observe_authentication_reply(const FirmwarePacket& packet, const uint8_t (&station)[6],
                                       const AccessPoint& peer, uint8_t channel) {
    constexpr unsigned descriptor_bytes = 48;
    if (packet.group || packet.opcode != 0xc1 || !(packet.sequence & 0x8000) || !packet.payload ||
        packet.length < descriptor_bytes + header_bytes)
        return AuthEvent::unrelated;
    const auto* rx = packet.payload;
    const auto* frame = rx + descriptor_bytes;
    if ((rx[12] & 3) != 3 || (rx[3] & 0x20) || rx[34] != channel || frame[0] != 0xb0 ||
        (frame[1] & 0xc3) || memcmp(frame + 4, station, sizeof(station)) ||
        memcmp(frame + 10, peer.bssid, sizeof(peer.bssid)) ||
        memcmp(frame + 16, peer.bssid, sizeof(peer.bssid)))
        return AuthEvent::unrelated;
    const unsigned length = read16(rx);
    if (length < header_bytes + body_bytes || length > packet.length - descriptor_bytes)
        return AuthEvent::malformed;
    if (read16(frame + 24) || read16(frame + 26) != 2)
        return AuthEvent::unrelated;
    return read16(frame + 28) ? AuthEvent::denied : AuthEvent::accepted;
}
} // namespace ax::IntelWifi
