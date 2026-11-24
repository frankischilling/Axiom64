// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_auth.cpp
 * @brief   Encode management frames and decode AX201 firmware and peer replies.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Uses the firmware TX v9, TX reply v7, and session protection v1 layouts.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_auth.hpp"
#include "mm/dma.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned header_bytes = 24, body_bytes = 6;
constexpr unsigned first_tb_bytes = 20, second_tb_bytes = 4 + header_bytes;
constexpr unsigned second_tb_offset = 64, third_tb_offset = 128;
static_assert(third_tb_offset + association_body_bytes <= authentication_dma_bytes);
constexpr uint8_t snap_prefix[]{0xaa, 0xaa, 3, 0, 0};
constexpr unsigned snap_bytes = 8, ethernet_bytes = 14;
constexpr uint8_t arp_header[]{0, 1, 8, 0, 6, 4};

bool uses_bridge_tunnel(uint16_t type) {
    return type == 0x80f3 || type == 0x8137; // AppleTalk ARP and IPX.
}

uint16_t read16(const uint8_t* data) {
    return uint16_t(data[0] | (unsigned(data[1]) << 8));
}

uint32_t read32(const uint8_t* data) {
    return read16(data) | (uint32_t(read16(data + 2)) << 16);
}

void write32(uint8_t* data, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        data[i] = uint8_t(value >> (8 * i));
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

bool parse_probe_ipv4(const char*& cursor, uint32_t& address) {
    address = 0;
    for (unsigned octet = 0; octet < 4; ++octet) {
        unsigned value = 0, digits = 0;
        while (*cursor >= '0' && *cursor <= '9') {
            if (++digits > 3)
                return false;
            value = value * 10 + unsigned(*cursor++ - '0');
        }
        if (!digits || value > 255)
            return false;
        address = (address << 8) | value;
        if (octet < 3) {
            if (*cursor != '.')
                return false;
            ++cursor;
        }
    }
    return ip4::unicast(address) && (address >> 24) != 127;
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

bool parse_data_probe_target(const char* text, AuthenticationTarget& target) {
    if (!text || strlen(text) < 33 || text[17] != ',')
        return false;
    char address[18]{};
    memcpy(address, text, 17);
    AuthenticationTarget parsed;
    const char* cursor = text + 18;
    if (!parse_authentication_target(address, parsed) ||
        !parse_probe_ipv4(cursor, parsed.source_ipv4) || *cursor != ',' ||
        !parse_probe_ipv4(++cursor, parsed.peer_ipv4) || *cursor ||
        parsed.source_ipv4 == parsed.peer_ipv4)
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

bool observe_association_beacon(const FirmwarePacket& packet, const AccessPoint& peer,
                                uint8_t channel, AssociationTiming& timing) {
    constexpr unsigned descriptor_bytes = 48, beacon_header = 36;
    if (packet.group || packet.opcode != 0xc1 || !(packet.sequence & 0x8000) || !packet.payload ||
        packet.length < descriptor_bytes + beacon_header)
        return false;
    const auto* rx = packet.payload;
    const auto* frame = rx + descriptor_bytes;
    const unsigned length = read16(rx);
    if ((rx[12] & 3) != 3 || (rx[3] & 0x20) || rx[34] != channel || frame[0] != 0x80 ||
        (frame[1] & 0xc3) || memcmp(frame + 10, peer.bssid, sizeof(peer.bssid)) ||
        memcmp(frame + 16, peer.bssid, sizeof(peer.bssid)) || length < beacon_header ||
        length > packet.length - descriptor_bytes)
        return false;

    const uint16_t interval = read16(frame + 32);
    if (!interval)
        return false;
    uint8_t count = 0, period = 0;
    for (unsigned offset = beacon_header; offset < length;) {
        if (length - offset < 2)
            return false;
        const auto type = frame[offset], size = frame[offset + 1];
        offset += 2;
        if (size > length - offset)
            return false;
        if (type == 5) {
            if (size < 4 || period || !frame[offset + 1] || frame[offset] >= frame[offset + 1])
                return false;
            count = frame[offset];
            period = frame[offset + 1];
        }
        offset += size;
    }
    if (!period)
        return false;
    timing = {uint64_t(read32(frame + 24)) | (uint64_t(read32(frame + 28)) << 32), read32(rx + 36),
              interval, count, period};
    return true;
}

void prepare_associated_mac(const uint8_t (&station)[6], const AccessPoint& peer, uint16_t aid,
                            const AssociationTiming& timing,
                            uint8_t (&command)[mac_context_bytes]) {
    prepare_authentication_mac(station, peer, command);
    // The two clocks share a microsecond unit. The device timer wraps at 32 bits.
    const uint64_t to_dtim = uint64_t(timing.dtim_count) * timing.beacon_interval_tu * 1024;
    const uint64_t dtim_tsf = timing.beacon_tsf + to_dtim;
    command[52] &= ~(1u << 6); // Stop forwarding every beacon after synchronization.
    write32(command + 100, 1);
    write32(command + 104, timing.receive_time + uint32_t(to_dtim));
    write32(command + 108, uint32_t(dtim_tsf));
    write32(command + 112, uint32_t(dtim_tsf >> 32));
    write32(command + 116, timing.beacon_interval_tu);
    write32(command + 124, uint32_t(timing.beacon_interval_tu) * timing.dtim_period);
    write32(command + 136, aid);
    write32(command + 140, timing.receive_time);
}

bool prepare_association_request(const AccessPoint& peer, const uint8_t* ies, unsigned bytes,
                                 bool high_band, AssociationRequest& request) {
    request.length = 0;
    if ((peer.capability & 0x13) != 1 || !peer.ssid_length ||
        peer.ssid_length > sizeof(peer.ssid) || !ies)
        return false;

    const unsigned first_rate = high_band ? scan_cck_rate_count : 0;
    unsigned rates = 0;
    for (unsigned offset = 0; offset < bytes;) {
        if (bytes - offset < 2)
            return false;
        const unsigned id = ies[offset], length = ies[offset + 1];
        offset += 2;
        if (length > bytes - offset || id == 48)
            return false;
        const auto* data = ies + offset;
        const uint8_t wpa_type[]{0, 0x50, 0xf2, 1};
        if (id == 221 && length >= sizeof(wpa_type) && !memcmp(data, wpa_type, sizeof(wpa_type)))
            return false;
        if (id == 1 || id == 50) {
            for (unsigned i = 0; i < length; ++i) {
                unsigned index = first_rate;
                while (index < sizeof(scan_legacy_rates) &&
                       scan_legacy_rates[index] != (data[i] & 0x7f))
                    ++index;
                if (index < sizeof(scan_legacy_rates))
                    rates |= 1u << index;
                else if (data[i] & 0x80)
                    return false;
            }
        }
        offset += length;
    }
    if (!rates)
        return false;

    uint8_t supported[sizeof(scan_legacy_rates)];
    unsigned count = 0;
    for (unsigned i = first_rate; i < sizeof(scan_legacy_rates); ++i)
        if (rates & (1u << i))
            supported[count++] = scan_legacy_rates[i];

    auto* body = request.body;
    const auto capability = peer.capability & 0x0421; // ESS, short preamble, short slot.
    body[0] = uint8_t(capability);
    body[1] = uint8_t(capability >> 8);
    body[2] = 1;
    body[3] = 0;
    body[4] = 0; // SSID.
    body[5] = peer.ssid_length;
    memcpy(body + 6, peer.ssid, peer.ssid_length);
    unsigned end = 6 + peer.ssid_length;
    const unsigned initial = min(count, 8u);
    body[end++] = 1; // Supported Rates.
    body[end++] = uint8_t(initial);
    memcpy(body + end, supported, initial);
    end += initial;
    if (count > initial) {
        body[end++] = 50; // Extended Supported Rates.
        body[end++] = uint8_t(count - initial);
        memcpy(body + end, supported + initial, count - initial);
        end += count - initial;
    }
    request.length = end;
    return true;
}

static bool prepare_station_frame(const AuthenticationDma& dma, PeerQueue queue, uint32_t rate,
                                  const uint8_t (&header)[header_bytes], uint16_t frame_sequence,
                                  const uint8_t* body, unsigned bytes,
                                  const uint8_t* prefix = nullptr, unsigned prefix_bytes = 0) {
    const unsigned length = bytes + prefix_bytes;
    if (!valid_authentication_dma(dma) || !rate || !queue.id || queue.id >= 512 || !length ||
        length > authentication_dma_bytes - third_tb_offset)
        return false;
    memset(dma.payload, 0, third_tb_offset);
    const auto sequence = transmit_sequence(queue);
    dma.payload[0] = 0x1c;
    dma.payload[2] = uint8_t(sequence);
    dma.payload[3] = uint8_t(sequence >> 8);
    dma.payload[4] = uint8_t(header_bytes + length);
    dma.payload[5] = uint8_t((header_bytes + length) >> 8);
    dma.payload[7] = header_bytes / 2; // Offload MAC header size in words.
    dma.payload[8] = 3;                // Use the command rate and disable encryption.

    auto* rate_field = dma.payload + second_tb_offset;
    for (unsigned i = 0; i < 4; ++i)
        rate_field[i] = uint8_t(rate >> (8 * i));
    memcpy(rate_field + 4, header, sizeof(header));
    rate_field[4 + 22] = uint8_t(frame_sequence << 4);
    rate_field[4 + 23] = uint8_t(frame_sequence >> 4);
    if (prefix_bytes)
        memcpy(dma.payload + third_tb_offset, prefix, prefix_bytes);
    memcpy(dma.payload + third_tb_offset + prefix_bytes, body, bytes);

    const unsigned slot = queue.write_pointer & (management_queue_entries - 1);
    auto& descriptor = dma.ring[slot];
    descriptor = {};
    descriptor.buffer_count = 3;
    descriptor.buffers[0] = {first_tb_bytes, dma.address};
    descriptor.buffers[1] = {second_tb_bytes, dma.address + second_tb_offset};
    descriptor.buffers[2] = {uint16_t(length), dma.address + third_tb_offset};
    dma.byte_counts[slot] = uint16_t((header_bytes + length + 3) / 4);
    return true;
}

bool prepare_management_frame(const AuthenticationDma& dma, PeerQueue queue, uint32_t rate,
                              const uint8_t (&station)[6], const AccessPoint& peer,
                              ManagementFrame kind, const AssociationRequest& association,
                              uint16_t sequence) {
    constexpr uint8_t auth_body[]{0, 0, 1, 0, 0, 0};
    constexpr uint8_t leave_body[]{3, 0}; // Station is leaving.
    const uint8_t* body = auth_body;
    unsigned length = sizeof(auth_body);
    if (kind == ManagementFrame::associate) {
        body = association.body;
        length = association.length;
        if (length > sizeof(association.body))
            return false;
    } else if (kind == ManagementFrame::leave) {
        body = leave_body;
        length = sizeof(leave_body);
    }
    uint8_t header[header_bytes]{uint8_t(kind)};
    memcpy(header + 4, peer.bssid, sizeof(peer.bssid));
    memcpy(header + 10, station, sizeof(station));
    memcpy(header + 16, peer.bssid, sizeof(peer.bssid));
    return prepare_station_frame(dma, queue, rate, header, sequence, body, length);
}

bool prepare_station_data(const AuthenticationDma& dma, PeerQueue queue, uint32_t rate,
                          const uint8_t (&station)[6], const uint8_t (&bssid)[6],
                          const uint8_t* frame, size_t length, uint16_t sequence) {
    if (!frame || length < ethernet_bytes || length > station_frame_bytes ||
        memcmp(frame + 6, station, sizeof(station)))
        return false;
    const uint16_t type = ip4::get16(frame + 12);
    if (type < 1536 || (length > 1514 && type != 0x8100 && type != 0x88a8))
        return false;
    uint8_t header[header_bytes]{0x08, 0x01}; // Data frame headed to the distribution system.
    memcpy(header + 4, bssid, sizeof(bssid));
    memcpy(header + 10, station, sizeof(station));
    memcpy(header + 16, frame, sizeof(station));
    uint8_t snap[snap_bytes];
    memcpy(snap, snap_prefix, sizeof(snap_prefix));
    snap[5] = uses_bridge_tunnel(type) ? 0xf8 : 0;
    ip4::put16(snap + 6, type);
    return prepare_station_frame(dma, queue, rate, header, sequence, frame + ethernet_bytes,
                                 unsigned(length - ethernet_bytes), snap, sizeof(snap));
}

bool prepare_arp_request(const AuthenticationDma& dma, PeerQueue queue, uint32_t rate,
                         const uint8_t (&station)[6], const AuthenticationTarget& target,
                         uint16_t sequence) {
    uint8_t frame[ethernet_bytes + 28]{};
    memset(frame, 0xff, 6);
    memcpy(frame + 6, station, sizeof(station));
    ip4::put16(frame + 12, 0x0806);
    auto* arp = frame + ethernet_bytes;
    memcpy(arp, arp_header, sizeof(arp_header));
    arp[7] = 1;
    memcpy(arp + 8, station, sizeof(station));
    ip4::put32(arp + 14, target.source_ipv4);
    ip4::put32(arp + 24, target.peer_ipv4);
    return prepare_station_data(dma, queue, rate, station, target.bssid, frame, sizeof(frame),
                                sequence);
}

size_t receive_station_data(const FirmwarePacket& packet, const uint8_t (&station)[6],
                            const uint8_t (&bssid)[6], uint8_t channel,
                            uint8_t (&output)[station_frame_bytes]) {
    constexpr unsigned descriptor_bytes = 48;
    if (packet.group || packet.opcode != 0xc1 || !(packet.sequence & 0x8000) || !packet.payload ||
        packet.length < descriptor_bytes + header_bytes)
        return 0;
    const auto* rx = packet.payload;
    const auto* frame = rx + descriptor_bytes;
    if ((rx[12] & 3) != 3 || (rx[3] & 0x40) || rx[34] != channel ||
        (frame[0] != 0x08 && frame[0] != 0x88) || (frame[1] & 0xc7) != 2 || (frame[22] & 15) ||
        (!(frame[4] & 1) && memcmp(frame + 4, station, sizeof(station))) ||
        memcmp(frame + 10, bssid, sizeof(bssid)) || !memcmp(frame + 16, station, sizeof(station)) ||
        (frame[16] & 1))
        return 0;
    const unsigned body_offset = header_bytes + (frame[0] == 0x88 ? 2 : 0) + (rx[3] & 0x20 ? 2 : 0);
    const unsigned length = read16(rx);
    const unsigned trailer = (rx[2] & 0xf0) >> 3;
    if (length < body_offset + snap_bytes + trailer || length > packet.length - descriptor_bytes)
        return 0;
    const auto* snap = frame + body_offset;
    const uint16_t type = ip4::get16(snap + 6);
    const size_t payload = length - body_offset - snap_bytes - trailer;
    if (memcmp(snap, snap_prefix, sizeof(snap_prefix)) || type < 1536 ||
        (snap[5] != 0xf8 && (snap[5] || uses_bridge_tunnel(type))) ||
        payload > (type == 0x8100 || type == 0x88a8 ? 1504u : 1500u))
        return 0;
    memcpy(output, frame + 4, 6);
    memcpy(output + 6, frame + 16, 6);
    ip4::put16(output + 12, type);
    memcpy(output + ethernet_bytes, snap + snap_bytes, payload);
    return ethernet_bytes + payload;
}

bool observe_arp_response(const FirmwarePacket& packet, const uint8_t (&station)[6],
                          uint8_t channel, const AuthenticationTarget& target) {
    uint8_t frame[station_frame_bytes];
    const size_t length = receive_station_data(packet, station, target.bssid, channel, frame);
    if (length < ethernet_bytes + 28 || memcmp(frame, station, sizeof(station)) ||
        ip4::get16(frame + 12) != 0x0806)
        return false;
    const auto* arp = frame + ethernet_bytes;
    uint8_t sender = 0;
    for (unsigned i = 0; i < sizeof(station); ++i)
        sender |= arp[8 + i];
    return sender && !(arp[8] & 1) && !memcmp(arp, arp_header, sizeof(arp_header)) &&
           ip4::get16(arp + 6) == 2 && !memcmp(arp + 8, frame + 6, sizeof(station)) &&
           ip4::get32(arp + 14) == target.peer_ipv4 &&
           !memcmp(arp + 18, station, sizeof(station)) &&
           ip4::get32(arp + 24) == target.source_ipv4;
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

namespace {
AuthEvent management_reply(const FirmwarePacket& packet, const uint8_t (&station)[6],
                           const AccessPoint& peer, uint8_t channel, uint8_t subtype,
                           const uint8_t*& body, unsigned minimum = body_bytes) {
    constexpr unsigned descriptor_bytes = 48;
    if (packet.group || packet.opcode != 0xc1 || !(packet.sequence & 0x8000) || !packet.payload ||
        packet.length < descriptor_bytes + header_bytes)
        return AuthEvent::unrelated;
    const auto* rx = packet.payload;
    const auto* frame = rx + descriptor_bytes;
    if ((rx[12] & 3) != 3 || (rx[3] & 0x20) || rx[34] != channel || frame[0] != subtype ||
        (frame[1] & 0xc7) || (frame[22] & 15) || memcmp(frame + 4, station, sizeof(station)) ||
        memcmp(frame + 10, peer.bssid, sizeof(peer.bssid)) ||
        memcmp(frame + 16, peer.bssid, sizeof(peer.bssid)))
        return AuthEvent::unrelated;
    const unsigned length = read16(rx);
    if (length < header_bytes + minimum || length > packet.length - descriptor_bytes)
        return AuthEvent::malformed;
    body = frame + header_bytes;
    return AuthEvent::accepted;
}
} // namespace

bool observe_station_disconnect(const FirmwarePacket& packet, const uint8_t (&station)[6],
                                const AccessPoint& peer, uint8_t channel) {
    const uint8_t* body = nullptr;
    return management_reply(packet, station, peer, channel, 0xc0, body, 2) == AuthEvent::accepted ||
           management_reply(packet, station, peer, channel, 0xa0, body, 2) == AuthEvent::accepted;
}

AuthEvent observe_authentication_reply(const FirmwarePacket& packet, const uint8_t (&station)[6],
                                       const AccessPoint& peer, uint8_t channel) {
    const uint8_t* body = nullptr;
    const auto result = management_reply(packet, station, peer, channel, 0xb0, body);
    if (result != AuthEvent::accepted)
        return result;
    if (read16(body) || read16(body + 2) != 2)
        return AuthEvent::unrelated;
    return read16(body + 4) ? AuthEvent::denied : AuthEvent::accepted;
}

AuthEvent observe_association_reply(const FirmwarePacket& packet, const uint8_t (&station)[6],
                                    const AccessPoint& peer, uint8_t channel, uint16_t& aid) {
    const uint8_t* body = nullptr;
    const auto result = management_reply(packet, station, peer, channel, 0x10, body);
    if (result != AuthEvent::accepted)
        return result;
    if (read16(body + 2))
        return AuthEvent::denied;
    const auto id = read16(body + 4) & 0x7ff;
    if (!id || id > 2007)
        return AuthEvent::malformed;
    aid = uint16_t(id);
    return AuthEvent::accepted;
}
} // namespace ax::IntelWifi
