// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/net/intel_wifi_codecs.cpp
 * @brief   Test AX201 scan, association, and CCMP key messages on the host.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_auth.hpp"
#include "drivers/net/intel_wifi_key.hpp"
#include "drivers/net/intel_wifi_scan.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax::IntelWifi;
using Bytes = std::vector<uint8_t>;

void check_intel_wifi_association_codec() {
    AccessPoint peer{};
    peer.capability = 1;
    peer.ssid[0] = 'A';
    peer.ssid_length = 1;
    peer.bssid[0] = 2;
    const uint8_t rsn[]{1, 1, 0x82, 48, 2, 1, 0};
    const uint8_t wpa[]{1, 1, 0x82, 221, 4, 0, 0x50, 0xf2, 1};
    const uint8_t basic[]{1, 2, 0x8c, 0xff};
    AssociationRequest request;
    assert(!prepare_association_request(peer, rsn, sizeof(rsn), false, request));
    assert(!prepare_association_request(peer, wpa, sizeof(wpa), false, request));
    assert(!prepare_association_request(peer, basic, sizeof(basic), true, request));
    assert(!prepare_association_request(peer, basic, sizeof(basic) - 1, true, request));

    constexpr uint8_t station[]{2, 0, 0, 0, 0, 3};
    uint8_t receive[ax::page_size]{};
    const auto length = uint16_t(24 + 6 + association_response_ie_capacity);
    receive[0] = uint8_t(length);
    receive[1] = uint8_t(length >> 8);
    receive[12] = 3;
    receive[34] = 1;
    auto* frame = receive + 48;
    frame[0] = 0x10;
    memcpy(frame + 4, station, sizeof(station));
    memcpy(frame + 10, peer.bssid, sizeof(peer.bssid));
    memcpy(frame + 16, peer.bssid, sizeof(peer.bssid));
    frame[28] = 42;
    frame[29] = 0xc0;
    FirmwarePacket packet{0xc1, 0, 0x8000, receive, size_t(48 + length)};
    AssociationReply reply;
    assert(observe_association_reply(packet, station, peer, 1, reply) == AuthEvent::accepted);
    assert(reply.aid == 42 && !reply.status && reply.elements == frame + 30 &&
           reply.element_bytes == association_response_ie_capacity);
    --packet.length;
    assert(observe_association_reply(packet, station, peer, 1, reply) == AuthEvent::malformed);
    packet.length += 2;
    ++receive[0];
    assert(observe_association_reply(packet, station, peer, 1, reply) == AuthEvent::malformed);
    std::puts("AX201_ASSOCIATION_CODEC_PASS");
}

void check_intel_wifi_ccmp_data() {
    constexpr uint8_t station[]{2, 0, 0, 0, 0, 3}, bssid[]{2, 0, 0, 0, 0, 1};
    CommandDescriptor ring[management_queue_entries]{};
    uint16_t counts[management_queue_entries]{};
    uint8_t payload[authentication_dma_bytes]{};
    const AuthenticationDma dma{ring, counts, payload, 0x52000};
    const PeerQueue queue{0x102, 0x37};
    uint8_t ethernet[15]{};
    memcpy(ethernet, bssid, sizeof(bssid));
    memcpy(ethernet + 6, station, sizeof(station));
    ethernet[12] = 8;
    ethernet[14] = 0x7f;
    const uint8_t snap[]{0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x7f};
    assert(prepare_station_data(dma, queue, 0x400a, station, bssid, ethernet, sizeof(ethernet), 7,
                                true));
    assert(payload[8] == 1 && payload[69] == 0x41);
    assert(payload[4] == 24 + sizeof(snap) && !memcmp(payload + 128, snap, sizeof(snap)));
    assert(prepare_station_data(dma, queue, 0x400a, station, bssid, ethernet, sizeof(ethernet), 7));
    assert(payload[8] == 3 && payload[69] == 1);

    uint8_t rx[112]{};
    uint8_t decoded[station_frame_bytes]{};
    StationCcmpKeys keys{};
    FirmwarePacket packet{0xc1, 0, 0x8000, rx, sizeof(rx)};
    auto* frame = rx + 48;
    auto make_rx = [&](bool encrypted, bool qos, bool group, uint8_t key, uint64_t pn) {
        memset(rx, 0, sizeof(rx));
        const unsigned mac = qos ? 26 : 24;
        const unsigned body = mac + (encrypted ? 8 : 0) + (qos ? 2 : 0);
        rx[0] = uint8_t(body + sizeof(snap) + 4);
        rx[2] = 0x20; // Four bytes of trailer in the MPDU length.
        rx[3] = qos ? 0x20 : 0;
        rx[12] = encrypted ? 0x43 : 3;
        rx[13] = encrypted ? 2 : 0;
        rx[34] = 1;
        frame[0] = qos ? 0x88 : 8;
        frame[1] = encrypted ? 0x42 : 2;
        memcpy(frame + 4, station, sizeof(station));
        if (group)
            memset(frame + 4, 0xff, 6);
        memcpy(frame + 10, bssid, sizeof(bssid));
        memcpy(frame + 16, bssid, sizeof(bssid));
        if (qos)
            frame[24] = 4;
        if (encrypted) {
            auto* iv = frame + mac;
            iv[0] = uint8_t(pn);
            iv[1] = uint8_t(pn >> 8);
            iv[3] = uint8_t((key << 6) | 0x20);
            for (unsigned i = 0; i < 4; ++i)
                iv[4 + i] = uint8_t(pn >> (16 + 8 * i));
        }
        memcpy(frame + body, snap, sizeof(snap));
        packet.length = 48 + rx[0];
        return frame + body;
    };
    const auto receive = [&] {
        return receive_station_data(packet, station, bssid, 1, decoded, &keys);
    };

    constexpr uint64_t pn = 0x010203040506;
    auto* body = make_rx(true, false, false, 0, pn);
    assert(!receive());
    keys.pairwise.installed = true;
    keys.pairwise.packet_number[0] = pn - 1;
    assert(!receive_station_data(packet, station, bssid, 1, decoded));
    rx[12] &= ~0x40;
    assert(!receive());
    rx[12] |= 0x40;
    frame[27] = 0; // Missing Extended IV.
    assert(!receive());
    frame[27] = 0x60; // Wrong pairwise key index.
    assert(!receive());
    frame[27] = 0x20;
    --packet.length;
    assert(!receive());
    ++packet.length;
    body[0] = 0;
    assert(!receive() && keys.pairwise.packet_number[0] == pn - 1);
    body[0] = 0xaa;
    assert(receive() == sizeof(ethernet) && decoded[14] == 0x7f);
    assert(keys.pairwise.packet_number[0] == pn && !receive());
    make_rx(true, true, false, 0, pn);
    frame[24] = 0;
    assert(!receive());
    make_rx(true, true, false, 0, pn - 1);
    frame[24] |= 0x80;
    assert(!receive() && !keys.pairwise.packet_number[4]);
    frame[24] &= 0x7f;
    assert(receive() == sizeof(ethernet) && keys.pairwise.packet_number[4] == pn - 1 && !receive());
    make_rx(true, false, true, 2, pn - 1);
    keys.group[1].installed = true;
    assert(!receive());
    keys.group[2].installed = true;
    keys.group[2].packet_number[0] = pn - 2;
    assert(receive() == sizeof(ethernet) && decoded[0] == 0xff && !receive());

    body = make_rx(false, false, false, 0, 0);
    assert(!receive());
    body[6] = 0x88;
    body[7] = 0x8e;
    assert(receive() == sizeof(ethernet));
    frame[21] ^= 1;
    assert(!receive());
    std::puts("AX201_CCMP_DATA_CODEC_PASS");
}

void check_intel_wifi_key_codec() {
    constexpr uint8_t key[ccmp_key_bytes]{0x12, 0x34, 0x56, 0x78};
    constexpr uint64_t largest_pn = 0xffffffffffff;
    uint8_t command[key_command_bytes]{};
    assert(!prepare_ccmp_key_install({32, 0, false}, key, 0, 0, command));
    assert(!prepare_ccmp_key_install({0, 4, true}, key, 0, 0, command));
    assert(!prepare_ccmp_key_install({0, 0, false}, key, largest_pn + 1, 0, command));
    assert(!prepare_ccmp_key_install({0, 0, false}, key, 0, largest_pn + 1, command));
    assert(prepare_ccmp_key_install({31, 3, true}, key, largest_pn, 0x010203040506, command));
    const uint8_t addr[]{1, 0, 0, 0, 0, 0, 0, 0x80, 3, 0, 0, 0, 0x42};
    assert(!memcmp(command, addr, sizeof(addr)));
    assert(!memcmp(command + 16, key, sizeof(key)));
    const uint8_t pn[]{255, 255, 255, 255, 255, 255, 0, 0, 6, 5, 4, 3, 2, 1, 0, 0};
    assert(!memcmp(command + 64, pn, sizeof(pn)));
    assert(!prepare_ccmp_key_remove({0, 4, true}, command));
    assert(prepare_ccmp_key_remove({31, 3, true}, command));
    assert(command[0] == 3 && !memcmp(command + 1, addr + 1, sizeof(addr) - 1));
    const uint8_t empty[key_command_bytes]{};
    assert(!memcmp(command + 13, empty, sizeof(command) - 13));
    erase_key_bytes(command, sizeof(command));
    assert(!memcmp(command, empty, sizeof(command)));
    std::puts("AX201_CCMP_KEY_CODEC_PASS");
}

void check_intel_wifi_scan_channels() {
    NvmInfo nvm{};
    nvm.bands = 3;
    RegulatoryProfile profile{};
    profile.channel_slots = regulatory_channel_limit;
    profile.flags[13] = 1;
    profile.flags[18] = 0x39;
    profile.flags[19] = 0x29;
    const auto mixed = scan_channel_list(nvm, profile);
    assert(mixed.count == scan_channel_limit);
    assert(mixed.entries[13].number == 14 && mixed.entries[13].frequency_mhz == 2484 &&
           mixed.entries[13].allowed);
    assert(mixed.entries[18].number == 52 && mixed.entries[18].frequency_mhz == 5260 &&
           mixed.entries[18].allowed && mixed.entries[18].radar && mixed.entries[18].indoor &&
           !mixed.entries[18].active);
    assert(mixed.entries[19].allowed && mixed.entries[19].indoor && !mixed.entries[19].active);
    assert(!mixed.entries[20].allowed);
    nvm.bands = 2;
    const auto high_only = scan_channel_list(nvm, profile);
    assert(high_only.count == scan_channel_limit - 14 &&
           high_only.entries[0].frequency_mhz == 5180 && !high_only.entries[0].allowed);
    assert(high_only.entries[4].frequency_mhz == 5260 && high_only.entries[4].allowed);
    std::puts("AX201_SCAN_CHANNEL_MODEL_PASS");
}

void check_intel_wifi_access_points() {
    PassiveScan scan{};
    ScanElementStorage elements{};
    scan.elements = &elements;
    scan.channels[0] = 1;
    scan.channels[1] = 6;
    scan.channels[2] = 36;
    scan.channel_count = 3;
    auto observe = [&](bool probe, uint8_t channel, uint8_t advertised, uint8_t bssid_tail,
                       uint8_t energy, const Bytes& name, bool truncated = false) {
        constexpr unsigned descriptor = 48, fixed_frame = 36;
        const auto frame_bytes = fixed_frame + 2 + name.size() + 3;
        uint8_t packet[128]{};
        packet[0] = uint8_t(frame_bytes);
        packet[12] = 3;
        packet[32] = energy;
        packet[33] = 85;
        packet[34] = channel;
        auto* frame = packet + descriptor;
        frame[0] = probe ? 0x50 : 0x80;
        frame[16] = 2;
        frame[21] = bssid_tail;
        frame[32] = 100;
        frame[34] = 0x31;
        frame[35] = 0x04;
        frame[37] = uint8_t(name.size());
        for (unsigned i = 0; i < name.size(); ++i)
            frame[38 + i] = name[i];
        const auto ds = 38 + name.size();
        frame[ds] = 3;
        frame[ds + 1] = truncated ? 2 : 1;
        frame[ds + 2] = advertised;
        observe_passive_scan(scan, {0xc1, 0, 0x8000, packet, descriptor + frame_bytes});
    };
    observe(false, 1, 12, 1, 48, {'X'}); // Channel outside the selected profile.
    observe(false, 1, 1, 1, 48, {'X'}, true);
    assert(scan.access_point_count == 0);
    observe(false, 1, 6, 1, 35, {});
    assert(scan.access_point_count == 1);
    auto& point = scan.access_points[0];
    assert(point.frequency_mhz == 2437 && point.signal_dbm == scan_signal_unavailable);
    observe(true, 6, 6, 1, 62, {'A', 0, 0xff});
    assert(scan.access_point_count == 1 && point.probe_response && point.ssid_length == 3);
    assert(point.ssid[0] == 'A' && point.ssid[1] == 0 && point.ssid[2] == 0xff);
    assert(point.signal_dbm == -62 && point.beacon_interval_tu == 100 && point.capability == 0x431);
    const uint8_t probe[]{0, 3, 'A', 0, 0xff, 3, 1, 6};
    const uint8_t original_beacon[]{0, 0, 3, 1, 6};
    assert(point.probe_ie_bytes == sizeof(probe) &&
           point.beacon_ie_bytes == sizeof(original_beacon));
    assert(!memcmp(elements.records[0].probe, probe, sizeof(probe)) &&
           !memcmp(elements.records[0].beacon, original_beacon, sizeof(original_beacon)));
    observe(false, 6, 6, 1, 41, {0, 0, 0});
    assert(scan.access_point_count == 1 && point.probe_response && point.ssid_length == 3 &&
           point.signal_dbm == -41);
    const uint8_t later_beacon[]{0, 3, 0, 0, 0, 3, 1, 6};
    assert(point.beacon_ie_bytes == sizeof(later_beacon));
    assert(!memcmp(elements.records[0].beacon, later_beacon, sizeof(later_beacon)));
    observe(true, 6, 6, 1, 52, {});
    assert(point.probe_ie_bytes == sizeof(probe) &&
           !memcmp(elements.records[0].probe, probe, sizeof(probe)));
    observe(false, 36, 36, 1, 60, {'B'});
    assert(scan.access_point_count == 2 && scan.access_points[1].frequency_mhz == 5180);
    for (uint8_t address = 2; address <= 32; ++address)
        observe(false, 6, 6, address, 80, {'Z'});
    assert(scan.access_point_count == 32 && scan.access_points_truncated);
    std::puts("AX201_ACCESS_POINT_MODEL_PASS");
}
