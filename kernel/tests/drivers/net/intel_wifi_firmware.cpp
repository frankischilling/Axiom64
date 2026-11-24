// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/net/intel_wifi_firmware.cpp
 * @brief   Exercise AX201 firmware structure and rejection paths.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_live.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

void check_intel_wifi_access_points();
void check_intel_wifi_boot_queues(const ax::IntelWifi::FirmwareImage&);
void check_intel_wifi_association_codec();
void check_intel_wifi_ccmp_data();
void check_intel_wifi_key_codec();
void check_intel_wifi_scan_channels();
void check_intel_wifi_station_keys();
void check_intel_wifi_rsn_codec();
void check_intel_wifi_receive_recycling();
void initialize_intel_wifi_receive_descriptors(uint64_t*, uint64_t*);

namespace {
using namespace ax::IntelWifi;
using Bytes = std::vector<uint8_t>;
constexpr uint8_t enterprise_ie[]{48, 20,  1, 0, 0, 15, 172, 4,   1, 0, 0,
                                  15, 172, 4, 1, 0, 0,  15,  172, 1, 0, 0};

void word(Bytes& bytes, size_t where, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        bytes.at(where + i) = uint8_t(value >> (8 * i));
}

size_t append(Bytes& file, uint32_t type, uint32_t length) {
    const size_t start = file.size();
    file.resize(start + 8 + ((size_t(length) + 3) & ~size_t(3)));
    word(file, start, type);
    word(file, start + 4, length);
    return start + 8;
}

size_t section(Bytes& file, uint32_t offset, const Bytes& data) {
    const size_t start = append(file, 19, uint32_t(data.size()) + 4);
    word(file, start, offset);
    for (size_t i = 0; i < data.size(); ++i)
        file[start + 4 + i] = data[i];
    return start;
}

void alive_packet(uint8_t* data) {
    // A short, unrelated notification followed by an aligned ALIVE v6 frame.
    data[0] = 4;
    data[4] = 0x68;
    data[64] = 148;
    data[68] = 1;
    data[72] = 0xfe;
    data[73] = 0xca;
}

enum class StartupCase {
    good,
    blocked,
    unowned,
    timeout,
    bad_buffer,
    stop_failed,
    bus_master_failed
};

enum class RegulatoryCase { unused, valid, bad_count, disallowed, disabled, rejected };
enum class PeerCase {
    unused,
    success,
    passive_only,
    station_denied,
    short_queue,
    queue_denied,
    remove_denied
};
enum class AuthCase {
    unused,
    accepted,
    reply_first,
    denied_session,
    denied_tx,
    denied_ap,
    reply_timeout,
    protection_expired,
    wrong_target
};
enum class AssocCase { unused, accepted, refused, invalid_id, secured, bad_beacon, leave_failed };
enum class ArpCase { unused, accepted, reply_first, wrong_peer, rejected_tx, missing_completion };
enum class KeyCase { unused, complete, refused_removal, missing_install };
enum class ScanCase {
    unused,
    complete,
    early_completion,
    aborted,
    timeout,
    no_reply,
    second_aborted,
    busy_queue
};

struct StartupFixture {
    StartupCase scenario;
    uint32_t csr[(0x1c80 / 4) + 1]{};
    ReceiveStatus receive_status{};
    uint32_t used[rx_ring_entries]{};
    uint64_t free_ring[rx_ring_entries]{};
    uint64_t descriptors[rx_ring_entries - 1]{};
    uint8_t buffer[ax::page_size]{};
    uint8_t replies[9][ax::page_size]{};
    Bytes live_replies;
    CommandDescriptor commands[command_ring_entries]{};
    CommandPayloads payloads{};
    unsigned commands_sent = 0;
    uint8_t scan_only_channel = 0;
    uint8_t notification_channel = 1;
    bool probe_expected = false;
    bool check_channels = false;
    bool dual_lmac = false;
    PeerCase peer_case = PeerCase::unused;
    AuthCase auth_case = AuthCase::unused;
    AssocCase assoc_case = AssocCase::unused;
    ArpCase arp_case = ArpCase::unused;
    bool open_station = false;
    KeyCase key_case = KeyCase::unused;
    bool extra_association_elements = false;
    bool secured_association = false;
    uint16_t disconnect_reason = 0;
    unsigned cancel_after_commands = 0;
    unsigned rejoin_command_offset = 0, rejoin_rx_offset = 0;
    CommandDescriptor management_ring[management_queue_entries]{};
    uint16_t management_counts[transmit_byte_count_bytes / sizeof(uint16_t)]{};
    CommandDescriptor data_ring[management_queue_entries]{};
    uint16_t data_counts[transmit_byte_count_bytes / sizeof(uint16_t)]{};
    uint8_t authentication_payload[authentication_dma_bytes]{};
    unsigned authentication_rx_buffers = 0;
    bool defer_authentication_completion = false;
    uint16_t deferred_authentication_buffer = 0;
    unsigned data_rx_buffers = 0;
    unsigned bad_binding_status = 0;
    unsigned short_binding_status = 0;
    unsigned scan_delays = 0;
    bool malformed_nvm = false;
    bool wrong_sequence = false;
    bool reject_scan_config = false;
    RegulatoryCase regulatory = RegulatoryCase::unused;
    ScanCase passive = ScanCase::unused;
    bool master = false;
    bool requested_master = false;
    bool sent_doorbell = false;
    unsigned receive_updates = 0;
    bool recycle = false;
    bool requested_stop = false;
    bool reset_after_dma = false;

    explicit StartupFixture(StartupCase scenario) : scenario(scenario) {
        csr[0x24 / 4] = scenario == StartupCase::blocked ? 0 : 1u << 27;
        csr[0x380 / 4] = 0x02112233;
        csr[0x384 / 4] = 0x4455;
        alive_packet(buffer);
    }

    void scan_notifications(uint8_t* reply, uint8_t id) const {
        const auto completion = [](uint8_t* frame, uint8_t id, uint8_t status) {
            frame[0] = 20;
            frame[4] = 0xf;
            frame[7] = 0x80;
            frame[8] = id;
            frame[14] = status;
        };
        completion(reply + 64, id ? 0 : 7, 1); // A different or already completed scan.
        for (unsigned offset : {128u, 256u, 384u}) {
            auto* frame = reply + offset;
            frame[0] = 90;
            frame[4] = 0xc1;
            frame[7] = 0x80;
            auto* mpdu = frame + 8;
            mpdu[0] = 38;
            mpdu[12] = offset == 384 ? 1 : 3;
            mpdu[34] = notification_channel;
            auto* beacon = mpdu + 48;
            beacon[0] = 0x80;
            beacon[16] = 0x02;
            const unsigned first_peer = id && !rejoin_command_offset ? 0x20 : 0x10;
            beacon[21] = uint8_t(first_peer + (offset == 384 ? 2 : 1));
            if (peer_case != PeerCase::unused)
                beacon[34] = 1; // ESS capability.
            if (auth_case != AuthCase::unused) {
                frame[0] = 93;
                mpdu[0] = 41;
                beacon[32] = 100;
                beacon[38] = beacon[39] = 1;
                beacon[40] = 0x82; // Basic 1 Mbps rate.
            }
            if (assoc_case != AssocCase::unused) {
                const uint8_t ies[]{0,  3,  'l', 'a', 'b', 1, 8,  0x82, 4,  11, 22,
                                    12, 18, 24,  36,  50,  4, 48, 72,   96, 108};
                memcpy(beacon + 36, ies, sizeof(ies));
                mpdu[0] = 36 + sizeof(ies);
                frame[0] = 52 + mpdu[0];
                if (assoc_case == AssocCase::secured)
                    beacon[34] |= 0x10;
            }
            // Zero-length SSID is valid for a hidden network.
        }
        if (passive != ScanCase::timeout) {
            const bool abort =
                passive == ScanCase::aborted || (id && passive == ScanCase::second_aborted);
            completion(reply + 512, id, abort ? 2 : 1);
        }
        if (passive == ScanCase::no_reply)
            reply[6] = 0xff;
        if (passive == ScanCase::early_completion) {
            uint8_t ack[64];
            memcpy(ack, reply, sizeof(ack));
            memmove(reply, reply + sizeof(ack), 512);
            memcpy(reply + 512, ack, sizeof(ack));
        }
    }

    uint8_t* reply_buffer(unsigned slot) {
        if (!live_replies.empty())
            return live_replies.data() + slot * ax::page_size;
        return slot < 9 ? replies[slot] : nullptr;
    }

    unsigned expect_channel_command(unsigned index, uint8_t* expected) const {
        const bool high = index >= 14;
        const uint8_t lmac = high && dual_lmac;
        switch (index) {
        case 8:
        case 13:
        case 14:
        case 18:
            expected[0] = 8;
            expected[12] = index == 13 || index == 18 ? 3 : 1;
            expected[16] = high ? 36 : 1;
            expected[20] = !high;
            expected[24] = lmac;
            return 32;
        case 9:
        case 15:
            expected[0] = 8;
            expected[1] = 5;
            expected[12] = 4;
            expected[13] = 0x14;
            return 32;
        case 10:
            expected[0] = 0xd1;
            expected[8] = 3;
            expected[13] = 0x10;
            expected[17] = 0x20;
            for (unsigned i = 0; i < 10; ++i) {
                expected[20 + i * 4] = 0x40;
                expected[21 + i * 4] = 0x42;
                expected[22 + i * 4] = 0x0f;
            }
            for (unsigned i = 0; i < 5; ++i) {
                expected[60 + i * 8] = 0x90;
                expected[61 + i * 8] = 1;
                expected[64 + i * 8] = 0xa0;
            }
            return 92;
        default:
            assert(index == 11 || index == 12 || index == 16 || index == 17);
            const bool remove = index == 12 || index == 17;
            expected[0] = 0x2b;
            expected[12] = remove ? 3 : 1;
            memset(expected + (remove ? 16 : 20), 0xff, remove ? 12 : 8);
            expected[32] = lmac;
            return 28;
        }
    }

    unsigned expect_peer_command(unsigned index, uint8_t* expected) const {
        if (index <= 12)
            return expect_channel_command(index - 1, expected);
        if (index >= 17)
            return expect_channel_command(index - 5, expected);
        if (index == 13) {
            expected[0] = 0x18;
            expected[10] = expected[11] = 0xff;
            expected[16] = 2;
            expected[21] = 0x11;
            expected[34] = 2;
            expected[35] = 0x3c;
            return 48;
        }
        if (index == 16) {
            expected[0] = 0x19;
            return 4;
        }
        assert(index == 14 || index == 15);
        expected[0] = 0x17;
        expected[1] = 5;
        expected[12] = 1;
        expected[16] = 15;
        if (index == 14) {
            expected[24] = 1;
            expected[29] = 0x10;
            expected[30] = 0x05;
            expected[38] = 0x05;
        } else {
            expected[8] = 1;
        }
        return 36;
    }

    unsigned expect_key_check_command(unsigned index, uint8_t* expected) const {
        if (index <= 11)
            return expect_channel_command(index, expected);
        const uint8_t address[]{2, 0x11, 0x22, 0x33, 0x44, 0x55};
        const uint8_t fixture[]{2, 0x11, 0x22, 0x33, 0x44, 0x54};
        if (index == 12) {
            expected[0] = 0x28;
            expected[12] = 2;
            expected[16] = 5;
            memcpy(expected + 24, address, sizeof(address));
            memcpy(expected + 32, fixture, sizeof(fixture));
            expected[40] = 0xf;
            expected[44] = 0x15;
            expected[60] = 0x44;
            expected[124] = 100;
            expected[140] = 1;
            return 148;
        }
        if (index == 13) {
            const unsigned length = expect_peer_command(13, expected);
            memcpy(expected + 16, fixture, sizeof(fixture));
            return length;
        }
        if (index >= 18)
            return expect_peer_command(index - 2, expected);
        const bool group = index == 15 || index == 16;
        expected[0] = 0x18;
        expected[1] = 5;
        expected[8] = index < 16 ? 1 : 3;
        expected[12] = 1;
        expected[16] = group;
        expected[20] = group ? 0x42 : 2;
        if (index < 16) {
            for (unsigned i = 0; i < 16; ++i)
                expected[24 + i] = uint8_t(i + 1);
            expected[72] = group;
        }
        return 80;
    }

    void authentication_doorbell(uint32_t value) {
        const auto step = authentication_rx_buffers - data_rx_buffers;
        const bool cancelling = cancel_after_commands == 16 && commands_sent == 16 && step == 1;
        const bool leaving = cancelling || step == 2;
        const bool synced = step == 2 && assoc_case != AssocCase::bad_beacon;
        const unsigned command_count = (disconnect_reason && step == 2) || data_rx_buffers ? 19
                                       : synced                                            ? 17
                                                                                           : 16;
        assert(auth_case != AuthCase::unused &&
               commands_sent == command_count + rejoin_command_offset && step <= 2);
        assert(!step || assoc_case != AssocCase::unused);
        assert(value == 0x01010035 + step);
        const auto slot = 4 + step;
        const auto& descriptor = management_ring[slot];
        const uint8_t auth_body[]{0, 0, 1, 0, 0, 0};
        const uint8_t open_body[]{1,  0,  1,  0,  0, 3,  'l', 'a', 'b', 1,  8, 2,  4,  11,  22, 12,
                                  18, 24, 36, 50, 4, 48, 72,  96,  108, 59, 2, 81, 81, 127, 1,  0};
        uint8_t assoc_body[sizeof(open_body) + sizeof(enterprise_ie)];
        memcpy(assoc_body, open_body, sizeof(open_body));
        unsigned association_length = sizeof(open_body) - (extra_association_elements ? 0 : 7);
        if (secured_association) {
            assoc_body[0] |= 0x10;
            memcpy(assoc_body + association_length, enterprise_ie, sizeof(enterprise_ie));
            association_length += sizeof(enterprise_ie);
        }
        const auto reason = disconnect_reason ? disconnect_reason : 3;
        const uint8_t leave_body[]{uint8_t(reason), uint8_t(reason >> 8)};
        const uint8_t* body = step == 0 ? auth_body : leaving ? leave_body : assoc_body;
        const uint16_t length = step == 0 ? sizeof(auth_body)
                                : leaving ? sizeof(leave_body)
                                          : association_length;
        assert(descriptor.buffer_count == 3 && management_counts[slot] == (24 + length + 3) / 4);
        const TransmitBuffer buffers[]{{20, 0x52000}, {28, 0x52040}, {length, 0x52080}};
        assert(!memcmp(descriptor.buffers, buffers, sizeof(buffers)));
        const uint8_t first[20]{0x1c, 0, uint8_t(slot), 1, uint8_t(24 + length), 0, 0, 12, 3};
        const uint8_t subtype = step == 0 ? 0xb0 : leaving ? 0xc0 : 0;
        const uint8_t sequence = uint8_t(authentication_rx_buffers << 4);
        const uint8_t second[]{
            0, 0x40, 0,    0,    subtype, 0,    0, 0, 2, 0, 0, 0,    0,        0x11,
            2, 0x11, 0x22, 0x33, 0x44,    0x55, 2, 0, 0, 0, 0, 0x11, sequence, 0,
        };
        assert(!memcmp(authentication_payload, first, sizeof(first)));
        assert(!memcmp(authentication_payload + 64, second, sizeof(second)));
        assert(!memcmp(authentication_payload + 128, body, length));

        auto* buffer = reply_buffer(commands_sent + authentication_rx_buffers + rejoin_rx_offset);
        const bool first_reply = (auth_case == AuthCase::reply_first ||
                                  (open_station && auth_case == AuthCase::denied_ap)) &&
                                 !leaving;
        auto* tx = buffer + (first_reply ? 128 : 0);
        tx[0] = 52;
        tx[4] = 0x1c;
        tx[6] = uint8_t(slot);
        tx[7] = 1;
        tx[8] = 1;
        tx[44] = tx[45] = 1;
        tx[48] =
            auth_case == AuthCase::denied_tx || (step == 2 && assoc_case == AssocCase::leave_failed)
                ? 0x84
                : 1;
        tx[52] = uint8_t(0x35 + step);

        if (auth_case == AuthCase::protection_expired) {
            auto* ended = buffer + 64;
            ended[0] = 20;
            ended[4] = 0xfb;
            ended[5] = 3;
            ended[7] = 0x80;
            ended[12] = 1;
        } else if (!leaving && auth_case != AuthCase::reply_timeout) {
            auto* rx = buffer + (first_reply ? 0 : 64);
            rx[0] = 82;
            rx[4] = 0xc1;
            rx[7] = 0x80;
            auto* mpdu = rx + 8;
            mpdu[0] = 30;
            mpdu[12] = 3;
            mpdu[34] = 1;
            auto* frame = mpdu + 48;
            const uint8_t header[]{
                0xb0, 0, 0, 0,    2, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 0,
                0,    0, 0, 0x11, 2, 0,    0,    0,    0,    0x11, 0, 0,
            };
            memcpy(frame, header, sizeof(header));
            if (step == 0) {
                frame[26] = 2;
                frame[28] = auth_case == AuthCase::denied_ap ? 13 : 0;
            } else {
                frame[0] = 0x10;
                frame[24] = 1;
                frame[26] = assoc_case == AssocCase::refused ? 17 : 0;
                frame[28] = assoc_case == AssocCase::invalid_id ? 0 : 42;
                frame[29] = 0xc0;
                if (open_station) {
                    const uint8_t elements[]{1, 1, 0x82};
                    rx[0] += sizeof(elements);
                    mpdu[0] += sizeof(elements);
                    memcpy(frame + 30, elements, sizeof(elements));
                }
                auto* beacon = buffer + 192;
                beacon[0] = 94;
                beacon[4] = 0xc1;
                beacon[7] = 0x80;
                auto* beacon_mpdu = beacon + 8;
                beacon_mpdu[0] = 42;
                beacon_mpdu[12] = 3;
                beacon_mpdu[34] = 1;
                const uint8_t gp2[]{0xf0, 0xff, 0xff, 0xff};
                memcpy(beacon_mpdu + 36, gp2, sizeof(gp2));
                auto* beacon_frame = beacon_mpdu + 48;
                memcpy(beacon_frame, header, sizeof(header));
                beacon_frame[0] = 0x80;
                memset(beacon_frame + 4, 0xff, 6);
                const uint8_t timing[]{0, 0xff, 0xff, 0xff, 4, 0, 0, 0, 100, 0, 1, 0};
                memcpy(beacon_frame + 24, timing, sizeof(timing));
                const uint8_t period = assoc_case == AssocCase::bad_beacon ? 1 : 3;
                const uint8_t tim[]{5, 4, 1, period, 0, 0};
                memcpy(beacon_frame + 36, tim, sizeof(tim));
            }
        }
        ++authentication_rx_buffers;
        const unsigned index = commands_sent + authentication_rx_buffers + rejoin_rx_offset;
        used[index] = index + 1;
        if (defer_authentication_completion)
            deferred_authentication_buffer = uint16_t(index + 1);
        else
            receive_status.closed_buffer = uint16_t(index + 1);
    }

    void arp_doorbell(uint32_t value) {
        const unsigned pointer = 0x37 + data_rx_buffers;
        assert(arp_case != ArpCase::unused && commands_sent == (open_station ? 19u : 18u) &&
               authentication_rx_buffers == 2 + data_rx_buffers);
        assert(value == 0x01020000 + pointer + 1);
        const uint8_t slot = pointer & (management_queue_entries - 1);
        const auto& descriptor = data_ring[slot];
        const uint8_t body[]{0xaa, 0xaa, 3, 0, 0, 0,    8,    6,    0,    1,    8,   0,
                             6,    4,    0, 1, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 192, 0,
                             2,    10,   0, 0, 0, 0,    0,    0,    192,  0,    2,   1};
        const TransmitBuffer buffers[]{{20, 0x52000}, {28, 0x52040}, {sizeof(body), 0x52080}};
        assert(descriptor.buffer_count == 3 && data_counts[slot] == 15);
        assert(!memcmp(descriptor.buffers, buffers, sizeof(buffers)));
        const uint8_t first[20]{0x1c, 0, slot, 2, 60, 0, 0, 12, 3};
        const uint8_t sequence = uint8_t((2 + data_rx_buffers) << 4);
        const uint8_t header[]{0,    0x40, 0,    0,    8,    1,    0,        0,    2,    0,
                               0,    0,    0,    0x11, 2,    0x11, 0x22,     0x33, 0x44, 0x55,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, sequence, 0};
        assert(!memcmp(first, authentication_payload, sizeof(first)));
        assert(!memcmp(header, authentication_payload + 64, sizeof(header)));
        assert(!memcmp(body, authentication_payload + 128, sizeof(body)));

        auto* buffer = reply_buffer(commands_sent + authentication_rx_buffers);
        const bool first_reply = arp_case == ArpCase::reply_first;
        auto* tx = buffer + (first_reply ? 128 : 0);
        tx[0] = 52;
        tx[4] = arp_case == ArpCase::missing_completion ? 0x55 : 0x1c;
        tx[6] = slot;
        tx[7] = 2;
        tx[8] = 1;
        tx[44] = 2;
        tx[45] = 1;
        tx[48] = arp_case == ArpCase::rejected_tx ? 0x84 : 1;
        tx[52] = uint8_t(pointer + 1);

        auto* rx = buffer + (first_reply ? 0 : 64);
        rx[0] = 116;
        rx[4] = 0xc1;
        rx[7] = 0x80;
        auto* mpdu = rx + 8;
        mpdu[0] = 64;
        mpdu[3] = 0x20; // Receive padding after a QoS header.
        mpdu[12] = 3;
        mpdu[34] = 1;
        const uint8_t response[]{
            0x88, 2,    0,   0, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 2,    0,    0,    0,    0, 0x11,
            2,    0,    0,   0, 0, 0x12, 0,    0,    0,    0,    0,    0,    0xaa, 0xaa, 3, 0,
            0,    0,    8,   6, 0, 1,    8,    0,    6,    4,    0,    2,    2,    0,    0, 0,
            0,    0x12, 192, 0, 2, 1,    2,    0x11, 0x22, 0x33, 0x44, 0x55, 192,  0,    2, 10,
        };
        static_assert(sizeof(response) == 64);
        memcpy(mpdu + 48, response, sizeof(response));
        if (arp_case == ArpCase::wrong_peer)
            mpdu[48 + 53] = 2;
        ++data_rx_buffers;
        ++authentication_rx_buffers;
        const unsigned index = commands_sent + authentication_rx_buffers;
        used[index] = index + 1;
        receive_status.closed_buffer = uint16_t(index + 1);
    }

    void command_reply(unsigned tail) {
        const unsigned actual = ++commands_sent;
        const unsigned index = actual - rejoin_command_offset;
        assert(tail == (actual & (command_sequence_count - 1)));
        assert(actual <= (live_replies.empty() ? 9u : live_replies.size() / ax::page_size));
        const unsigned sequence = (actual - 1) & (command_sequence_count - 1);
        const unsigned slot = sequence & (command_ring_entries - 1);
        const auto& command = payloads[slot];
        const bool key_check = key_case != KeyCase::unused;
        const bool scanning = check_channels || key_check || passive != ScanCase::unused;
        const bool auth = auth_case != AuthCase::unused;
        const bool association = assoc_case != AssocCase::unused;
        const bool data = arp_case != ArpCase::unused;
        const bool leaving =
            !cancel_after_commands && disconnect_reason && actual >= 20 && actual <= 25;
        const unsigned cancel_step = cancel_after_commands && actual > cancel_after_commands
                                         ? actual - cancel_after_commands
                                         : 0;
        const bool cancel_phy = cancel_after_commands == 9 && cancel_step == 1;
        const auto cancel_station =
            cancel_after_commands == 16 && cancel_step
                ? cancel_step + unsigned(auth_case == AuthCase::protection_expired)
                : 0;
        const unsigned clear_association = data ? 20 : 18;
        const unsigned release_session = open_station  ? 19
                                         : association ? clear_association + 1
                                                       : 17;
        const unsigned peer_index = !auth || index <= 13      ? index
                                    : index > release_session ? index - (release_session - 14)
                                                              : index - 1;
        const bool data_queue = data && (index == 18 || (index == 19 && !open_station));
        const bool mcc = index == (scanning ? 5 : 4) && regulatory != RegulatoryCase::unused;
        uint8_t expected[command_slot_bytes]{};
        uint16_t payload_bytes = 4;
        expected[2] = uint8_t(sequence);
        expected[1] = 1;
        if (index <= 3) {
            const uint8_t codes[]{3, 0, 2};
            expected[0] = codes[slot];
            expected[1] = index == 1 ? 2 : 12;
            expected[8] = index == 1 ? 2 : 0;
        } else if (scanning && index == 4) {
            expected[0] = 0x98;
            expected[8] = 1;
        } else if (mcc) {
            expected[0] = 0xc8;
            payload_bytes = 28;
            expected[8] = expected[9] = 'Z';
            expected[10] = 0x10;
        } else if (index <= 6) {
            expected[0] = 0xc;
            payload_bytes = 12;
            expected[12] = 1;
            expected[16] = 2;
        } else if (cancel_phy) {
            payload_bytes = expect_peer_command(18, expected);
        } else if (cancel_station == 1) {
            expected[0] = 5;
            expected[1] = 3;
            expected[12] = 3;
            payload_bytes = 24;
        } else if (index == 7 || (leaving && actual == 20) || cancel_station == 2) {
            expected[0] = 0x28;
            payload_bytes = 148;
            expected[12] = leaving || cancel_station == 2 ? 2 : 1;
            expected[16] = 5;
            const uint8_t address[]{2, 0x11, 0x22, 0x33, 0x44, 0x55};
            memcpy(expected + 24, address, sizeof(address));
            memset(expected + 32, 0xff, 6);
            expected[40] = 0xf;
            expected[44] = 0x15;
            expected[60] = 0x44;
        } else if (cancel_station >= 3) {
            assert(cancel_station <= 6);
            payload_bytes = expect_peer_command(cancel_station + 12, expected);
        } else if (leaving) {
            if (actual <= 22) {
                payload_bytes = expect_peer_command(15, expected);
                if (actual == 21)
                    expected[16] = 0;
            } else {
                payload_bytes = expect_peer_command(actual - 7, expected);
            }
        } else if (key_check) {
            payload_bytes = expect_key_check_command(index, expected);
        } else if (check_channels) {
            payload_bytes = expect_channel_command(index, expected);
        } else if (auth &&
                   (index == 13 || (association && (index == 17 || index == clear_association)))) {
            expected[0] = 0x28;
            expected[12] = 2;
            expected[16] = 5;
            const uint8_t address[]{2, 0x11, 0x22, 0x33, 0x44, 0x55};
            memcpy(expected + 24, address, sizeof(address));
            expected[32] = 2;
            expected[37] = 0x11;
            expected[40] = 0xf;
            expected[44] = 0x15;
            expected[60] = 0x44;
            expected[124] = 100;
            expected[140] = 1;
            if (index == 17) {
                expected[60] = 4;
                expected[108] = 1;
                const uint8_t dtim[]{0xf0, 0x8f, 1, 0, 0, 0x8f, 1, 0, 5, 0, 0, 0};
                memcpy(expected + 112, dtim, sizeof(dtim));
                expected[132] = 44;
                expected[133] = 1;
                expected[144] = 42;
                const uint8_t gp2[]{0xf0, 0xff, 0xff, 0xff};
                memcpy(expected + 148, gp2, sizeof(gp2));
            }
            payload_bytes = 148;
        } else if (data_queue) {
            expected[0] = 0x17;
            expected[1] = 5;
            expected[12] = 1;
            if (index == 18) {
                expected[24] = 1;
                expected[29] = 0x40;
                expected[30] = 5;
                expected[37] = 0x30;
                expected[38] = 5;
            } else {
                expected[8] = 1;
            }
            payload_bytes = 36;
        } else if (auth && (index == 16 || index == release_session)) {
            expected[0] = 5;
            expected[1] = 3;
            expected[12] = index == 16 ? 1 : 3;
            if (index == 16) {
                expected[20] = 0x84;
                expected[21] = 3;
            }
            payload_bytes = 24;
        } else if (peer_case != PeerCase::unused && index > 8) {
            payload_bytes = expect_peer_command(peer_index, expected);
        } else {
            expected[0] = 0xd;
            payload_bytes = 1940;
            expected[8] = uint8_t((index - 8 + (rejoin_command_offset != 0)) & 1);
            expected[12] = 6;
            expected[16] = 2;
            expected[17] = probe_expected ? 0 : 8;
            expected[44] = 6;
            expected[48] = expected[49] = 110;
            if (scan_only_channel) {
                expected[53] = 1;
                expected[60] = scan_only_channel;
                expected[61] = scan_only_channel <= 14;
                expected[62] = 1;
            } else {
                expected[53] = 2;
                expected[60] = expected[61] = expected[62] = 1;
                expected[68] = 36;
                expected[70] = 1;
            }
            expected[594] = 1;
            if (probe_expected) {
                expected[20] = expected[21] = 10;
                expected[56] = 3;
                const uint8_t segments[]{0,  0, 26, 0, 26, 0, 16, 0, 42, 0,
                                         10, 0, 52, 0, 0,  0, 52, 0, 0,  0};
                const uint8_t probe[]{
                    0x40, 0,    0,    0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x11, 0x22,
                    0x33, 0x44, 0x55, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0,    0,    0,    0,
                    1,    8,    2,    4,    11,   22,   12,   18,   24,   36,   50,   4,    48,
                    72,   96,   108,  1,    8,    12,   18,   24,   36,   48,   72,   96,   108,
                };
                memcpy(expected + 604, segments, sizeof(segments));
                memcpy(expected + 624, probe, sizeof(probe));
                expected[1141] = 3;
                expected[1142] = 'A';
                expected[1144] = 'B';
            }
        }
        expected[4] = uint8_t(payload_bytes);
        expected[5] = uint8_t(payload_bytes >> 8);
        assert(!memcmp(expected, command, sizeof(expected)));
        const uint16_t command_bytes = payload_bytes + 8;
        const uint16_t first_bytes = command_bytes > 20 ? 20 : command_bytes;
        assert(commands[slot].buffer_count == (command_bytes > 20 ? 2 : 1));
        assert(commands[slot].buffers[0].length == first_bytes);
        assert(commands[slot].buffers[0].address == 0xa000 + slot * command_slot_bytes);
        if (command_bytes > 20) {
            assert(commands[slot].buffers[1].length == command_bytes - 20);
            assert(commands[slot].buffers[1].address == 0xa014 + slot * command_slot_bytes);
        }

        if (index == 15 && key_case == KeyCase::missing_install)
            return;
        const unsigned rx_index = actual + authentication_rx_buffers + rejoin_rx_offset;
        auto* reply = reply_buffer(rx_index - 1);
        const bool backlog = index == 8 && passive == ScanCase::busy_queue;
        if (backlog) {
            for (unsigned offset = 0; offset < ax::page_size; offset += 64) {
                reply[offset] = 4;
                reply[offset + 4] = 0x55; // Unrelated notification.
                reply[offset + 7] = 0x80;
            }
            used[index + 1] = index + 2;
            reply = reply_buffer(index);
        }
        if (index == 2) {
            // INIT complete and the command reply share a receive buffer.
            reply[0] = 4;
            reply[4] = 4;
            reply[7] = 0x80;
            reply += 64;
        }
        if (auth && index == 16) {
            // Firmware can notify session start before it acknowledges the control command.
            reply[0] = 20;
            reply[4] = 0xfb;
            reply[5] = 3;
            reply[7] = 0x80;
            reply[12] = auth_case != AuthCase::denied_session;
            reply[16] = 1;
            reply += 64;
        }
        const bool peer = peer_case != PeerCase::unused;
        const bool binding =
            (check_channels || peer || key_check) && index >= 8 && command[0] == 0x2b;
        const bool add_peer = (peer || key_check) && peer_index == 13 && command[0] == 0x18;
        const unsigned length = binding ? (index == short_binding_status ? 7 : 8)
                                : leaving && actual >= 21 && actual <= 22 ? 12
                                : cancel_station == 3                     ? 12
                                : data_queue                              ? 12
                                : add_peer                                ? 8
                                : peer && peer_index == 14 && command[0] == 0x17
                                    ? (peer_case == PeerCase::short_queue ? 11 : 12)
                                : peer && peer_index == 15 && command[0] == 0x17 ? 12
                                : mcc        ? (scanning ? 84 : 32)
                                : index == 3 ? 472
                                             : 4;
        reply[0] = uint8_t(length);
        reply[1] = uint8_t(length >> 8);
        const bool reject = (index == 4 && reject_scan_config) ||
                            (index == 16 && key_case == KeyCase::refused_removal);
        reply[4] = reject ? 2 : command[0];
        reply[5] = reject ? 0 : command[1];
        reply[6] = index == 3 && wrong_sequence ? 0xff : command[2];
        if (index == 3) {
            reply[8] = malformed_nvm;
            reply[12] = 0x1d;
            reply[13] = 0x0a;
            reply[15] = 1;
            reply[16] = 3;
            reply[20] = 3;
            reply[24] = 3;
            reply[28] = regulatory != RegulatoryCase::disabled;
            reply[32] = 51;
        }
        if (mcc) {
            auto* data = reply + 8;
            data[0] = regulatory == RegulatoryCase::rejected ? 4 : 0;
            data[16] = scanning ? 15 : regulatory == RegulatoryCase::bad_count ? 3 : 2;
            data[20] = regulatory == RegulatoryCase::disallowed ? 0 : 0x09;
            if (peer_case == PeerCase::passive_only)
                data[20] = 1;
            if (scanning)
                data[76] = 0x01;
        }
        if (binding && index == bad_binding_status)
            reply[11] = 1;
        if (add_peer) {
            reply[8] = peer_case == PeerCase::station_denied ? 2 : 1;
            reply[11] = 0x80; // The ADD_STA status occupies the low byte.
        }
        if (peer && peer_index == 14 && command[0] == 0x17) {
            reply[8] = reply[9] = 1;
            reply[10] = peer_case == PeerCase::queue_denied;
            reply[12] = 0x34;
            reply[13] = 0x12;
        }
        if (peer && peer_index == 15 && command[0] == 0x17)
            reply[10] = peer_case == PeerCase::remove_denied;
        if (data_queue && index == 18) {
            reply[8] = 2;
            reply[9] = 1;
            reply[12] = 0x37;
        }
        if (!check_channels && !key_check && index >= 8 && (!peer || index == 8))
            scan_notifications(reply, uint8_t((index - 8 + (rejoin_command_offset != 0)) & 1));
        used[rx_index] = rx_index + 1;
        receive_status.closed_buffer = uint16_t(rx_index + 1 + backlog);
    }

    void write(unsigned offset, uint32_t value) {
        assert(offset % 4 == 0 && offset / 4 < sizeof(csr) / sizeof(*csr));
        auto& reg = csr[offset / 4];
        if (offset == 8) {
            reg &= ~value;
            return;
        }
        reg = value;
        if (offset == 0 && scenario == StartupCase::unowned)
            reg &= ~(1u << 22);
        if (offset == 0x24 && (value & 4))
            reg |= 1;
        if (offset == 0x20) {
            if (value & 0x200) {
                requested_stop = true;
                if (scenario != StartupCase::stop_failed)
                    reg |= 0x100;
            }
            if (value & 0x80) {
                assert(!master);
                reg &= ~0x80;
                reset_after_dma |= requested_master;
            }
        }
        if (offset == 0x44c && csr[0x444 / 4] == 0x03a05c44) {
            assert(value == 1 && master && csr[0x40 / 4] == 0x9000 && !csr[0x44 / 4]);
            assert(csr[0x0c / 4] & 1);
            if (scenario != StartupCase::timeout)
                csr[8 / 4] |= 1;
        }
        if (offset == 0x1c80) {
            assert(master);
            if (!sent_doorbell) {
                assert(value == 2040);
                sent_doorbell = true;
                used[0] = scenario == StartupCase::bad_buffer ? 0 : 1;
                receive_status.closed_buffer = 1;
            } else {
                assert(recycle && value == receive_updates * 8);
                if (!receive_updates)
                    assert(free_ring[2047] == descriptors[0]);
                ++receive_updates;
            }
        }
        if (offset == 0x460) {
            assert(master && sent_doorbell);
            if (value >> 16 == 0x102)
                arp_doorbell(value);
            else if (value >> 16)
                authentication_doorbell(value);
            else
                command_reply(value);
        }
    }

    FirmwareBootIo make_io() {
        return {
            this,
            [](void* ptr, unsigned offset) {
                return static_cast<StartupFixture*>(ptr)->csr[offset / 4];
            },
            [](void* ptr, unsigned offset, uint32_t value) {
                static_cast<StartupFixture*>(ptr)->write(offset, value);
            },
            [](void* ptr, unsigned usec) {
                auto& model = *static_cast<StartupFixture*>(ptr);
                if (model.commands_sent >= 8 && !model.requested_stop && usec == 1000)
                    ++model.scan_delays;
                return true;
            },
            [](void* ptr, bool enable) {
                auto& model = *static_cast<StartupFixture*>(ptr);
                model.requested_master |= enable;
                if (enable && model.scenario == StartupCase::bus_master_failed)
                    return false;
                if (!enable)
                    assert(model.requested_stop);
                model.master = enable;
                return true;
            },
            [](void* ptr, unsigned id) -> uint8_t* {
                auto& model = *static_cast<StartupFixture*>(ptr);
                if (id == 1)
                    return model.buffer;
                return id >= 2 ? model.reply_buffer(id - 2) : nullptr;
            },
        };
    }

    FirmwareBootMemory make_memory(bool nvm, bool repost) {
        FirmwareBootMemory memory{0x9000, &receive_status, used};
        recycle = repost;
        if (recycle) {
            initialize_intel_wifi_receive_descriptors(free_ring, descriptors);
            memory.free_ring = free_ring;
            memory.receive_descriptors = descriptors;
        }
        if (nvm) {
            memory.commands = commands;
            memory.command_payloads = &payloads;
            memory.command_dma = 0xa000;
        }
        if (peer_case != PeerCase::unused)
            memory.peer_queue = {0x50000, 0x51000};
        if (auth_case != AuthCase::unused)
            memory.authentication = {management_ring, management_counts, authentication_payload,
                                     0x52000};
        if (arp_case != ArpCase::unused) {
            memory.data_queue = {0x53000, 0x54000};
            memory.data_transmit = {data_ring, data_counts, authentication_payload, 0x52000};
        }
        return memory;
    }

    FirmwareBootResult run(bool nvm = false, const ScanChecks* scan = nullptr) {
        const auto io = make_io();
        auto memory = make_memory(nvm, scan && scan->check >= FirmwareCheck::rescan);
        return start_and_stop_quz(io, memory, scan);
    }
};

void check_startup() {
    {
        PassiveScan scan{};
        scan.id = 1;
        const FirmwarePacket accepted{0xd, 1, 5, nullptr, 0};
        const uint8_t data[16]{1, 0, 0, 0, 0, 0, 1};
        const FirmwarePacket complete{0xf, 0, 0x8000, data, sizeof(data)};
        PassiveScanExchange delayed(scan, 5, 25);
        delayed.expire(2024);
        assert(delayed.outcome() == ScanOutcome::pending);
        delayed.observe(accepted, 2024);
        delayed.expire(14023);
        assert(delayed.outcome() == ScanOutcome::pending);
        delayed.expire(14024);
        delayed.observe(complete, 14024);
        assert(delayed.outcome() == ScanOutcome::completion_timeout);
        PassiveScanExchange early(scan, 5, 1000);
        early.observe(complete, 1001);
        const FirmwarePacket reject{2, 0, 5, nullptr, 0};
        early.observe(reject, 1002);
        assert(early.outcome() == ScanOutcome::rejected);
    }
    uint8_t buffer[ax::page_size]{};
    alive_packet(buffer);
    assert(read_alive_notification(buffer, sizeof(buffer)) == AlivePacket::success);
    assert(read_alive_notification(buffer, 75) == AlivePacket::malformed);
    buffer[73] = 0;
    assert(read_alive_notification(buffer, sizeof(buffer)) == AlivePacket::rejected);
    buffer[66] = 1;
    assert(read_alive_notification(buffer, sizeof(buffer)) == AlivePacket::malformed);

    for (auto scenario :
         {StartupCase::good, StartupCase::blocked, StartupCase::unowned, StartupCase::timeout,
          StartupCase::bad_buffer, StartupCase::stop_failed, StartupCase::bus_master_failed}) {
        StartupFixture model(scenario);
        const auto outcome = model.run();
        const bool attempted_dma =
            scenario != StartupCase::blocked && scenario != StartupCase::unowned;
        assert(model.requested_master == attempted_dma && !model.master);
        assert(model.requested_stop == attempted_dma && model.reset_after_dma == attempted_dma);
        assert(outcome.alive ==
               (scenario == StartupCase::good || scenario == StartupCase::stop_failed));
        assert(outcome.dma_idle == (scenario != StartupCase::stop_failed));
    }
    std::puts("AX201_STARTUP_MODEL_PASS");

    for (int scenario = 0; scenario < 3; ++scenario) {
        StartupFixture model(StartupCase::good);
        model.malformed_nvm = scenario == 1;
        model.wrong_sequence = scenario == 2;
        const auto outcome = model.run(true);
        assert(outcome.alive && outcome.dma_idle && model.reset_after_dma &&
               model.commands_sent == 3);
        if (scenario == 0) {
            assert(outcome.nvm.version == 0xa1d && outcome.nvm.bands == 3);
            assert(outcome.nvm.channel_count == 51 && outcome.nvm.addresses == 1);
        } else {
            assert(!outcome.nvm.version);
        }
    }
    std::puts("AX201_NVM_MODEL_PASS");

    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        StartupFixture model(StartupCase::good);
        model.reject_scan_config = scenario == 1;
        model.malformed_nvm = scenario == 3;
        const ScanChecks scan{{scenario == 2 ? uint8_t(4) : uint8_t(1), 2},
                              FirmwareCheck::scan_config};
        const auto outcome = model.run(true, &scan);
        const char* expected[] = {
            "firmware scan configuration accepted",
            "firmware scan configuration failed",
            "firmware and NVM antenna masks do not overlap",
            "firmware returned invalid NVM data",
        };
        assert(!strcmp(outcome.status, expected[scenario]));
        assert(outcome.alive && outcome.dma_idle && model.reset_after_dma && !model.master);
        assert(model.commands_sent == (scenario >= 2 ? 3u : 4u));
    }
    std::puts("AX201_SCAN_CONFIG_MODEL_PASS");

    struct RegulatoryTest {
        RegulatoryCase scenario;
        const char* status;
        unsigned commands;
    };

    for (const auto& test :
         {RegulatoryTest{RegulatoryCase::valid,
                         "firmware regulatory profile and scan configuration passed", 5},
          {RegulatoryCase::bad_count, "firmware returned an invalid regulatory profile", 4},
          {RegulatoryCase::disallowed, "firmware regulatory profile has no permitted channels", 4},
          {RegulatoryCase::disabled, "firmware NVM has location-aware regulation disabled", 3},
          {RegulatoryCase::rejected, "firmware returned an invalid regulatory profile", 4}}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = test.scenario;
        const ScanChecks scan{{1, 2}, FirmwareCheck::regulatory};
        const auto outcome = model.run(true, &scan);
        assert(!strcmp(outcome.status, test.status) && model.commands_sent == test.commands);
        assert(outcome.alive && outcome.dma_idle && model.reset_after_dma && !model.master);
        if (test.scenario == RegulatoryCase::valid) {
            assert(!strcmp(outcome.regulatory.country, "00"));
            assert(outcome.regulatory.valid_channels == 1 && outcome.regulatory.channel_slots == 2);
            assert(outcome.regulatory.flags[0] == 9 && outcome.regulatory.flags[1] == 0);
        }
    }
    std::puts("AX201_REGULATORY_MODEL_PASS");

    for (const auto test : {ScanCase::complete, ScanCase::early_completion, ScanCase::aborted,
                            ScanCase::timeout, ScanCase::no_reply, ScanCase::busy_queue}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = test;
        ScanElementStorage elements{};
        const ScanChecks scan{{1, 2}, FirmwareCheck::passive_scan, &elements};
        const auto outcome = model.run(true, &scan);
        assert(outcome.alive && outcome.dma_idle && model.reset_after_dma && !model.master);
        assert(model.commands_sent == 8 && outcome.passive.channel_count == 2);
        if (test == ScanCase::busy_queue)
            assert(model.scan_delays == 1);
        if (test == ScanCase::timeout) {
            assert(!strcmp(outcome.status, "passive scan completion timed out"));
            assert(!outcome.successful);
        } else if (test == ScanCase::aborted) {
            assert(!strcmp(outcome.status, "firmware aborted the passive scan"));
            assert(!outcome.successful);
        } else if (test == ScanCase::no_reply) {
            assert(!strcmp(outcome.status, "passive scan command reply timed out"));
            assert(!outcome.successful && !outcome.completed_scans);
        } else {
            assert(!strcmp(outcome.status, "firmware passive scan complete"));
            assert(outcome.successful && outcome.passive.access_point_count == 1);
            assert(outcome.passive.elements == &elements);
            assert(outcome.passive.access_points[0].beacon_ie_bytes == 2);
            assert(elements.records[0].beacon[0] == 0 && elements.records[0].beacon[1] == 0);
        }
    }
    std::puts("AX201_PASSIVE_SCAN_MODEL_PASS");
    for (const auto test : {ScanCase::early_completion, ScanCase::second_aborted}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = test;
        ScanElementStorage elements{};
        const ScanChecks scans{{1, 2}, FirmwareCheck::rescan, &elements};
        const auto result = model.run(true, &scans);
        const bool complete = test == ScanCase::early_completion;
        assert(result.completed_scans == (complete ? 2u : 1u) && result.successful == complete);
        assert(model.commands_sent == 9 && result.dma_idle && model.reset_after_dma &&
               !model.master);
        assert(model.receive_updates == 2);
        assert(result.passive.id == 1 && result.passive.access_point_count == 1);
        assert(result.passive.access_points[0].bssid[5] == 0x21);
        assert(!strcmp(result.status, complete ? "two firmware passive scans complete"
                                               : "firmware aborted the passive scan"));
    }
    std::puts("AX201_REPEAT_SCAN_MODEL_PASS");
}

void check_live_scans() {
    StartupFixture model(StartupCase::good);
    model.regulatory = RegulatoryCase::valid;
    model.passive = ScanCase::early_completion;
    model.live_replies.resize(300 * ax::page_size);
    const auto io = model.make_io();
    const auto memory = model.make_memory(true, true);
    LiveScanSession session(io, memory);
    const auto boot = start_live_quz(session, {1, 2});
    assert(boot.successful && !boot.dma_idle && session.running && model.master);
    assert(model.commands_sent == 7 && session.next_command == 7 && !session.active);

    ScanElementStorage elements{};
    for (unsigned scan = 0; scan < 260; ++scan) {
        const uint64_t now = 10000 + 20000ull * scan;
        assert(submit_live_scan(session, elements, now) == 0 && session.active);
        assert(submit_live_scan(session, elements, now) == -16);
        assert(poll_live_scan(session, now + 50) == ScanOutcome::complete && !session.active);
        assert(session.scan.access_point_count == 1 && session.scan.id == (scan & 1));
        assert(!model.scan_delays && session.running && model.master);
    }
    assert(model.commands_sent == 267 && session.next_command == 11);
    assert(session.channels.entries[1].frequency_mhz == 2417 &&
           !session.channels.entries[1].allowed);
    assert(submit_live_scan(session, elements, 5500000, {.channels = uint64_t(1) << 1}) == -22);
    assert(model.commands_sent == 267 && !session.active);
    assert(session.channels.entries[14].frequency_mhz == 5180 &&
           session.channels.entries[14].allowed);
    model.scan_only_channel = 36;
    assert(submit_live_scan(session, elements, 5500001, {.channels = uint64_t(1) << 14}) == 0);
    assert(poll_live_scan(session, 5500051) == ScanOutcome::complete && !session.active);
    assert(session.scan.channel_count == 1 && session.scan.channels[0] == 36);
    assert(!session.scan.access_point_count);
    model.scan_only_channel = 0;
    std::puts("AX201_FILTERED_SCAN_MODEL_PASS");
    model.passive = ScanCase::timeout;
    assert(submit_live_scan(session, elements, 6000000) == 0);
    assert(poll_live_scan(session, 6000001) == ScanOutcome::pending);
    assert(poll_live_scan(session, 6012001) == ScanOutcome::completion_timeout);
    assert(stop_live_quz(session) && !session.running && model.reset_after_dma && !model.master);
    assert(submit_live_scan(session, elements, 6012002) == -95);
    std::puts("AX201_LIVE_SCAN_MODEL_PASS scans=260");
}

void check_active_scan() {
    for (const auto mode : {ScanCase::complete, ScanCase::second_aborted}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = mode;
        const auto io = model.make_io();
        const auto memory = model.make_memory(true, true);
        LiveScanSession session(io, memory);
        assert(start_live_quz(session, {1, 2}).successful);
        assert(session.channels.entries[0].active && !session.channels.entries[14].active);
        ScanRequest request;
        request.ssids.count = 2;
        request.ssids.entries[1] = {{'A', 0, 'B'}, 3};
        ScanElementStorage elements{};
        model.probe_expected = true;
        model.scan_only_channel = 1;
        assert(submit_live_scan(session, elements, 100, request) == 0);
        assert(model.commands_sent == 8 && session.active && session.scan.id == 0);
        assert(session.scan.channel_count == 1 && session.scan.channels[0] == 1);

        model.probe_expected = false;
        model.scan_only_channel = model.notification_channel = 36;
        assert(poll_live_scan(session, 150) == ScanOutcome::pending);
        assert(model.commands_sent == 9 && session.active && session.scan.id == 1);
        assert(session.scan.channel_count == 1 && session.scan.channels[0] == 36);
        assert(session.scan.access_point_count == 1);
        assert(submit_live_scan(session, elements, 160, request) == -16);
        const auto outcome = poll_live_scan(session, 200);
        assert(outcome ==
               (mode == ScanCase::complete ? ScanOutcome::complete : ScanOutcome::aborted));
        assert(!session.active && session.scan.access_point_count == 2);
        assert(session.scan.access_points[0].frequency_mhz == 2412);
        assert(session.scan.access_points[1].frequency_mhz == 5180);
        assert(stop_live_quz(session) && !model.master && model.reset_after_dma);
    }
    std::puts("AX201_ACTIVE_SCAN_MODEL_PASS");
}

void check_channel_contexts() {
    struct Case {
        StartupCase startup;
        bool dual_lmac;
        unsigned refused, shortened, commands, completed;
        const char* status;
    };

    const Case cases[]{
        {StartupCase::good, false, 0, 0, 18, 2, "operating channel binding check passed"},
        {StartupCase::good, true, 0, 0, 18, 2, "operating channel binding check passed"},
        {StartupCase::good, false, 11, 0, 11, 0, "station channel binding failed"},
        {StartupCase::good, false, 0, 17, 17, 1, "station channel unbind failed"},
        {StartupCase::stop_failed, false, 0, 0, 18, 2,
         "operating channel check could not stop DMA"},
    };
    for (const auto& test : cases) {
        StartupFixture model(test.startup);
        model.check_channels = true;
        model.dual_lmac = test.dual_lmac;
        model.regulatory = RegulatoryCase::valid;
        model.bad_binding_status = test.refused;
        model.short_binding_status = test.shortened;
        model.live_replies.resize(18 * ax::page_size);
        const ScanChecks request{{1, 2}, FirmwareCheck::channel_context, nullptr, test.dual_lmac};
        const auto result = model.run(true, &request);
        const bool stopped = test.startup != StartupCase::stop_failed;
        assert(result.dma_idle == stopped && !model.master && model.reset_after_dma);
        assert(result.successful == (stopped && !test.refused && !test.shortened));
        assert(result.alive && !result.completed_scans &&
               result.checked_channels == test.completed);
        assert(model.commands_sent == test.commands && !strcmp(result.status, test.status));
    }
    std::puts("AX201_CHANNEL_CONTEXT_MODEL_PASS");
}

void check_security_key_commands() {
    constexpr struct {
        StartupCase startup;
        KeyCase key;
        unsigned commands;
        const char* status;
    } cases[]{
        {StartupCase::good, KeyCase::complete, 20,
         "CCMP pairwise and group key commands acknowledged"},
        {StartupCase::good, KeyCase::refused_removal, 16,
         "firmware did not acknowledge group key removal"},
        {StartupCase::good, KeyCase::missing_install, 15,
         "firmware did not acknowledge group key installation"},
        {StartupCase::stop_failed, KeyCase::missing_install, 15,
         "firmware did not acknowledge group key installation"},
    };

    for (const auto& test : cases) {
        StartupFixture model(test.startup);
        model.regulatory = RegulatoryCase::valid;
        model.key_case = test.key;
        model.live_replies.resize(20 * ax::page_size);
        const ScanChecks request{{1, 2}, FirmwareCheck::security_key};
        const auto result = model.run(true, &request);
        const bool stopped = test.startup == StartupCase::good;
        assert(result.alive && result.dma_idle == stopped && model.reset_after_dma);
        assert(result.successful == (test.key == KeyCase::complete));
        assert(!result.completed_scans && model.commands_sent == test.commands);
        assert(!strcmp(result.status, test.status));
        const uint8_t blank[command_slot_bytes]{};
        assert(!memcmp(model.payloads[13], blank, sizeof(blank)));
        assert((memcmp(model.payloads[14], blank, sizeof(blank)) == 0) == stopped);
    }
    std::puts("AX201_SECURITY_KEY_COMMAND_MODEL_PASS");
}

void check_peer_queues() {
    const ScanChecks request{{1, 2}, FirmwareCheck::peer_queue};
    {
        StartupFixture model(StartupCase::good);
        const auto io = model.make_io();
        auto memory = model.make_memory(true, true);
        memory.peer_queue = {0x51000, 0x51000};
        const auto result = start_and_stop_quz(io, memory, &request);
        assert(!strcmp(result.status, "invalid management queue DMA addresses"));
        assert(!model.requested_master && !model.commands_sent && result.dma_idle);
    }
    assert(!valid_peer_queue_memory({0x50001, 0x51000}));
    assert(!valid_peer_queue_memory({0x100000000, 0x51000}));
    assert(valid_peer_queue_memory({0x50000, 0x51000}));

    struct Case {
        StartupCase startup;
        PeerCase response;
        unsigned commands;
        bool queue_allocated;
        const char* status;
    };

    const Case cases[]{
        {StartupCase::good, PeerCase::success, 18, true,
         "peer station and management queue check passed"},
        {StartupCase::good, PeerCase::passive_only, 8, false,
         "no infrastructure access point on a channel permitted for active operation"},
        {StartupCase::good, PeerCase::station_denied, 13, false,
         "firmware rejected the unassociated peer station"},
        {StartupCase::good, PeerCase::short_queue, 14, false,
         "firmware management queue allocation failed"},
        {StartupCase::good, PeerCase::queue_denied, 14, false,
         "firmware management queue allocation failed"},
        {StartupCase::good, PeerCase::remove_denied, 15, true,
         "firmware management queue removal failed"},
        {StartupCase::stop_failed, PeerCase::success, 18, true,
         "peer queue check could not stop DMA"},
    };
    for (const auto& test : cases) {
        StartupFixture model(test.startup);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = test.response;
        model.live_replies.resize(18 * ax::page_size);
        const auto result = model.run(true, &request);
        assert(model.commands_sent == test.commands);
        assert(!strcmp(result.status, test.status));
        const bool stopped = test.startup != StartupCase::stop_failed;
        assert(result.dma_idle == stopped && !model.master && model.reset_after_dma);
        assert(result.alive && result.completed_scans == 1);
        assert(result.successful == (stopped && test.response == PeerCase::success));
        assert(result.peer_queue.id == (test.queue_allocated ? 257 : 0));
        assert(result.peer_queue.write_pointer == (test.queue_allocated ? 0x34 : 0));
    }

    uint8_t allocation[8]{};
    PeerQueue queue{23, 0x40};
    assert(!parse_station_queue({0x17, 5, 0, allocation, sizeof(allocation)}, queue));
    allocation[1] = 2; // One beyond the last supported queue.
    assert(!parse_station_queue({0x17, 5, 0, allocation, sizeof(allocation)}, queue));
    assert(queue.id == 23 && queue.write_pointer == 0x40);
    std::puts("AX201_PEER_QUEUE_MODEL_PASS");
}

void check_authentication_exchange() {
    AuthenticationTarget target;
    assert(parse_authentication_target("02:00:00:00:00:11", target));
    assert(!parse_authentication_target("01:00:00:00:00:11", target));
    assert(!parse_authentication_target("02:00:00-00:00:11", target));
    assert(!parse_authentication_target("00:00:00:00:00:00", target));
    assert(target.bssid[0] == 2 && target.bssid[5] == 0x11);
    const uint8_t rates[]{1, 3, 0x82, 0x98, 0x8c};
    assert(authentication_rate(rates, sizeof(rates), false, 3) == 0x4000);
    assert(authentication_rate(rates, sizeof(rates), true, 2) == 0x8100);
    assert(!authentication_rate(rates, sizeof(rates) - 1, false, 3));

    struct Case {
        AuthCase response;
        unsigned commands;
        bool transmitted;
        const char* status;
    };

    const Case cases[]{
        {AuthCase::accepted, 21, true, "open-system authentication exchange passed"},
        {AuthCase::reply_first, 21, true, "open-system authentication exchange passed"},
        {AuthCase::denied_session, 16, false, "firmware session protection failed"},
        {AuthCase::denied_tx, 16, true, "firmware could not deliver the authentication request"},
        {AuthCase::denied_ap, 16, true, "access point refused open-system authentication"},
        {AuthCase::reply_timeout, 16, true, "open-system authentication timed out"},
        {AuthCase::wrong_target, 8, false,
         "requested access point not found on a permitted active channel"},
    };
    for (const auto& test : cases) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = test.response;
        model.live_replies.resize(22 * ax::page_size);
        ScanElementStorage elements{};
        ScanChecks request{{1, 2}, FirmwareCheck::authenticate, &elements, false, target};
        if (test.response == AuthCase::wrong_target)
            request.target.bssid[5] = 0x22;
        const auto result = model.run(true, &request);
        assert(model.commands_sent == test.commands && !strcmp(result.status, test.status));
        assert(bool(model.authentication_rx_buffers) == test.transmitted);
        assert(result.alive && result.dma_idle && !model.master && model.reset_after_dma);
        assert(result.successful ==
               (test.response == AuthCase::accepted || test.response == AuthCase::reply_first));
    }
    std::puts("AX201_AUTHENTICATION_MODEL_PASS");
}

void check_association_exchange() {
    struct Case {
        AssocCase response;
        AuthCase auth_response;
        unsigned commands, transmits;
        uint16_t aid;
        const char* status;
    };

    const Case cases[]{
        {AssocCase::accepted, AuthCase::accepted, 23, 3, 42,
         "open-system association, beacon synchronization, and deauthentication passed"},
        {AssocCase::accepted, AuthCase::reply_first, 23, 3, 42,
         "open-system association, beacon synchronization, and deauthentication passed"},
        {AssocCase::refused, AuthCase::accepted, 16, 2, 0, "access point refused association"},
        {AssocCase::invalid_id, AuthCase::accepted, 16, 2, 0,
         "access point returned an invalid association reply"},
        {AssocCase::secured, AuthCase::accepted, 8, 0, 0,
         "association check requires a named open access point with supported legacy rates"},
        {AssocCase::bad_beacon, AuthCase::accepted, 16, 3, 42,
         "associated access point beacon timed out"},
        {AssocCase::leave_failed, AuthCase::accepted, 17, 3, 42,
         "firmware could not deliver the management frame"},
    };
    for (const auto& test : cases) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = test.auth_response;
        model.assoc_case = test.response;
        model.live_replies.resize(32 * ax::page_size);
        ScanElementStorage elements{};
        const ScanChecks request{
            {1, 2}, FirmwareCheck::associate, &elements, false, {{2, 0, 0, 0, 0, 0x11}}};
        const auto result = model.run(true, &request);
        assert(model.commands_sent == test.commands && !strcmp(result.status, test.status));
        assert(model.authentication_rx_buffers == test.transmits);
        assert(result.association_id == test.aid);
        assert(result.alive && result.dma_idle && !model.master && model.reset_after_dma);
        assert(result.successful == (test.response == AssocCase::accepted));
    }

    std::puts("AX201_ASSOCIATION_MODEL_PASS");
}

void check_associated_arp() {
    AuthenticationTarget target;
    assert(parse_data_probe_target("02:00:00:00:00:11,192.0.2.10,192.0.2.1", target));
    assert(!parse_data_probe_target("02:00:00:00:00:11,192.0.2.256,192.0.2.1", target));
    assert(!parse_data_probe_target("02:00:00:00:00:11,192.0.2.1,192.0.2.1", target));
    assert(!parse_data_probe_target("02:00:00:00:00:11,192.0.2.10,192.0.2.1,0", target));
    assert(target.source_ipv4 == 0xc000020a && target.peer_ipv4 == 0xc0000201);
    for (const auto scenario :
         {ArpCase::accepted, ArpCase::reply_first, ArpCase::wrong_peer, ArpCase::rejected_tx}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = AuthCase::accepted;
        model.assoc_case = AssocCase::accepted;
        model.arp_case = scenario;
        model.live_replies.resize(32 * ax::page_size);
        ScanElementStorage elements{};
        const ScanChecks request{{1, 2}, FirmwareCheck::data_probe, &elements, false, target};
        const auto result = model.run(true, &request);
        const bool success = scenario == ArpCase::accepted || scenario == ArpCase::reply_first;
        const char* status = success ? "associated ARP exchange and deauthentication passed"
                             : scenario == ArpCase::wrong_peer
                                 ? "associated ARP exchange timed out"
                                 : "firmware did not confirm ARP transmission";
        assert(!strcmp(result.status, status) && result.successful == success);
        assert(model.commands_sent == (success ? 25u : 18u));
        assert(model.authentication_rx_buffers == (success ? 4u : 3u) &&
               model.data_rx_buffers == 1);
        assert(result.association_id == 42 && result.alive && result.dma_idle && !model.master &&
               model.reset_after_dma);
    }
    std::puts("AX201_ASSOCIATED_ARP_MODEL_PASS");
}

void check_open_station() {
    const uint8_t arp[]{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 8,    6,
        0,    1,    8,    0,    6,    4,    0, 1,    2,    0x11, 0x22, 0x33, 0x44, 0x55,
        192,  0,    2,    10,   0,    0,    0, 0,    0,    0,    192,  0,    2,    1,
    };
    AuthenticationTarget target;
    assert(parse_authentication_target("02:00:00:00:00:11", target));
    for (const auto scenario :
         {ArpCase::accepted, ArpCase::rejected_tx, ArpCase::missing_completion}) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = AuthCase::accepted;
        model.assoc_case = AssocCase::accepted;
        model.arp_case = scenario;
        model.open_station = true;
        model.live_replies.resize(32 * ax::page_size);
        const auto io = model.make_io();
        const auto memory = model.make_memory(true, true);
        LiveScanSession session(io, memory);
        ScanElementStorage elements{};
        const auto result = start_live_quz(session, {1, 2}, &target, &elements);
        assert(result.successful && !result.dma_idle && result.association_id == 42 &&
               model.master);
        assert(session.running && session.station.queue.id == 0x102 && model.commands_sent == 19);
        assert(submit_live_data(session, arp, 8, 20) == -22);
        assert(submit_live_data(session, arp, sizeof(arp), 20) == 0);
        assert(submit_live_data(session, arp, sizeof(arp), 21) == -11);

        struct Observations {
            unsigned received = 0, completed = 0, rejected = 0;
        } seen;

        const auto poll = [&](uint64_t now) {
            return poll_live_station(
                session, now, &seen,
                [](void* owner, const uint8_t* data, size_t length) {
                    assert(length == 42 && data[0] == 2 && data[5] == 0x55 && data[11] == 0x12);
                    assert(data[12] == 8 && data[13] == 6 && data[21] == 2 && data[41] == 10);
                    ++static_cast<Observations*>(owner)->received;
                },
                [](void* owner, size_t length, bool failed) {
                    assert(length == 42);
                    auto& stats = *static_cast<Observations*>(owner);
                    ++stats.completed;
                    stats.rejected += failed;
                });
        };
        assert(poll(22) && seen.received == 1);
        if (scenario == ArpCase::missing_completion) {
            assert(seen.completed == 0 && !poll(1020) && session.station.pending_bytes == 42);
        } else {
            assert(seen.completed == 1 && seen.rejected == (scenario == ArpCase::rejected_tx));
            assert(submit_live_data(session, arp, sizeof(arp), 23) == 0 && poll(24));
            assert(seen.received == 2 && seen.completed == 2);
            assert(session.station.queue.write_pointer == 0x39 && !session.station.pending_bytes);
            if (scenario == ArpCase::accepted) {
                const unsigned index = model.receive_status.closed_buffer;
                auto* packet = model.reply_buffer(index - 1);
                const uint8_t disconnect[]{0xc0, 0, 0, 0,    2, 0x11, 0x22, 0x33, 0x44,
                                           0x55, 2, 0, 0,    0, 0,    0x11, 2,    0,
                                           0,    0, 0, 0x11, 0, 0,    8,    0};
                packet[0] = 4 + 48 + sizeof(disconnect);
                packet[4] = 0xc1;
                packet[7] = 0x80;
                packet[8] = sizeof(disconnect);
                packet[8 + 12] = 3;
                packet[8 + 34] = 1;
                memcpy(packet + 8 + 48, disconnect, sizeof(disconnect));
                model.used[index] = index + 1;
                model.receive_status.closed_buffer = uint16_t(index + 1);
                assert(poll(25));
                assert(session.leave.phase == LeavePhase::drain && session.leave.from_ap);
                assert(session.leave.reason == 8 && !session.leave.send_deauthentication);
            } else {
                assert(poll(3000) && session.leave.phase == LeavePhase::idle);
                assert(poll(3022) && session.leave.phase == LeavePhase::drain);
                assert(!session.leave.reason && !session.leave.from_ap &&
                       !session.leave.send_deauthentication);
            }
        }
        assert(stop_live_quz(session) && !session.running && !model.master &&
               model.reset_after_dma);
        assert(submit_live_data(session, arp, sizeof(arp), 4000) == -95);
    }
    std::puts("AX201_OPEN_STATION_MODEL_PASS");
}

void check_rejoin(StartupFixture& model, LiveScanSession& session, ScanElementStorage& scan,
                  const StationRequest& request, uint64_t now) {
    const auto previous_commands = model.commands_sent;
    model.rejoin_command_offset = previous_commands - 7;
    model.rejoin_rx_offset = model.authentication_rx_buffers;
    model.authentication_rx_buffers = model.data_rx_buffers = model.cancel_after_commands = 0;
    model.disconnect_reason = 0;
    model.auth_case = AuthCase::accepted;
    model.assoc_case = AssocCase::accepted;
    assert(submit_live_scan(session, scan, ++now) == 0);
    assert(poll_live_scan(session, ++now) == ScanOutcome::complete);
    assert(submit_live_join(session, session.scan, request) == 0);
    auto joined = JoinOutcome::pending;
    for (const auto deadline = now + 98; now < deadline && joined == JoinOutcome::pending;)
        joined = poll_live_join(session, ++now);
    assert(joined == JoinOutcome::connected && model.commands_sent == previous_commands + 12);
    assert(session.station.queue.id == 0x102 && session.station.next_sequence == 2);
}

void check_live_departure(StartupFixture& model, LiveScanSession& session, ScanElementStorage& scan,
                          const StationRequest& request, ArpCase pending, bool missed_beacons) {
    const uint8_t arp[]{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 8,    6,
        0,    1,    8,    0,    6,    4,    0, 1,    2,    0x11, 0x22, 0x33, 0x44, 0x55,
        192,  0,    2,    10,   0,    0,    0, 0,    0,    0,    192,  0,    2,    1,
    };
    if (pending != ArpCase::unused)
        assert(submit_live_data(session, arp, sizeof(arp), 25) == 0);
    model.disconnect_reason = 8;
    assert(submit_live_leave(session, 0) == -22);
    const auto transmissions = model.authentication_rx_buffers;
    uint64_t now = 27;
    if (missed_beacons) {
        assert(pending == ArpCase::unused);
        assert(poll_live_station(session, now, nullptr, nullptr, nullptr));
        now += 3000;
        assert(poll_live_station(session, now, nullptr, nullptr, nullptr));
        assert(session.leave.phase == LeavePhase::drain && !session.leave.send_deauthentication);
    } else {
        assert(submit_live_leave(session, model.disconnect_reason) == 0);
    }
    assert(submit_live_leave(session, model.disconnect_reason) == -16);
    assert(submit_live_join(session, session.scan, request) == -16);
    assert(submit_live_scan(session, scan, 26) == -16);
    assert(submit_live_data(session, arp, sizeof(arp), 26) == -95);
    assert(model.commands_sent == 19 && model.authentication_rx_buffers <= 3);

    unsigned completions = 0;
    const auto complete = [](void* context, size_t length, bool failed) {
        assert(length == 42 && failed);
        ++*static_cast<unsigned*>(context);
    };
    auto result = poll_live_leave(session, now, &completions, complete);
    if (pending == ArpCase::missing_completion) {
        assert(result == LeaveOutcome::pending);
        assert(poll_live_leave(session, 1025, &completions, complete) == LeaveOutcome::failed);
        assert(!completions && session.station.pending_bytes == sizeof(arp));
        assert(model.commands_sent == 19 && model.authentication_rx_buffers == 3);
        return;
    }
    for (const auto deadline = now + 72; now < deadline && result == LeaveOutcome::pending;)
        result = poll_live_leave(session, ++now, &completions, complete);
    assert(result == LeaveOutcome::disconnected && completions == (pending != ArpCase::unused));
    assert(!session.station.queue.id && !session.station.management.id && !model.requested_stop);
    assert(model.commands_sent == 25 && submit_live_leave(session, 3) == 0);
    assert(model.authentication_rx_buffers == transmissions + !missed_beacons);

    check_rejoin(model, session, scan, request, now);
}

void check_live_connection() {
    constexpr struct {
        AuthCase authentication;
        AssocCase association;
        ArpCase pending;
        bool secured = false;
        bool missed_beacons = false;
    } cases[]{
        {AuthCase::accepted, AssocCase::accepted, ArpCase::rejected_tx},
        {AuthCase::accepted, AssocCase::accepted, ArpCase::missing_completion},
        {AuthCase::reply_first, AssocCase::leave_failed, ArpCase::unused},
        {AuthCase::accepted, AssocCase::refused, ArpCase::unused},
        {AuthCase::denied_ap, AssocCase::accepted, ArpCase::unused},
        {AuthCase::denied_tx, AssocCase::accepted, ArpCase::unused},
        {AuthCase::reply_timeout, AssocCase::accepted, ArpCase::unused},
        {AuthCase::protection_expired, AssocCase::accepted, ArpCase::unused},
        {AuthCase::accepted, AssocCase::bad_beacon, ArpCase::unused},
        {AuthCase::accepted, AssocCase::accepted, ArpCase::unused, true},
        {AuthCase::accepted, AssocCase::accepted, ArpCase::unused, false, true},
    };

    for (const auto& [authentication, association, pending, secured, missed_beacons] : cases) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = authentication;
        model.assoc_case = association;
        model.arp_case = pending == ArpCase::unused ? ArpCase::accepted : pending;
        model.open_station = true;
        model.live_replies.resize(48 * ax::page_size);
        const auto io = model.make_io();
        const auto memory = model.make_memory(true, true);
        LiveScanSession session(io, memory);
        assert(start_live_quz(session, {1, 2}).successful);
        ScanElementStorage scan{};
        StationRequest request{{{'l', 'a', 'b'}, 3}, {2, 0, 0, 0, 0, 0x11}, 2412};
        assert(submit_live_leave(session, 3) == 0);
        assert(submit_live_join(session, session.scan, request) == -2);
        assert(submit_live_scan(session, scan, 0) == 0);
        assert(submit_live_join(session, session.scan, request) == -16);
        assert(poll_live_scan(session, 1) == ScanOutcome::complete);
        request.bssid[5] = 0x12;
        assert(submit_live_join(session, session.scan, request) == -2);
        request.bssid[5] = 0x11;
        request.controlled_port = true;
        const uint8_t extra[]{59, 2, 81, 81, 127, 1, 0};
        memcpy(request.extra, extra, sizeof(extra));
        request.extra_bytes = sizeof(extra);
        model.extra_association_elements = true;
        if (secured) {
            request.akm = RsnAkm::enterprise;
            request.controlled_port = false;
            memcpy(request.extra + request.extra_bytes, enterprise_ie, sizeof(enterprise_ie));
            request.extra_bytes += sizeof(enterprise_ie);
            assert(submit_live_join(session, session.scan, request) == -95);
            session.security_keys = true;
            assert(submit_live_join(session, session.scan, request) == -2); // Open AP.
            auto& peer = session.scan.access_points[0];
            auto* beacon = scan.records[0].beacon;
            memcpy(beacon + peer.beacon_ie_bytes, enterprise_ie, sizeof(enterprise_ie));
            peer.beacon_ie_bytes += sizeof(enterprise_ie);
            peer.capability |= 0x10;
            model.secured_association = true;
        }
        assert(submit_live_join(session, session.scan, request) == 0);
        assert(submit_live_scan(session, scan, 2) == -16 && model.commands_sent == 8);
        assert(submit_live_join(session, session.scan, request) == -16);

        auto outcome = JoinOutcome::pending;
        uint64_t now = 2;
        while (now < 1500 && session.join.phase != JoinPhase::idle &&
               outcome == JoinOutcome::pending)
            outcome = poll_live_join(session, now++);
        const bool sent =
            authentication == AuthCase::accepted || authentication == AuthCase::reply_first;
        assert(session.join.association_sent == sent);
        const uint16_t status = authentication == AuthCase::denied_ap ? 13
                                : association == AssocCase::refused   ? 17
                                                                      : 0;
        assert(session.join.peer_status == status);
        if (sent) {
            const uint8_t elements[]{1, 1, 0x82};
            assert(session.join.response_ie_bytes == sizeof(elements));
            assert(!memcmp(session.association_response_ies, elements, sizeof(elements)));
        } else
            assert(!session.join.response_ie_bytes);
        if (sent && association != AssocCase::refused && association != AssocCase::bad_beacon) {
            assert(outcome == JoinOutcome::connected && model.commands_sent == 19);
            assert(session.station.queue.id == 0x102 && session.station.channel == 1);
            assert(session.station.next_sequence == 2 && session.join.aid == 42);
            assert(!session.station.port_authorized && session.station.ccmp == secured);
            uint8_t packet[14]{};
            packet[12] = 8;
            assert(submit_live_data(session, packet, sizeof(packet), 22) == -13);
            if (secured) {
                assert(stop_live_quz(session) && !model.master);
                continue;
            }
            session.station.port_authorized = true;
            session.station.ccmp = true;
            assert(submit_live_data(session, packet, sizeof(packet), 22) == -13);
            packet[12] = 0x88;
            packet[13] = 0x8e;
            assert(submit_live_data(session, packet, sizeof(packet), 22) == -13);
            session.station.ccmp = false;
            assert(submit_live_join(session, session.scan, request) == -106);
            check_live_departure(model, session, scan, request, pending, missed_beacons);
        } else {
            assert(!session.station.queue.id && model.commands_sent == 16);
            assert(outcome == JoinOutcome::pending);
            assert(session.leave.join_result ==
                   (status ? JoinOutcome::rejected : JoinOutcome::timeout));
            assert(session.station.management.write_pointer == (sent ? 0x36 : 0x35));
            assert(submit_live_scan(session, scan, now) == -16);
            model.cancel_after_commands = model.commands_sent;
            auto leave = LeaveOutcome::pending;
            for (const auto deadline = now + 32; leave == LeaveOutcome::pending && now < deadline;)
                leave = poll_live_leave(session, now++, nullptr, nullptr);
            assert(leave == LeaveOutcome::disconnected && session.running && !model.requested_stop);
            assert(model.commands_sent ==
                   (authentication == AuthCase::protection_expired ? 21u : 22u));
            check_rejoin(model, session, scan, request, now);
        }
        assert(stop_live_quz(session) && !model.master);
    }
    std::puts("AX201_LIVE_CONNECTION_MODEL_PASS");
}

void check_cancel_join() {
    constexpr struct {
        JoinPhase phase;
        bool in_flight;
    } cases[]{
        {JoinPhase::phy, false},
        {JoinPhase::chains, false},
        {JoinPhase::authenticate, false},
        {JoinPhase::authenticate, true},
    };

    for (const auto& [cancel_at, in_flight] : cases) {
        StartupFixture model(StartupCase::good);
        model.regulatory = RegulatoryCase::valid;
        model.passive = ScanCase::complete;
        model.peer_case = PeerCase::success;
        model.auth_case = AuthCase::reply_timeout;
        model.assoc_case = AssocCase::accepted;
        model.arp_case = ArpCase::accepted;
        model.open_station = true;
        model.live_replies.resize(48 * ax::page_size);
        const auto io = model.make_io();
        const auto memory = model.make_memory(true, true);
        LiveScanSession session(io, memory);
        assert(start_live_quz(session, {1, 2}).successful);
        ScanElementStorage scan{};
        const StationRequest request{{{'l', 'a', 'b'}, 3}, {2, 0, 0, 0, 0, 0x11}, 2412};
        assert(submit_live_scan(session, scan, 0) == 0);
        assert(poll_live_scan(session, 1) == ScanOutcome::complete);
        assert(submit_live_join(session, session.scan, request) == 0);
        uint64_t now = 2;
        while (session.join.phase != cancel_at && now < 30)
            assert(poll_live_join(session, now++) == JoinOutcome::pending);
        assert(session.join.phase == cancel_at);
        if (cancel_at == JoinPhase::authenticate) {
            model.defer_authentication_completion = in_flight;
            assert(poll_live_join(session, now++) == JoinOutcome::pending);
            assert(session.join.acknowledged == !in_flight && !session.join.indicated);
        }
        assert(model.commands_sent == (cancel_at == JoinPhase::phy      ? 8u
                                       : cancel_at == JoinPhase::chains ? 9u
                                                                        : 16u));
        model.cancel_after_commands = model.commands_sent;
        model.disconnect_reason = 8;
        assert(submit_live_leave(session, 8) == 0);
        assert(submit_live_leave(session, 3) == 0);
        assert(session.join.cancel_reason == 8);
        if (in_flight) {
            assert(poll_live_join(session, now++) == JoinOutcome::pending);
            assert(session.join.phase == JoinPhase::authenticate);
            assert(session.leave.phase == LeavePhase::idle && model.commands_sent == 16);
            assert(model.deferred_authentication_buffer);
            model.receive_status.closed_buffer = model.deferred_authentication_buffer;
            model.defer_authentication_completion = false;
        }
        assert(poll_live_join(session, now++) == JoinOutcome::pending);
        assert(session.join.phase == JoinPhase::idle && session.leave.reason == 8);
        assert(submit_live_join(session, session.scan, request) == -16);
        assert(submit_live_scan(session, scan, now) == -16);
        auto leave = LeaveOutcome::pending;
        while (leave == LeaveOutcome::pending && now < 50)
            leave = poll_live_leave(session, now++, nullptr, nullptr);
        assert(leave == LeaveOutcome::disconnected && session.running && !model.requested_stop);
        assert(!session.station.queue.id && !session.station.management.id);
        assert(model.commands_sent == (cancel_at == JoinPhase::phy      ? 8u
                                       : cancel_at == JoinPhase::chains ? 10u
                                                                        : 22u));
        assert(model.authentication_rx_buffers == (cancel_at == JoinPhase::authenticate ? 2u : 0u));

        check_rejoin(model, session, scan, request, now);
        assert(stop_live_quz(session) && !model.master);
    }
    std::puts("AX201_CANCEL_JOIN_MODEL_PASS");
}

} // namespace

int main(int argc, char** argv) {
    Bytes file(88);
    word(file, 4, 0x0a4c5749);
    word(file, 72, 77);
    const size_t version = append(file, 36, 12);
    word(file, version, 77);
    word(file, version + 4, 0x12345678);
    word(file, append(file, 48, 4), 0x06630001);
    word(file, append(file, 48, 4), 0x04010c02);
    word(file, append(file, 48, 4), 0x0005010c);
    word(file, append(file, 48, 4), 0x050101c8);
    word(file, append(file, 48, 4), 0x00010198);
    word(file, append(file, 48, 4), 0x00050128);
    word(file, append(file, 48, 4), 0x000f010d);
    word(file, append(file, 48, 4), 0x046300c1);
    word(file, append(file, 48, 4), 0x00040108);
    word(file, append(file, 48, 4), 0x00020508);
    word(file, append(file, 48, 4), 0x000301d1);
    const auto binding_version = append(file, 48, 4);
    word(file, binding_version, 0x0102012b);
    word(file, append(file, 48, 4), 0x020c0118);
    word(file, append(file, 48, 4), 0x00020119);
    word(file, append(file, 48, 4), 0x00010518);
    const auto scheduler_version = append(file, 48, 4);
    word(file, scheduler_version, 0x02030517);
    word(file, append(file, 48, 4), 0x0709011c);
    word(file, append(file, 48, 4), 0x00010305);
    word(file, append(file, 48, 4), 0x026303fb);
    const auto rate_version = append(file, 48, 4);
    word(file, rate_version, 0x036305f7);
    word(file, append(file, 29, 8) + 4, 1u << 9);
    word(file, append(file, 30, 8) + 4, 1u << 1);
    const auto binding_caps = append(file, 30, 8);
    word(file, binding_caps, 1);
    word(file, binding_caps + 4, (1u << 7) | (1u << 8) | (1u << 22));
    auto regulatory_caps = append(file, 30, 8);
    word(file, regulatory_caps, 2);
    word(file, regulatory_caps + 4, 1u << 25);
    word(file, append(file, 23, 4), 0x00330018);
    word(file, append(file, 27, 4), 2);
    const size_t first_section = section(file, 0x400000, {7});
    const size_t delimiter = section(file, 0xffffcccc, {0, 0, 0, 0});
    section(file, 0x800000, {8, 9});
    const size_t paging_length = append(file, 32, 4);
    word(file, paging_length, 4096);
    section(file, 0xaaaabbbb, {0, 0, 0, 0});
    section(file, 0, {10});
    const size_t last_section = section(file, 0x1000000, Bytes(4096, 11));
    FirmwareImage image{};
    assert(!parse_firmware(file.data(), file.size(), image));
    assert(image.nvm_version == 4);
    assert(image.scan_config_version == 5 && image.antennas.tx == 3 && image.antennas.rx == 3);
    assert(image.current_regulatory_profile);
    assert(image.passive_scan_supported);
    assert(image.channel_context_supported && image.dual_lmac);
    assert(image.peer_queue_supported);
    assert(image.authentication_supported);
    assert(image.version[1] == 0x12345678 && image.alive_version == 6 &&
           image.paging_bytes == 4096);
    assert(image.regions[lmac].count == 1 && image.regions[umac].count == 1 &&
           image.regions[paging].count == 2);
    assert(image.regions[lmac].sections[0].data == file.data() + first_section + 4 &&
           *image.regions[umac].sections[0].data == 8 &&
           image.regions[paging].sections[1].data[4095] == 11);
    check_intel_wifi_boot_queues(image);
    check_startup();
    check_live_scans();
    check_active_scan();
    check_intel_wifi_scan_channels();
    check_channel_contexts();
    check_intel_wifi_key_codec();
    check_intel_wifi_station_keys();
    check_intel_wifi_ccmp_data();
    check_security_key_commands();
    check_peer_queues();
    check_authentication_exchange();
    check_intel_wifi_association_codec();
    check_intel_wifi_rsn_codec();
    check_association_exchange();
    check_associated_arp();
    check_open_station();
    check_live_connection();
    check_cancel_join();
    check_intel_wifi_receive_recycling();
    check_intel_wifi_access_points();

    auto reject = [&](const Bytes& invalid) {
        FirmwareImage prior{};
        prior.version[0] = 99;
        assert(parse_firmware(invalid.data(), invalid.size(), prior));
        assert(prior.version[0] == 99 && !prior.regions[lmac].count);
    };
    for (const size_t field :
         {size_t(4), version, delimiter, paging_length, last_section - 4, first_section}) {
        Bytes invalid = file;
        word(invalid, field, UINT32_MAX);
        reject(invalid);
    }
    Bytes duplicate = file;
    word(duplicate, append(duplicate, 27, 4), 2);
    reject(duplicate);
    Bytes duplicate_alive = file;
    word(duplicate_alive, append(duplicate_alive, 48, 4), 0x06630001);
    reject(duplicate_alive);
    Bytes duplicate_scan = file;
    word(duplicate_scan, append(duplicate_scan, 48, 4), 0x0004010c);
    reject(duplicate_scan);
    Bytes duplicate_binding = file;
    word(duplicate_binding, append(duplicate_binding, 48, 4), 0x0102012b);
    reject(duplicate_binding);
    Bytes duplicate_security_key = file;
    word(duplicate_security_key, append(duplicate_security_key, 48, 4), 0x00010518);
    reject(duplicate_security_key);
    Bytes short_binding = file;
    word(short_binding, binding_version, 0x0002012b);
    FirmwareImage unsupported_binding{};
    assert(!parse_firmware(short_binding.data(), short_binding.size(), unsupported_binding));
    assert(!unsupported_binding.channel_context_supported &&
           unsupported_binding.passive_scan_supported);
    Bytes old_binding = file;
    word(old_binding, binding_caps + 4, 0);
    assert(!parse_firmware(old_binding.data(), old_binding.size(), unsupported_binding));
    assert(!unsupported_binding.channel_context_supported && !unsupported_binding.dual_lmac);
    Bytes old_scheduler = file;
    word(old_scheduler, scheduler_version, 0x02010517);
    FirmwareImage unsupported_queue{};
    assert(!parse_firmware(old_scheduler.data(), old_scheduler.size(), unsupported_queue));
    assert(unsupported_queue.channel_context_supported && !unsupported_queue.peer_queue_supported);
    Bytes unsupported_rate = file;
    word(unsupported_rate, rate_version, 0x026305f7);
    FirmwareImage unsupported_auth{};
    assert(!parse_firmware(unsupported_rate.data(), unsupported_rate.size(), unsupported_auth));
    assert(unsupported_auth.peer_queue_supported && !unsupported_auth.authentication_supported);
    Bytes no_regulatory = file;
    word(no_regulatory, regulatory_caps + 4, 0);
    FirmwareImage without_mcc{};
    assert(!parse_firmware(no_regulatory.data(), no_regulatory.size(), without_mcc));
    assert(!without_mcc.current_regulatory_profile);
    Bytes duplicate_phy = file;
    word(duplicate_phy, append(duplicate_phy, 23, 4), 0x00330018);
    reject(duplicate_phy);
    Bytes oversized = file;
    section(oversized, 0x1010000, Bytes(max_section_bytes + 1, 0));
    reject(oversized);
    for (size_t size = 0; size < file.size(); ++size) {
        FirmwareImage prior{};
        assert(parse_firmware(file.data(), size, prior));
    }

    if (argc == 2) {
        std::ifstream input(argv[1], std::ios::binary);
        Bytes device_file{std::istreambuf_iterator<char>(input), {}};
        assert(!parse_firmware(device_file.data(), device_file.size(), image));
        assert(image.nvm_version == 4);
        assert(image.scan_config_version == 5 && image.antennas.tx == 3 && image.antennas.rx == 3);
        assert(image.current_regulatory_profile);
        assert(image.passive_scan_supported);
        assert(image.channel_context_supported && !image.dual_lmac);
        assert(image.peer_queue_supported);
        assert(image.authentication_supported);
        assert(image.security_key_version == 1);
        assert(image.version[0] == 77 && image.alive_version == 6 &&
               image.paging_bytes == 0x97000 && image.regions[lmac].count == 14 &&
               image.regions[umac].count == 15 && image.regions[paging].count == 20);
        check_intel_wifi_boot_queues(image);
        std::puts("AX201_FIRMWARE_RELEASE_PASS");
    }
    std::puts("AX201_FIRMWARE_CODEC_PASS");
}
