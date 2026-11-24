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
#include "drivers/net/intel_wifi_live.hpp"
#include "drivers/net/intel_wifi_scan.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax::IntelWifi;
using Bytes = std::vector<uint8_t>;

void check_intel_wifi_boot_queues(const FirmwareImage& image) {
    FirmwareAddresses addresses{};
    uint64_t section_address = 0x100000;
    for (unsigned group = 0; group < region_count; ++group)
        for (unsigned i = 0; i < image.regions[group].count; ++i) {
            addresses[group][i] = section_address;
            section_address += max_section_bytes;
        }

    constexpr ReceiveQueues rx{0x4000, 0x9000, 0xb000};
    constexpr uint64_t tx = 0xc000;
    BootContext context{};
    assert(make_boot_context(image, addresses, rx, tx, context));
    const auto* bytes = reinterpret_cast<const uint8_t*>(&context);
    const uint8_t header[] = {0x51, 0x03, 0, 0, 0xc0, 0x01, 0, 0, 0xb0, 0x09, 0, 0};
    assert(!memcmp(bytes, header, sizeof(header)));
    assert(context.rx.free_ring == rx.free_ring && context.rx.used_ring == rx.used_ring &&
           context.rx.status == rx.status && context.commands == tx && bytes[56] == 2);
    for (unsigned i = 57; i < 192; ++i)
        assert(bytes[i] == 0);
    for (unsigned i = 1728; i < sizeof(context); ++i)
        assert(bytes[i] == 0);
    for (unsigned i = 0; i < max_sections; ++i) {
        assert(context.umac[i] == addresses[umac][i]);
        assert(context.lmac[i] == addresses[lmac][i]);
        assert(context.paging[i] == addresses[paging][i]);
    }

    const BootContext saved = context;
    assert(!make_boot_context(image, addresses, {rx.free_ring + 1, rx.used_ring, rx.status}, tx,
                              context));
    assert(!make_boot_context(image, addresses, rx, 0xfffff000ull, context));
    addresses[paging][0] = 0;
    assert(!make_boot_context(image, addresses, rx, tx, context));
    assert(!memcmp(&context, &saved, sizeof(context)));

    uint64_t receive = 0;
    assert(encode_receive_buffer(0xfffff000ull, 2047, receive) && receive == 0xfffff7ffull);
    assert(!encode_receive_buffer(0x100000000ull, 1, receive));
    assert(!encode_receive_buffer(0x100a, 1, receive));
    assert(!encode_receive_buffer(0x1000, 0, receive));
    assert(!encode_receive_buffer(0x1000, 4096, receive));
    assert(receive == 0xfffff7ffull);

    uint8_t command[invalid_command_size]{};
    CommandDescriptor ring[command_ring_entries]{};
    constexpr uint64_t invalid = 0x12000;
    assert(!prepare_command_ring(0, command, ring));
    assert(prepare_command_ring(invalid, command, ring));
    const uint8_t expected_command[] = {6, 15, 0xff, 0xff, 0, 0, 0, 0};
    assert(!memcmp(command, expected_command, sizeof(command)));
    for (const auto& descriptor : ring) {
        const uint8_t expected_descriptor[256] = {1, 0, 8, 0, 0, 0x20, 0x01};
        assert(!memcmp(&descriptor, expected_descriptor, sizeof(descriptor)));
    }
    assert(!prepare_command_ring(invalid + 1, command, ring));
    assert(!memcmp(command, expected_command, sizeof(command)));
}

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

void initialize_intel_wifi_receive_descriptors(uint64_t* ring, uint64_t* descriptors) {
    for (unsigned id = 1; id < rx_ring_entries; ++id) {
        assert(encode_receive_buffer(0x200000 + id * ax::page_size, id, descriptors[id - 1]));
        ring[id - 1] = descriptors[id - 1];
    }
}

namespace {
struct ReceiveFixture {
    uint64_t free_ring[rx_ring_entries]{};
    uint64_t descriptors[rx_ring_entries - 1]{};
    uint32_t used_ring[rx_ring_entries]{};
    bool device_owned[rx_ring_entries]{};
    ReceiveStatus status{};
    Bytes buffers = Bytes((rx_ring_entries - 1) * ax::page_size);
    unsigned completed = 0, published = 0, doorbells = 0;
    const FirmwareBootIo io{
        this,
        nullptr,
        [](void* state, unsigned offset, uint32_t value) {
            auto& self = *static_cast<ReceiveFixture*>(state);
            assert(offset == 0x1c80);
            assert(value == (self.doorbells ? (self.published + 8) % rx_ring_entries : 2040));
            for (unsigned slot = self.published; slot != value;
                 slot = (slot + 1) % rx_ring_entries) {
                const unsigned id = self.free_ring[slot] & rx_buffer_id_mask;
                assert(id && id < rx_ring_entries && !self.device_owned[id]);
                assert(self.free_ring[slot] == self.descriptors[id - 1]);
                self.device_owned[id] = true;
            }
            self.published = value;
            ++self.doorbells;
        },
        nullptr,
        nullptr,
        [](void* state, unsigned id) { return static_cast<ReceiveFixture*>(state)->page(id); },
    };
    const FirmwareBootMemory memory{0x9000,  &status, used_ring, nullptr,
                                    nullptr, 0,       free_ring, descriptors};

    ReceiveFixture() {
        initialize_intel_wifi_receive_descriptors(free_ring, descriptors);
    }

    uint8_t* page(unsigned id) {
        assert(id && id < rx_ring_entries);
        return buffers.data() + (id - 1) * ax::page_size;
    }

    void close_buffer(unsigned id) {
        assert(completed % rx_ring_entries != published);
        used_ring[completed++ % rx_ring_entries] = 0xc000 | id;
        status.closed_buffer = completed & rx_buffer_id_mask;
    }

    void put(unsigned id, uint8_t opcode, bool multiple = false) {
        assert(device_owned[id]);
        device_owned[id] = false;
        auto* bytes = page(id);
        for (size_t i = 0; i < ax::page_size; ++i)
            assert(!bytes[i]);
        bytes[0] = 5;
        bytes[4] = opcode;
        bytes[8] = opcode;
        if (multiple) {
            bytes[64] = 5;
            bytes[68] = uint8_t(opcode + 1);
            bytes[72] = uint8_t(opcode + 1);
        }
        close_buffer(id);
    }
};

} // namespace

void check_intel_wifi_receive_recycling() {
    ReceiveFixture fixture;
    ReceiveReader reader(fixture.io, fixture.memory);
    reader.post_initial();
    FirmwarePacket packet{};
    // The completion descriptor names the buffer, even when IDs arrive out of order.
    fixture.put(2, 12, true);
    fixture.put(1, 14);
    assert(reader.next(packet) == PacketRead::packet && packet.opcode == 12);
    assert(packet.payload[0] == 12 && fixture.doorbells == 1);
    assert(reader.next(packet) == PacketRead::packet && packet.opcode == 13);
    assert(packet.payload[0] == 13 && fixture.doorbells == 1);
    assert(reader.next(packet) == PacketRead::packet && packet.opcode == 14);
    assert(reader.next(packet) == PacketRead::end && fixture.doorbells == 2);
    assert(fixture.free_ring[2047] == fixture.descriptors[1] &&
           fixture.free_ring[0] == fixture.descriptors[0]);

    unsigned returned = 2;
    for (; returned < 4 * rx_ring_entries + 1; ++returned) {
        const unsigned id = fixture.free_ring[returned % rx_ring_entries] & rx_buffer_id_mask;
        const auto opcode = uint8_t(returned + 1);
        fixture.put(id, opcode);
        assert(reader.next(packet) == PacketRead::packet && packet.opcode == opcode &&
               packet.payload[0] == opcode);
        assert(reader.next(packet) == PacketRead::end);
    }
    assert(fixture.completed == returned && fixture.doorbells == 1026);

    ReceiveFixture serial;
    ReceiveReader bad_id(serial.io, serial.memory);
    bad_id.post_initial();
    serial.put(1, 1);
    serial.put(2, 2);
    assert(bad_id.next(packet) == PacketRead::packet);
    assert(bad_id.next(packet) == PacketRead::packet);
    assert(bad_id.next(packet) == PacketRead::end);
    serial.close_buffer(2); // Released by the host, but not yet re-posted.
    assert(bad_id.next(packet) == PacketRead::malformed);

    ReceiveFixture unopened;
    ReceiveReader bad_tail(unopened.io, unopened.memory);
    bad_tail.post_initial();
    unopened.status.closed_buffer = 2041;
    assert(bad_tail.next(packet) == PacketRead::malformed);
    unopened.status.closed_buffer = 0;
    unopened.close_buffer(2041);
    assert(bad_tail.next(packet) == PacketRead::malformed);
    std::puts("AX201_RX_RECYCLE_MODEL_PASS packets=8194");
}

void check_intel_wifi_rsn_codec() {
    constexpr uint8_t enterprise[]{48, 20,  1, 0, 0, 15, 172, 4,   1, 0, 0,
                                   15, 172, 4, 1, 0, 0,  15,  172, 1, 0, 0};
    assert(station_rsn_matches(enterprise, sizeof(enterprise), RsnAkm::enterprise));
    assert(!station_rsn_matches(enterprise, sizeof(enterprise), RsnAkm::open));
    assert(!station_rsn_matches(enterprise, sizeof(enterprise), RsnAkm::personal));
    assert(!station_rsn_matches(enterprise, sizeof(enterprise) - 1, RsnAkm::enterprise));
    uint8_t ap[sizeof(enterprise)];
    memcpy(ap, enterprise, sizeof(ap));
    ap[20] = 0x80; // Management frame protection is optional on the access point.
    assert(supports_rsn(ap + 2, sizeof(ap) - 2, RsnAkm::enterprise, false));
    assert(!station_rsn_matches(ap, sizeof(ap), RsnAkm::enterprise));
    ap[20] = 0xc0;
    assert(!supports_rsn(ap + 2, sizeof(ap) - 2, RsnAkm::enterprise, false));
    ap[20] = 0;
    ap[8] = 0xff; // Pairwise suite list overruns the element.
    assert(!station_rsn_matches(ap, sizeof(ap), RsnAkm::enterprise));
    memcpy(ap, enterprise, sizeof(ap));
    ap[19] = 2;
    assert(station_rsn_matches(ap, sizeof(ap), RsnAkm::personal));
    ap[7] = 2; // TKIP group cipher.
    assert(!station_rsn_matches(ap, sizeof(ap), RsnAkm::personal));
    std::puts("AX201_RSN_CODEC_PASS");
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

namespace {
struct StationKeyFixture {
    ReceiveStatus status{};
    uint32_t used[rx_ring_entries]{};
    CommandDescriptor descriptors[command_ring_entries]{};
    CommandPayloads payloads{};
    uint8_t pages[8][ax::page_size]{};
    unsigned next_page = 0, commands = 0, completions = 0, received = 0;
    bool scan_abort = false, station_scan = false;
    enum class Reply { acknowledge, reject, withhold } reply = Reply::acknowledge;
    const FirmwareBootMemory memory{0, &status, used, descriptors, &payloads, 0x200000};
    const FirmwareBootIo io{
        this,
        [](void*, unsigned offset) { return offset == 0x24 ? 1u << 27 : 0; },
        [](void* context, unsigned offset, uint32_t value) {
            auto& self = *static_cast<StationKeyFixture*>(context);
            if (offset == 0x1c80)
                return;
            assert(offset == 0x460 && value == ++self.commands);
            const auto& data = self.payloads[value - 1];
            if (self.station_scan && data[0] == 0xd) {
                assert(value == 1 && data[1] == 1);
                constexpr uint8_t timing[]{120, 0, 0, 0, 120, 0, 0, 0, 120, 0, 0, 0, 120, 0, 0, 0};
                assert(!memcmp(data + 8 + 8 + 12, timing, sizeof(timing)));
                return;
            }
            if (self.scan_abort) {
                constexpr uint8_t command[]{0xe, 1, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
                assert(value == 2 && !memcmp(command, data, sizeof(command)));
                return;
            }
            assert(data[0] == key_command_opcode && data[1] == key_command_group);
            assert(data[2] == value - 1 && data[4] == key_command_bytes);
            if (self.reply == Reply::acknowledge)
                self.packet(key_command_opcode, key_command_group, uint16_t(value - 1), 0);
            if (self.reply == Reply::reject)
                self.packet(2, 0, uint16_t(value - 1), 0);
        },
        [](void*, unsigned us) { return us == 1000; },
        nullptr,
        [](void* context, unsigned id) {
            auto& self = *static_cast<StationKeyFixture*>(context);
            assert(id && id <= self.next_page);
            return self.pages[id - 1];
        },
    };

    uint8_t* packet(uint8_t opcode, uint8_t group, uint16_t sequence, uint8_t length) {
        assert(next_page < sizeof(pages) / sizeof(pages[0]));
        auto* bytes = pages[next_page];
        bytes[0] = length + 4;
        bytes[4] = opcode;
        bytes[5] = group;
        bytes[6] = uint8_t(sequence);
        bytes[7] = uint8_t(sequence >> 8);
        used[next_page] = next_page + 1;
        status.closed_buffer = ++next_page;
        return bytes + 8;
    }

    StationKeyResult change(LiveScanSession& session, const StationKeyRequest& request) {
        return change_station_key(
            session, request, 10, this,
            [](void* context, const uint8_t* frame, size_t bytes) {
                assert(bytes == 15 && frame[12] == 0x88 && frame[13] == 0x8e);
                ++static_cast<StationKeyFixture*>(context)->received;
            },
            [](void* context, size_t bytes, bool failed) {
                auto& self = *static_cast<StationKeyFixture*>(context);
                assert(bytes == 15 && !failed && !self.commands);
                ++self.completions;
            });
    }
};

void check_station_signal() {
    StationKeyFixture model;
    LiveScanSession session(model.io, model.memory);
    session.running = true;
    auto& station = session.station;
    station.queue.id = 1;
    station.channel = 1;
    station.peer.bssid[0] = 2;
    station.peer.bssid[5] = 1;
    session.receive.post_initial();
    const auto beacon = [&](uint8_t energy_a, uint8_t energy_b, uint8_t peer, uint8_t status) {
        uint8_t* rx = model.packet(0xc1, 0, 0x8000, 90);
        rx[0] = 42;
        rx[12] = status;
        rx[32] = energy_a;
        rx[33] = energy_b;
        rx[34] = station.channel;
        uint8_t* frame = rx + 48;
        frame[0] = 0x80;
        memcpy(frame + 10, station.peer.bssid, 6);
        memcpy(frame + 16, station.peer.bssid, 6);
        frame[15] = frame[21] = peer;
        frame[32] = 100;
        const uint8_t dtim[]{5, 4, 0, 1, 0, 0};
        memcpy(frame + 36, dtim, sizeof(dtim));
    };
    beacon(77, 61, 1, 3);
    assert(poll_live_station(session, 10, nullptr, nullptr, nullptr));
    assert(station.peer.signal_dbm == -61);
    beacon(32, 35, 2, 3);
    beacon(20, 21, 1, 2);
    beacon(0, 255, 1, 3);
    assert(poll_live_station(session, 20, nullptr, nullptr, nullptr));
    assert(station.peer.signal_dbm == -61);
    beacon(0, 79, 1, 3);
    assert(poll_live_station(session, 30, nullptr, nullptr, nullptr));
    assert(station.peer.signal_dbm == -79);
    std::puts("AX201_STATION_SIGNAL_MODEL_PASS");
}

void check_connected_scan() {
    constexpr uint8_t peer[6]{2, 0, 0, 0, 0, 1};
    constexpr uint8_t client[6]{2, 0, 0, 0, 0, 2};
    for (const bool leave : {false, true}) {
        StationKeyFixture model;
        model.station_scan = model.scan_abort = true;
        LiveScanSession session(model.io, model.memory);
        session.running = true;
        session.next_scan_id = 1;
        session.channels.entries[0] = {2412, 1, true, false, false, true};
        session.channels.count = 1;
        auto& station = session.station;
        station.queue.id = station.channel = 1;
        memcpy(station.peer.bssid, peer, sizeof(peer));
        memcpy(session.station_address, client, sizeof(client));
        session.receive.post_initial();
        ScanElementStorage elements{};
        station.port_authorized = false;
        assert(submit_live_scan(session, elements, 1) == -16 && !model.commands);
        station.port_authorized = true;
        station.beacon_deadline = 2;
        station.pending_bytes = 15;
        station.transmit_deadline = 6000;
        assert(submit_live_scan(session, elements, 3) == 0 && model.commands == 1);
        model.packet(0xd, 1, 0, 0);
        assert(poll_live_station(session, 4, nullptr, nullptr, nullptr));
        auto* tx = model.packet(0x1c, 0, 0x100, 48);
        tx[0] = tx[36] = tx[40] = tx[44] = 1;
        auto* rx = model.packet(0xc1, 0, 0x8000, 48 + 24 + 9);
        rx[0] = 24 + 9;
        rx[12] = 3;
        rx[34] = 1;
        auto* frame = rx + 48;
        frame[0] = 8;
        frame[1] = 2;
        memcpy(frame + 4, client, sizeof(client));
        memcpy(frame + 10, peer, sizeof(peer));
        memcpy(frame + 16, peer, sizeof(peer));
        constexpr uint8_t body[]{0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x71};
        memcpy(frame + 24, body, sizeof(body));
        const auto receive = [](void* context, const uint8_t* packet, size_t length) {
            assert(length == 15 && packet[12] == 8 && packet[13] == 0 && packet[14] == 0x71);
            ++static_cast<StationKeyFixture*>(context)->received;
        };
        const auto complete = [](void* context, size_t length, bool failed) {
            assert(length == 15 && !failed);
            ++static_cast<StationKeyFixture*>(context)->completions;
        };
        assert(poll_live_station(session, 4000, &model, receive, complete));
        assert(model.received == 1 && model.completions == 1 && !station.pending_bytes);
        assert(session.leave.phase == LeavePhase::idle && session.active);
        assert(poll_live_scan(session, 17000) == ScanOutcome::pending);
        if (leave) {
            assert(submit_live_leave(session, 3) == 0);
            assert(poll_live_scan(session, 17001) == ScanOutcome::pending && model.commands == 2);
            model.packet(0xe, 1, 1, 4);
        }
        auto* done = model.packet(0xf, 0, 0x8000, 16);
        done[0] = 1;
        done[6] = leave ? 2 : 1;
        assert(poll_live_station(session, 17002, &model, receive, complete));
        assert(poll_live_scan(session, 17002) ==
               (leave ? ScanOutcome::aborted : ScanOutcome::complete));
        assert(!session.active && !station.beacon_deadline && station.queue.id == 1);
        assert(session.leave.phase == (leave ? LeavePhase::drain : LeavePhase::idle));
    }
    std::puts("AX201_CONNECTED_SCAN_MODEL_PASS");
}

void check_scan_abort() {
    enum class Case {
        complete_early,
        aborted,
        completion_first,
        not_found,
        rejected,
        malformed,
        timeout
    };
    for (const auto test : {Case::complete_early, Case::aborted, Case::completion_first,
                            Case::not_found, Case::rejected, Case::malformed, Case::timeout}) {
        StationKeyFixture model;
        model.scan_abort = true;
        model.commands = 1;
        LiveScanSession session(model.io, model.memory);
        session.running = session.active = true;
        session.next_command = 1;
        session.scan.id = 1;
        session.passive_channels = 1;
        session.receive.post_initial();
        session.exchange.restart(0, 1);
        const auto done = [&](uint8_t id, uint8_t status) {
            auto* data = model.packet(0xf, 0, 0x8000, 16);
            data[0] = id;
            data[6] = status;
        };
        session.exchange.request_abort();
        assert(poll_live_scan(session, 10) == ScanOutcome::pending && model.commands == 1);
        model.packet(0xd, 1, 0, 0);
        if (test == Case::complete_early) {
            done(1, 1);
            assert(poll_live_scan(session, 11) == ScanOutcome::aborted && model.commands == 1);
            assert(!session.active && !session.passive_channels);
            continue;
        }
        assert(poll_live_scan(session, 11) == ScanOutcome::pending && model.commands == 2);
        session.exchange.request_abort();
        done(0, 2);
        if (test == Case::completion_first)
            done(1, 1);
        assert(poll_live_scan(session, 12) == ScanOutcome::pending && model.commands == 2);
        if (test == Case::timeout) {
            assert(poll_live_scan(session, 2011) == ScanOutcome::completion_timeout);
            continue;
        }
        if (test == Case::rejected) {
            model.packet(2, 0, 1, 0);
        } else {
            auto* reply = model.packet(0xe, 1, 1, 4);
            reply[0] = test == Case::not_found ? 2 : test == Case::malformed ? 3 : 0;
        }
        auto result = poll_live_scan(session, 13);
        if (test == Case::aborted || test == Case::rejected) {
            assert(result == ScanOutcome::pending);
            done(1, test == Case::aborted ? 2 : 1);
            result = poll_live_scan(session, 14);
        }
        assert(result == (test == Case::malformed ? ScanOutcome::malformed : ScanOutcome::aborted));
        assert(!session.active && !session.passive_channels && session.running);
    }
    std::puts("AX201_SCAN_ABORT_MODEL_PASS");
}
} // namespace

void check_intel_wifi_station_keys() {
    constexpr uint8_t material[ccmp_key_bytes]{0x91, 0xf2};
    constexpr uint8_t peer[6]{2, 0, 0, 0, 0, 1};
    constexpr uint8_t station[6]{2, 0, 0, 0, 0, 2};
    StationKeyFixture model;
    LiveScanSession session(model.io, model.memory);
    session.running = session.security_keys = session.station.ccmp = true;
    session.station.queue.id = 1;
    session.station.channel = 1;
    memcpy(session.station.peer.bssid, peer, sizeof(peer));
    memcpy(session.station_address, station, sizeof(station));
    session.receive.post_initial();
    assert(model.change(session, {nullptr, 0, {}, 4, true}).status == -2);
    auto* tx = model.packet(0x1c, 0, 0x100, 48);
    tx[0] = tx[36] = tx[40] = tx[44] = 1;
    session.station.pending_bytes = 15;
    auto* rx = model.packet(0xc1, 0, 0x8000, 48 + 24 + 9);
    rx[0] = 24 + 9;
    rx[12] = 3;
    rx[34] = 1;
    auto* hdr = rx + 48;
    hdr[0] = 8;
    hdr[1] = 2;
    memcpy(hdr + 4, station, sizeof(station));
    memcpy(hdr + 10, peer, sizeof(peer));
    memcpy(hdr + 16, peer, sizeof(peer));
    const uint8_t eapol[]{0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1};
    memcpy(hdr + 24, eapol, sizeof(eapol));

    StationKeyRequest request{material, 0x123456, {2, 0, 0, 0, 0, 1}};
    assert(model.change(session, request).status == 0);
    auto& key = session.station.keys.pairwise;
    const uint8_t cleared[command_slot_bytes]{};
    assert(!memcmp(model.payloads[0], cleared, sizeof(cleared)));
    assert(model.commands == 1 && model.completions == 1 && model.received == 1 && key.installed);
    assert(key.packet_number[0] == 0x123456 && key.packet_number[15] == 0x123456);
    key.packet_number[0] += 1;
    assert(model.change(session, request).status == 0 && model.commands == 1);
    assert(key.packet_number[0] == 0x123457);
    request.material = nullptr;
    model.reply = StationKeyFixture::Reply::reject;
    assert(model.change(session, request).status == -5 && key.installed);
    assert(!memcmp(model.payloads[1], cleared, sizeof(cleared)));
    model.reply = StationKeyFixture::Reply::acknowledge;
    assert(model.change(session, request).status == 0 && !key.installed);
    assert(!session.station.port_authorized);
    request.material = material;
    assert(model.change(session, request).status == -114 && model.commands == 3);
    request.group = true;
    request.index = 1;
    assert(model.change(session, request).status == 0);
    assert(session.station.keys.group[1].installed);
    session.leave.phase = LeavePhase::remove_keys;
    const auto completed = [](void*, size_t, bool) { assert(false); };
    assert(poll_live_leave(session, 11, nullptr, completed) == LeaveOutcome::pending);
    assert(!session.station.keys.group[1].installed && !session.station.keys.group[1].known);
    session.leave = {};
    model.reply = StationKeyFixture::Reply::withhold;
    const auto result = model.change(session, request);
    assert(result.status == -110 && result.link_lost && !session.station.keys.group[1].installed);
    assert(model.commands == 6 && !memcmp(model.payloads[5] + 24, material, sizeof(material)));
    std::puts("AX201_STATION_KEYS_MODEL_PASS");
}

void check_intel_wifi_scan_channels() {
    check_scan_abort();
    check_station_signal();
    check_connected_scan();
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
    ScanElementStorage retained_elements{};
    PassiveScan replacement{};
    replacement.elements = &retained_elements;
    auto peer = point;
    peer.signal_dbm = -59;
    retain_associated_access_point(replacement, scan, peer);
    retain_associated_access_point(replacement, scan, peer);
    assert(replacement.access_point_count == 1 && replacement.access_points[0].signal_dbm == -59 &&
           !memcmp(retained_elements.records[0].probe, probe, sizeof(probe)) &&
           !memcmp(retained_elements.records[0].beacon, later_beacon, sizeof(later_beacon)));

    // A scan of a different channel keeps the earlier result and its IEs.
    constexpr uint64_t first_scan = 1000, second_scan = 1200;
    point.seen_ms = first_scan;
    scan.access_points[1].seen_ms = first_scan;
    replacement.access_points[0] = scan.access_points[1];
    retained_elements.records[0] = elements.records[1];
    update_scan_history(replacement, scan, second_scan, nullptr);
    assert(replacement.access_point_count == 2);
    assert(replacement.access_points[0].seen_ms == second_scan &&
           replacement.access_points[1].seen_ms == first_scan);
    assert(!memcmp(retained_elements.records[1].probe, probe, sizeof(probe)));
    assert(!expire_scan_history(replacement, first_scan + scan_cache_lifetime_ms - 1, nullptr));
    assert(expire_scan_history(replacement, first_scan + scan_cache_lifetime_ms, nullptr));
    assert(replacement.access_point_count == 1 &&
           replacement.access_points[0].frequency_mhz == 5180);
    assert(!expire_scan_history(replacement, second_scan + scan_cache_lifetime_ms,
                                &scan.access_points[1]));
    assert(expire_scan_history(replacement, second_scan + scan_cache_lifetime_ms, nullptr));
    assert(replacement.access_point_count == 0);
    std::puts("AX201_ACCESS_POINT_MODEL_PASS");
}
