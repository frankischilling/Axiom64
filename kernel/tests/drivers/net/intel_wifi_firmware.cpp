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

namespace {
using namespace ax::IntelWifi;
using Bytes = std::vector<uint8_t>;

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

void check_boot_queues(const FirmwareImage& image) {
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
    wrong_target
};
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

void initial_receive_descriptors(uint64_t* ring, uint64_t* descriptors) {
    for (unsigned id = 1; id < rx_ring_entries; ++id) {
        assert(encode_receive_buffer(0x200000 + id * ax::page_size, id, descriptors[id - 1]));
        ring[id - 1] = descriptors[id - 1];
    }
}

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
        initial_receive_descriptors(free_ring, descriptors);
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

void check_receive_recycling() {
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
    CommandDescriptor management_ring[management_queue_entries]{};
    uint16_t management_counts[transmit_byte_count_bytes / sizeof(uint16_t)]{};
    uint8_t authentication_payload[authentication_dma_bytes]{};
    unsigned authentication_rx_buffers = 0;
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
            beacon[21] = uint8_t((id ? 0x20 : 0x10) + (offset == 384 ? 2 : 1));
            if (peer_case != PeerCase::unused)
                beacon[34] = 1; // ESS capability.
            if (auth_case != AuthCase::unused) {
                frame[0] = 93;
                mpdu[0] = 41;
                beacon[32] = 100;
                beacon[38] = beacon[39] = 1;
                beacon[40] = 0x82; // Basic 1 Mbps rate.
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

    void authentication_doorbell(uint32_t value) {
        assert(auth_case != AuthCase::unused && commands_sent == 16 && !authentication_rx_buffers);
        assert(value == 0x01010035);
        const auto& descriptor = management_ring[4];
        assert(descriptor.buffer_count == 3 && management_counts[4] == 8);
        const TransmitBuffer buffers[]{{20, 0x52000}, {28, 0x52040}, {6, 0x52080}};
        assert(!memcmp(descriptor.buffers, buffers, sizeof(buffers)));
        const uint8_t first[20]{0x1c, 0, 4, 1, 30, 0, 0, 12, 3};
        const uint8_t second[]{
            0, 0x40, 0,    0,    0xb0, 0,    0, 0, 2, 0, 0, 0,    0, 0x11,
            2, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 0, 0, 0, 0, 0x11, 0, 0,
        };
        const uint8_t body[6]{0, 0, 1, 0, 0, 0};
        assert(!memcmp(authentication_payload, first, sizeof(first)));
        assert(!memcmp(authentication_payload + 64, second, sizeof(second)));
        assert(!memcmp(authentication_payload + 128, body, sizeof(body)));

        auto* buffer = reply_buffer(commands_sent);
        const bool first_reply = auth_case == AuthCase::reply_first;
        auto* tx = buffer + (first_reply ? 128 : 0);
        tx[0] = 52;
        tx[4] = 0x1c;
        tx[6] = 4;
        tx[7] = 1;
        tx[8] = 1;
        tx[44] = tx[45] = 1;
        tx[48] = auth_case == AuthCase::denied_tx ? 0x84 : 1;
        tx[52] = 0x35;

        if (auth_case != AuthCase::reply_timeout) {
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
            frame[26] = 2;
            frame[28] = auth_case == AuthCase::denied_ap ? 13 : 0;
        }
        authentication_rx_buffers = 1;
        used[17] = 18;
        receive_status.closed_buffer = 18;
    }

    void command_reply(unsigned tail) {
        const unsigned index = ++commands_sent;
        assert(tail == (index & (command_sequence_count - 1)));
        assert(index <= (live_replies.empty() ? 9u : live_replies.size() / ax::page_size));
        const unsigned sequence = (index - 1) & (command_sequence_count - 1);
        const unsigned slot = sequence & (command_ring_entries - 1);
        const auto& command = payloads[slot];
        const bool scanning = check_channels || passive != ScanCase::unused;
        const bool auth = auth_case != AuthCase::unused;
        const unsigned peer_index = !auth || index <= 13 ? index
                                    : index >= 18        ? index - 3
                                                         : index - 1;
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
        } else if (index == 7) {
            expected[0] = 0x28;
            payload_bytes = 148;
            expected[12] = 1;
            expected[16] = 5;
            const uint8_t address[]{2, 0x11, 0x22, 0x33, 0x44, 0x55};
            memcpy(expected + 24, address, sizeof(address));
            memset(expected + 32, 0xff, 6);
            expected[40] = 0xf;
            expected[44] = 0x15;
            expected[60] = 0x44;
        } else if (check_channels) {
            payload_bytes = expect_channel_command(index, expected);
        } else if (auth && index == 13) {
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
            payload_bytes = 148;
        } else if (auth && (index == 16 || index == 17)) {
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
            expected[8] = uint8_t((index - 8) & 1);
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

        auto* reply = reply_buffer(index - 1 + authentication_rx_buffers);
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
        const bool binding = (check_channels || peer) && index >= 8 && command[0] == 0x2b;
        const unsigned length = binding ? (index == short_binding_status ? 7 : 8)
                                : peer && peer_index == 13 && command[0] == 0x18 ? 8
                                : peer && peer_index == 14 && command[0] == 0x17
                                    ? (peer_case == PeerCase::short_queue ? 11 : 12)
                                : peer && peer_index == 15 && command[0] == 0x17 ? 12
                                : mcc        ? (scanning ? 84 : 32)
                                : index == 3 ? 472
                                             : 4;
        reply[0] = uint8_t(length);
        reply[1] = uint8_t(length >> 8);
        const bool reject = index == 4 && reject_scan_config;
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
        if (peer && peer_index == 13 && command[0] == 0x18) {
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
        if (!check_channels && index >= 8 && (!peer || index == 8))
            scan_notifications(reply, uint8_t((index - 8) & 1));
        used[index + authentication_rx_buffers] = index + 1 + authentication_rx_buffers;
        receive_status.closed_buffer = uint16_t(index + 1 + backlog + authentication_rx_buffers);
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
            if (value >> 16)
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
            initial_receive_descriptors(free_ring, descriptors);
            memory.free_ring = free_ring;
            memory.receive_descriptors = descriptors;
        }
        if (nvm) {
            memory.commands = commands;
            memory.command_payloads = &payloads;
            memory.command_dma = 0xa000;
        }
        return memory;
    }

    FirmwareBootResult run(bool nvm = false, const ScanChecks* scan = nullptr) {
        const auto io = make_io();
        auto memory = make_memory(nvm, scan && scan->check >= FirmwareCheck::rescan);
        if (peer_case != PeerCase::unused)
            memory.peer_queue = {0x50000, 0x51000};
        if (auth_case != AuthCase::unused)
            memory.authentication = {management_ring, management_counts, authentication_payload,
                                     0x52000};
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

void check_scan_channels() {
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
    assert(!parse_management_queue({0x17, 5, 0, allocation, sizeof(allocation)}, queue));
    allocation[1] = 2; // One beyond the last supported queue.
    assert(!parse_management_queue({0x17, 5, 0, allocation, sizeof(allocation)}, queue));
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

void check_access_points() {
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
    check_boot_queues(image);
    check_startup();
    check_live_scans();
    check_active_scan();
    check_scan_channels();
    check_channel_contexts();
    check_peer_queues();
    check_authentication_exchange();
    check_receive_recycling();
    check_access_points();

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
        assert(image.version[0] == 77 && image.alive_version == 6 &&
               image.paging_bytes == 0x97000 && image.regions[lmac].count == 14 &&
               image.regions[umac].count == 15 && image.regions[paging].count == 20);
        check_boot_queues(image);
        std::puts("AX201_FIRMWARE_RELEASE_PASS");
    }
    std::puts("AX201_FIRMWARE_CODEC_PASS");
}
