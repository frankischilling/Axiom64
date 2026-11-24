// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/net/intel_wifi_firmware.cpp
 * @brief   Exercise AX201 firmware structure and rejection paths.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_start.hpp"
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

struct StartupFixture {
    StartupCase scenario;
    uint32_t csr[(0x1c80 / 4) + 1]{};
    ReceiveStatus receive_status{};
    uint32_t used[rx_ring_entries]{};
    uint8_t buffer[ax::page_size]{};
    uint8_t replies[5][ax::page_size]{};
    CommandDescriptor commands[command_ring_entries]{};
    CommandPayloads payloads{};
    unsigned commands_sent = 0;
    bool malformed_nvm = false;
    bool wrong_sequence = false;
    bool reject_scan_config = false;
    RegulatoryCase regulatory = RegulatoryCase::unused;
    bool master = false;
    bool requested_master = false;
    bool sent_doorbell = false;
    bool requested_stop = false;
    bool reset_after_dma = false;

    explicit StartupFixture(StartupCase scenario) : scenario(scenario) {
        csr[0x24 / 4] = scenario == StartupCase::blocked ? 0 : 1u << 27;
        alive_packet(buffer);
    }

    void command_reply(unsigned index) {
        assert(index == ++commands_sent && index <= 5);
        const unsigned slot = index - 1;
        const auto& command = payloads[slot];
        const bool mcc = index == 4 && regulatory != RegulatoryCase::unused;
        const uint8_t expected[][36]{
            {3, 2, 0, 0, 4, 0, 0, 0, 2},
            {0, 12, 1, 0, 4},
            {2, 12, 2, 0, 4},
            {0xc, 1, 3, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2},
            {0xc, 1, 4, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2},
        };
        const uint8_t expected_mcc[36]{0xc8, 1, 3, 0, 28, 0, 0, 0, 'Z', 'Z', 0x10};
        const auto command_bytes = mcc ? 36 : index >= 4 ? 20 : 12;
        assert(!memcmp(mcc ? expected_mcc : expected[slot], command, sizeof(expected_mcc)));
        assert(commands[slot].buffer_count == 1 &&
               commands[slot].buffers[0].length == command_bytes);
        assert(commands[slot].buffers[0].address == 0xa000 + slot * command_slot_bytes);

        auto* reply = replies[slot];
        if (index == 2) {
            // INIT complete and the command reply share a receive buffer.
            reply[0] = 4;
            reply[4] = 4;
            reply[7] = 0x80;
            reply += 64;
        }
        const unsigned length = mcc ? 32 : index == 3 ? 472 : 4;
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
            data[7] = 0;
            data[16] = regulatory == RegulatoryCase::bad_count ? 3 : 2;
            data[20] = regulatory == RegulatoryCase::disallowed ? 0 : 0x09;
        }
        used[index] = index + 1;
        receive_status.closed_buffer = uint16_t(index + 1);
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
            assert(value == 2040 && master && !sent_doorbell);
            sent_doorbell = true;
            used[0] = scenario == StartupCase::bad_buffer ? 0 : 1;
            receive_status.closed_buffer = 1;
        }
        if (offset == 0x460) {
            assert(master && sent_doorbell);
            command_reply(value);
        }
    }

    FirmwareBootResult run(bool nvm = false, const ScanChecks* scan = nullptr) {
        const FirmwareBootIo io{
            this,
            [](void* ptr, unsigned offset) {
                return static_cast<StartupFixture*>(ptr)->csr[offset / 4];
            },
            [](void* ptr, unsigned offset, uint32_t value) {
                static_cast<StartupFixture*>(ptr)->write(offset, value);
            },
            [](void*, unsigned) { return true; },
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
            [](void* ptr, unsigned id) -> const uint8_t* {
                auto& model = *static_cast<StartupFixture*>(ptr);
                if (id == 1)
                    return model.buffer;
                return id >= 2 && id <= 6 ? model.replies[id - 2] : nullptr;
            },
        };
        FirmwareBootMemory memory{0x9000, &receive_status, used};
        if (nvm) {
            memory.commands = commands;
            memory.command_payloads = &payloads;
            memory.command_dma = 0xa000;
        }
        return start_and_stop_quz(io, memory, scan);
    }
};

void check_startup() {
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
        const ScanChecks scan{{scenario == 2 ? uint8_t(4) : uint8_t(1), 2}, false};
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
        const ScanChecks scan{{1, 2}, true};
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
    word(file, append(file, 29, 8) + 4, 1u << 9);
    word(file, append(file, 30, 8) + 4, 1u << 1);
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
    assert(image.version[1] == 0x12345678 && image.alive_version == 6 &&
           image.paging_bytes == 4096);
    assert(image.regions[lmac].count == 1 && image.regions[umac].count == 1 &&
           image.regions[paging].count == 2);
    assert(image.regions[lmac].sections[0].data == file.data() + first_section + 4 &&
           *image.regions[umac].sections[0].data == 8 &&
           image.regions[paging].sections[1].data[4095] == 11);
    check_boot_queues(image);
    check_startup();

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
        assert(image.version[0] == 77 && image.alive_version == 6 &&
               image.paging_bytes == 0x97000 && image.regions[lmac].count == 14 &&
               image.regions[umac].count == 15 && image.regions[paging].count == 20);
        check_boot_queues(image);
        std::puts("AX201_FIRMWARE_RELEASE_PASS");
    }
    std::puts("AX201_FIRMWARE_CODEC_PASS");
}
