// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/net/intel_wifi_firmware.cpp
 * @brief   Exercise AX201 firmware structure and rejection paths.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_context.hpp"
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
} // namespace

int main(int argc, char** argv) {
    Bytes file(88);
    word(file, 4, 0x0a4c5749);
    word(file, 72, 77);
    const size_t version = append(file, 36, 12);
    word(file, version, 77);
    word(file, version + 4, 0x12345678);
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
    assert(image.version[1] == 0x12345678 && image.paging_bytes == 4096);
    assert(image.regions[lmac].count == 1 && image.regions[umac].count == 1 &&
           image.regions[paging].count == 2);
    assert(image.regions[lmac].sections[0].data == file.data() + first_section + 4 &&
           *image.regions[umac].sections[0].data == 8 &&
           image.regions[paging].sections[1].data[4095] == 11);
    check_boot_queues(image);

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
        assert(image.version[0] == 77 && image.paging_bytes == 0x97000 &&
               image.regions[lmac].count == 14 && image.regions[umac].count == 15 &&
               image.regions[paging].count == 20);
        check_boot_queues(image);
        std::puts("AX201_FIRMWARE_RELEASE_PASS");
    }
    std::puts("AX201_FIRMWARE_CODEC_PASS");
}
