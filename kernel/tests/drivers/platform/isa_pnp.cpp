// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/platform/isa_pnp.cpp
 * @brief   Tests ISA Plug and Play discovery against a port model.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks the isolation sequence, resource validation and active port readback.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "drivers/platform/isa_pnp.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;

constexpr uint8_t key[]{0x6a, 0xb5, 0xda, 0xed, 0xf6, 0xfb, 0x7d, 0xbe, 0xdf, 0x6f, 0x37,
                        0x1b, 0x0d, 0x86, 0xc3, 0x61, 0xb0, 0x58, 0x2c, 0x16, 0x8b, 0x45,
                        0xa2, 0xd1, 0xe8, 0x74, 0x3a, 0x9d, 0xce, 0xe7, 0x73, 0x39};

constexpr std::array<uint8_t, 9> serial_a{0x41, 0xd0, 0x80, 1, 1, 2, 3, 4, 0xc0};
constexpr std::array<uint8_t, 9> serial_b{0x41, 0xd0, 0x80, 2, 4, 3, 2, 1, 0x18};

struct Function {
    uint16_t base;
    bool active;
};

struct Card {
    const std::array<uint8_t, 9> serial;
    const Bytes resources;
    const std::vector<Function> functions;
    unsigned number = 0;
};

struct Model {
    std::vector<Card> cards;
    uint16_t listening = 0x213;
    bool configured = false, data_ready = false, stall = false;
    unsigned key_position = 0, key_count = 0, waits = 0, delays = 0;
    unsigned csn_resets = 0, assignments = 0, status_reads = 0, data_reads = 0;
    unsigned serial_reads = 0, cursor = 0, logical = 0;
    uint16_t port = 0;
    uint8_t reg = 0;
    Card* active = nullptr;

    void address(uint8_t byte) {
        if (configured) {
            reg = byte;
            return;
        }
        if (!key_position && byte != key[0])
            return;
        assert(byte == key[key_position]);
        if (++key_position == sizeof(key)) {
            configured = true;
            key_position = 0;
            ++key_count;
        }
    }

    void write(uint16_t target, uint8_t byte) {
        if (target == 0x279) {
            address(byte);
            return;
        }
        assert(target == 0xa79);
        if (!configured)
            return;
        switch (reg) {
        case 0:
            port = uint16_t(byte) * 4 + 3;
            break;
        case 2:
            assert(byte == 2 || byte == 4); // No reset of logical-device resources.
            if (byte == 2) {
                configured = false;
                active = nullptr;
                ++waits;
            } else {
                ++csn_resets;
                for (auto& card : cards)
                    card.number = 0;
            }
            break;
        case 3:
            assert(!byte);
            active = nullptr;
            cursor = serial_reads = logical = 0;
            data_ready = false;
            for (auto& card : cards)
                if (!card.number) {
                    active = &card;
                    break;
                }
            break;
        case 6:
            assert(active && serial_reads == 144 && port == listening && byte && !active->number);
            active->number = byte;
            ++assignments;
            break;
        case 7:
            assert(active && cursor == active->resources.size());
            assert(byte < active->functions.size());
            logical = byte;
            break;
        default:
            assert(false); // Discovery never writes Activate or resource registers.
        }
    }

    uint8_t read(uint16_t target) {
        assert(configured && target == port);
        if (!active || target != listening)
            return 0xff;
        if (reg == 1) {
            assert(!active->number && serial_reads < 144);
            unsigned index = serial_reads++;
            bool one = (active->serial[index / 16] >> ((index / 2) % 8)) & 1;
            return one ? (index % 2 ? 0xaa : 0x55) : 0xff;
        }
        assert(active->number);
        switch (reg) {
        case 5:
            ++status_reads;
            data_ready = !stall && cursor < active->resources.size();
            return data_ready;
        case 4:
            assert(data_ready);
            data_ready = false;
            ++data_reads;
            return active->resources[cursor++];
        case 6:
            return active->number;
        case 7:
            return logical;
        case 0x30:
            return active->functions[logical].active;
        case 0x60:
            return active->functions[logical].base >> 8;
        case 0x61:
            return active->functions[logical].base & 0xff;
        }
        assert(false);
        return 0;
    }

    ax::IsaPnp::Ports run() {
        const ax::IsaPnp::Bus bus{
            this, [](void* ctx, uint16_t port) { return static_cast<Model*>(ctx)->read(port); },
            [](void* ctx, uint16_t port, uint8_t value) {
                static_cast<Model*>(ctx)->write(port, value);
            },
            [](void* ctx, unsigned us) {
                static_cast<Model*>(ctx)->delays += us;
                return true;
            }};
        auto ports = ax::IsaPnp::discover(bus);
        assert(!configured && !active && waits == csn_resets * 2);
        assert(key_count == csn_resets * 2);
        return ports;
    }
};

Bytes checksum(Bytes bytes) {
    uint8_t sum = 0;
    bytes.push_back(0x79);
    for (auto byte : bytes)
        sum += byte;
    bytes.push_back(-sum);
    return bytes;
}

// A card-level long identifier followed by an unrelated logical device and a
// compatible UART. Only the second dependent configuration fits the active base.
const auto uart = checksum({
    0x82, 3,    0,    'U',  'A',  'R',  0x15, 0x41, 0xd0, 0x80, 0x01, 0,    0x15, 0x41,
    0xd0, 0x80, 0x02, 0,    0x1c, 0x41, 0xd0, 0x05, 0x01, 0x31, 0,    0x4b, 0xf8, 0x03,
    8,    0x31, 1,    0x47, 1,    0xe0, 0x02, 0x08, 0x03, 0x18, 8,    0x38,
});

const auto printer = checksum({0x15, 0x41, 0xd0, 0x04, 0x00, 0, 0x4b, 0x78, 0x02, 3});
} // namespace

int main() {
    Model empty;
    auto ports = empty.run();
    assert(!ports.cards && !ports.uart && !ports.printer && empty.csn_resets == 3);
    assert(empty.delays == 120000);

    Model healthy{
        {{serial_a, uart, {{0, false}, {0x2f8, true}}}, {serial_b, printer, {{0x278, true}}}},
        0x243};
    ports = healthy.run();
    assert(ports.cards == 2 && !ports.rejected && ports.uart == 0x2f8 && ports.printer == 0x278);
    assert(healthy.assignments == 2 && healthy.csn_resets == 2);
    assert(healthy.data_reads == uart.size() + printer.size());
    assert(healthy.status_reads == healthy.data_reads);

    Model unaligned{{{serial_a, uart, {{0, false}, {0x2e8, true}}}}};
    ports = unaligned.run();
    assert(ports.cards == 1 && !ports.rejected && !ports.uart);

    Model inactive{
        {{serial_a, uart, {{0, false}, {0x2f8, false}}}, {serial_b, printer, {{0x3bc, true}}}}};
    ports = inactive.run();
    assert(ports.cards == 2 && !ports.rejected && !ports.uart && !ports.printer);

    auto damaged = uart;
    damaged.back() ^= 0x80;
    Model bad_resource{
        {{serial_a, damaged, {{0, false}, {0x2f8, true}}}, {serial_b, printer, {{0x278, true}}}}};
    ports = bad_resource.run();
    assert(ports.cards == 2 && ports.rejected == 1 && !ports.uart && ports.printer == 0x278);

    Model oversized{{{serial_a, {0x82, 0xff, 0x7f}, {}}}};
    ports = oversized.run();
    assert(ports.cards == 1 && ports.rejected == 1 && oversized.data_reads == 3);

    Model timeout{{{serial_a, uart, {{0, false}, {0x2f8, true}}}}};
    timeout.stall = true;
    ports = timeout.run();
    assert(ports.cards == 1 && ports.rejected == 1 && timeout.status_reads == 20);

    auto invalid_id = serial_a;
    invalid_id.back() ^= 1;
    Model bad_serial{{{invalid_id, uart, {{0, false}, {0x2f8, true}}}}};
    ports = bad_serial.run();
    assert(!ports.cards && !bad_serial.assignments);

    Model ambiguous{{{serial_a, printer, {{0x278, true}}}, {serial_b, printer, {{0x278, true}}}}};
    ports = ambiguous.run();
    assert(ports.cards == 2 && !ports.rejected && !ports.printer);
    std::puts("ISA_PNP_PASS empty isolation fallback compatibility alternatives active checksum "
              "bounds timeout ambiguity");
}
