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
    uint8_t ranges = 0;
    uint8_t irq = 0, second_irq = 0;
    unsigned width = 8;
};

struct Card {
    const std::array<uint8_t, 9> serial;
    const Bytes resources;
    std::vector<Function> functions;
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
    uint16_t occupied = 0, damaged_check = 0;
    bool fail_probe = false, fail_deactivate = false, fail_disable_check = false;
    unsigned config_writes = 0, probes = 0;

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
            active = nullptr;
            cursor = serial_reads = logical = 0;
            data_ready = false;
            for (auto& card : cards)
                if (card.number == byte) {
                    active = &card;
                    if (byte)
                        cursor = card.resources.size();
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
        default: {
            assert(active && active->number && logical < active->functions.size());
            auto& fn = active->functions[logical];
            ++config_writes;
            if (reg == 0x30) {
                assert(byte <= 1 && !(fn.ranges & 2));
                if (byte || !fail_deactivate)
                    fn.active = byte;
            } else {
                assert(!fn.active);
                if (reg == 0x31) {
                    if ((byte & 2) || !fail_disable_check)
                        fn.ranges = byte;
                } else if (reg == 0x60)
                    fn.base = (fn.base & 0xff) | (uint16_t(byte) << 8);
                else if (reg == 0x61)
                    fn.base = (fn.base & 0xff00) | byte;
                else if (reg == 0x70)
                    fn.irq = byte;
                else if (reg == 0x72)
                    fn.second_irq = byte;
                else
                    assert(false);
            }
        }
        }
    }

    uint8_t read(uint16_t target) {
        assert(configured);
        if (target != port) {
            assert(active && logical < active->functions.size());
            const auto& fn = active->functions[logical];
            if (target == occupied)
                return 0;
            if ((fn.ranges & 2) && target >= fn.base && unsigned(target - fn.base) < fn.width) {
                if (target == damaged_check && fn.ranges == 2)
                    return 0xff;
                return fn.ranges & 1 ? 0x55 : 0xaa;
            }
            return 0xff;
        }
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
        case 0x31:
            return active->functions[logical].ranges;
        case 0x60:
            return active->functions[logical].base >> 8;
        case 0x61:
            return active->functions[logical].base & 0xff;
        case 0x70:
            return active->functions[logical].irq;
        case 0x72:
            return active->functions[logical].second_irq;
        }
        assert(false);
        return 0;
    }

    ax::IsaPnp::Ports run(bool configure = false) {
        const ax::IsaPnp::Bus bus{
            this, [](void* ctx, uint16_t port) { return static_cast<Model*>(ctx)->read(port); },
            [](void* ctx, uint16_t port, uint8_t value) {
                static_cast<Model*>(ctx)->write(port, value);
            },
            [](void* ctx, unsigned us) {
                static_cast<Model*>(ctx)->delays += us;
                return true;
            }};
        const ax::IsaPnp::Activation activation{
            configure, configure, [](void* ctx, ax::IsaPnp::Device, uint16_t base) {
                auto& model = *static_cast<Model*>(ctx);
                const auto& fn = model.active->functions[model.logical];
                assert(fn.active && fn.base == base && !(fn.ranges & 2) && !fn.irq &&
                       !fn.second_irq);
                ++model.probes;
                return !model.fail_probe;
            }};
        auto ports = ax::IsaPnp::discover(bus, configure ? activation : ax::IsaPnp::Activation{});
        assert(!configured && !active && waits == csn_resets * 2);
        assert(key_count == csn_resets * 2);
        if (!configure)
            assert(!config_writes);
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

const auto configurable_uart = checksum({
    0x15, 0x41, 0xd0, 0x05, 0x01, 2,    // Advertises I/O range check.
    0x22, 0x18, 0,    0x22, 0x20, 0,    // Advertises two IRQ registers.
    0x30, 0x4b, 0xf8, 0x03, 8,          // COM1 alternative.
    0x30, 0x4b, 0xf8, 0x02, 8,    0x38, // COM2 alternative.
});

void activation_cases() {
    Model enabled{{{serial_a, configurable_uart, {{0, false, 0, 3, 5}}}}};
    enabled.occupied = 0x3f8;
    auto ports = enabled.run(true);
    assert(ports.uart == 0x2f8 && ports.enabled == 1 && ports.uart_probed && enabled.probes == 1);
    assert(!ports.rollback_failed && enabled.cards[0].functions[0].active);

    Model prefer_active{{{serial_a, configurable_uart, {{0, false, 0, 3, 5}}},
                         {serial_b, configurable_uart, {{0x2f8, true}}}}};
    ports = prefer_active.run(true);
    assert(ports.uart == 0x2f8 && !ports.enabled && !prefer_active.config_writes);

    Model wrong_pattern{{{serial_a, configurable_uart, {{0x3e8, false, 1, 3, 5}}}}};
    wrong_pattern.occupied = 0x3f8;
    wrong_pattern.damaged_check = 0x2ff;
    ports = wrong_pattern.run(true);
    const auto& untouched = wrong_pattern.cards[0].functions[0];
    assert(!ports.uart && !ports.rollback_failed && !wrong_pattern.probes);
    assert(untouched.base == 0x3e8 && untouched.ranges == 1 && untouched.irq == 3 &&
           untouched.second_irq == 5 && !untouched.active);

    Model stuck_check{{{serial_a, configurable_uart, {{0x3e8, false, 0, 3, 5}}}}};
    stuck_check.occupied = 0x3f8;
    stuck_check.fail_disable_check = true;
    ports = stuck_check.run(true);
    const auto& stopped = stuck_check.cards[0].functions[0];
    assert(!ports.uart && ports.rollback_failed && !stuck_check.probes);
    assert(!stopped.active && stopped.base == 0x2f8 && stopped.ranges == 2 && stopped.irq == 3 &&
           stopped.second_irq == 5);

    for (bool restore_fails : {false, true}) {
        Model failed{{{serial_a, configurable_uart, {{0x3e8, false, 0, 3, 5}}}}};
        failed.occupied = 0x3f8;
        failed.fail_probe = true;
        failed.fail_deactivate = restore_fails;
        ports = failed.run(true);
        assert(!ports.uart && failed.probes == 1 && ports.rollback_failed == restore_fails);
        const auto& final = failed.cards[0].functions[0];
        if (!restore_fails)
            assert(!final.active && final.base == 0x3e8 && final.irq == 3 && final.second_irq == 5);
        else
            assert(final.active && final.base == 0x2f8);
    }

    auto needs_dma = configurable_uart;
    needs_dma.resize(needs_dma.size() - 2);
    needs_dma.insert(needs_dma.end(), {0x2a, 0x04, 0x00});
    Model unsupportable{{{serial_a, checksum(needs_dma), {{0, false}}}}};
    ports = unsupportable.run(true);
    assert(!ports.uart && !unsupportable.config_writes);

    Model absent_range_check{{{serial_a, printer, {{0, false}}}}};
    ports = absent_range_check.run(true);
    assert(!ports.printer && !absent_range_check.config_writes);
}
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
    activation_cases();
    std::puts("ISA_PNP_PASS empty isolation fallback compatibility alternatives active checksum "
              "bounds timeout ambiguity range-check activation rollback");
}
