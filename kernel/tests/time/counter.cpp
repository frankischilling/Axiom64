// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/time/counter.cpp
 * @brief   Exercises timekeeping and ACPI platform table validation.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Tests counter arithmetic and checks the firmware reader with valid and
 * malformed platform tables.
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
#include "core/time.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "firmware/acpi.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>

using ax::Clock::Counter;

static uint64_t random_state = 0x4158363454494d45ull;

static uint64_t random_value() {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static void counter_tests() {
    Counter unset;
    assert(unset.sample(100) == 0 && !unset.reset(0, 0, 1));
    Counter fraction;
    assert(fraction.reset(100, 3, 7));
    assert(fraction.sample(101) == 0 && fraction.sample(102) == 0);
    assert(fraction.sample(103) == 1 && fraction.sample(107) == 3);
    assert(fraction.sample(106) == 3 && fraction.sample(107) == 3);
    assert(fraction.sample(114) == 6);
    for (auto scale : std::array<std::array<uint64_t, 2>, 6>{{{0, 1},
                                                              {1, 0},
                                                              {2, 1},
                                                              {100000001, 100000001},
                                                              {1, 10000000000001ull},
                                                              {UINT64_MAX, UINT64_MAX}}}) {
        assert(fraction.reset(100, 3, 7) && fraction.sample(114) == 6);
        assert(!fraction.reset(0, scale[0], scale[1]));
        assert(fraction.sample(121) == 9);
    }
    Counter wrap;
    assert(wrap.reset(UINT64_MAX - 4, 1, 1));
    assert(wrap.sample(3) == 8 && wrap.sample(2) == 8 && wrap.sample(5) == 10);
    Counter saturate;
    assert(saturate.reset(0, 1, 1));
    assert(saturate.sample(INT64_MAX) == uint64_t(INT64_MAX));
    assert(saturate.sample(UINT64_MAX - 1) == UINT64_MAX - 1);
    assert(saturate.sample(1) == UINT64_MAX && saturate.sample(2) == UINT64_MAX);
    Counter ambiguous;
    assert(ambiguous.reset(0, 1, 1));
    assert(ambiguous.sample(uint64_t(INT64_MAX) + 1) == 0);
    assert(ambiguous.sample(5) == 5);

    for (unsigned fixture = 0; fixture < 4096; fixture++) {
        uint64_t numerator = 1 + random_value() % 100000000;
        uint64_t denominator = numerator + random_value() % (10000000000000ull - numerator + 1);
        uint64_t reading = random_value(), expected = 0, carry = 0;
        Counter counter;
        assert(counter.reset(reading, numerator, denominator));
        for (unsigned step = 0; step < 12; step++) {
            uint64_t delta = random_value() & uint64_t(INT64_MAX);
            reading += delta;
            unsigned __int128 scaled = static_cast<unsigned __int128>(delta) * numerator + carry;
            uint64_t whole = scaled / denominator;
            carry = scaled % denominator;
            expected = whole > UINT64_MAX - expected ? UINT64_MAX : expected + whole;
            assert(counter.sample(reading) == expected);
            assert(counter.sample(reading - 1) == expected);
        }
    }
    std::puts("CLOCK_COUNTER_PASS fixtures=4096 samples=49152 fractions_wrap_backwards_saturation");
}

struct Firmware {
    static constexpr uint64_t base = 0x100000, rsdt = base + 4096, xsdt = base + 8192,
                              hpet = base + 12288;
    std::array<uint8_t, 16384> bytes{};
    size_t readable = bytes.size(), calls = 0;

    uint8_t* at(uint64_t address) {
        return bytes.data() + address - base;
    }

    void put(uint64_t address, uint64_t value, size_t count) {
        for (size_t i = 0; i < count; i++)
            at(address)[i] = uint8_t(value >> (i * 8));
    }

    void sum(uint64_t address, size_t length, size_t field) {
        auto data = at(address);
        data[field] = 0;
        uint8_t checksum = 0;
        for (size_t i = 0; i < length; i++)
            checksum += data[i];
        data[field] = uint8_t(0 - checksum);
    }

    void rsdp_sum() {
        sum(base, 20, 8);
        sum(base, 36, 32);
    }

    Firmware() {
        std::memcpy(at(base), "RSD PTR ", 8);
        at(base)[15] = 2;
        put(base + 20, 36, 4);
        put(base + 24, xsdt, 8);
        rsdp_sum();
        std::memcpy(at(rsdt), "RSDT", 4);
        put(rsdt + 4, 40, 4);
        put(rsdt + 36, hpet, 4);
        sum(rsdt, 40, 9);
        std::memcpy(at(xsdt), "XSDT", 4);
        put(xsdt + 4, 44, 4);
        put(xsdt + 36, hpet, 8);
        sum(xsdt, 44, 9);
        std::memcpy(at(hpet), "HPET", 4);
        put(hpet + 4, 56, 4);
        put(hpet + 36, 0x8086a201, 4);
        at(hpet)[41] = 64;
        put(hpet + 44, 0xfed00000, 8);
        sum(hpet, 56, 9);
    }

    static const uint8_t* read(uint64_t address, size_t length, void* context) {
        auto& f = *static_cast<Firmware*>(context);
        f.calls++;
        if (address < base || address - base > f.readable || length > f.readable - (address - base))
            return nullptr;
        return f.at(address);
    }

    bool find(ax::Acpi::Hpet& output, uint64_t address = base) {
        calls = 0;
        bool result = ax::Acpi::find_hpet(address, read, this, output);
        assert(calls <= 1040);
        return result;
    }
};

static void firmware_tests() {
    for (unsigned variant = 0; variant < 5; variant++) {
        Firmware f;
        if (variant == 1) {
            f.at(Firmware::base)[15] = 0;
            f.put(Firmware::base + 16, Firmware::rsdt, 4);
            f.rsdp_sum();
        } else if (variant == 2) {
            f.put(Firmware::base + 16, Firmware::rsdt, 4);
            f.rsdp_sum();
            f.at(Firmware::xsdt)[9]++;
        } else if (variant == 3) {
            f.at(Firmware::hpet)[41] = 0;
            f.at(Firmware::hpet)[43] = 4;
            f.sum(Firmware::hpet, 56, 9);
        } else if (variant == 4) {
            f.put(Firmware::hpet + 44, (1ull << 52) - 1024, 8);
            f.sum(Firmware::hpet, 56, 9);
        }
        ax::Acpi::Hpet found;
        assert(f.find(found));
        assert(found.address == (variant == 4 ? (1ull << 52) - 1024 : 0xfed00000));
        assert(found.id == 0x8086a201);
    }
    constexpr unsigned malformed = 29;
    for (unsigned variant = 0; variant < malformed; variant++) {
        Firmware f;
        uint64_t address = Firmware::base;
        switch (variant) {
        case 0:
            address = 0;
            break;
        case 1:
            address = 1ull << 52;
            break;
        case 2:
            f.at(address)[0] = 'X';
            break;
        case 3:
            f.at(address)[8]++;
            break;
        case 4:
            f.at(address)[15] = 1;
            f.rsdp_sum();
            break;
        case 5:
            f.at(address)[32]++;
            break;
        case 6:
            f.put(address + 20, 35, 4);
            f.rsdp_sum();
            break;
        case 7:
            f.put(address + 20, 4097, 4);
            f.rsdp_sum();
            break;
        case 8:
            f.readable = 19;
            break;
        case 9:
            f.readable = 35;
            break;
        case 10:
            f.put(address + 24, UINT64_MAX, 8);
            f.rsdp_sum();
            break;
        case 11:
            f.put(Firmware::xsdt + 4, 35, 4);
            break;
        case 12:
            f.put(Firmware::xsdt + 4, 65537, 4);
            break;
        case 13:
            f.put(Firmware::xsdt + 4, 37, 4);
            f.sum(Firmware::xsdt, 37, 9);
            break;
        case 14:
            f.at(Firmware::xsdt)[0] = 'Z';
            f.sum(Firmware::xsdt, 44, 9);
            break;
        case 15:
            f.at(Firmware::xsdt)[9]++;
            break;
        case 16:
            f.put(Firmware::xsdt + 4, 36 + 257 * 8, 4);
            f.sum(Firmware::xsdt, 36 + 257 * 8, 9);
            break;
        case 17:
            f.put(Firmware::xsdt + 36, UINT64_MAX, 8);
            f.sum(Firmware::xsdt, 44, 9);
            break;
        case 18:
            f.at(Firmware::hpet)[0] = 'Z';
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 19:
            f.at(Firmware::hpet)[9]++;
            break;
        case 20:
            f.put(Firmware::hpet + 4, 55, 4);
            break;
        case 21:
            f.put(Firmware::hpet + 4, 65537, 4);
            break;
        case 22:
            f.at(Firmware::hpet)[40] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 23:
            f.at(Firmware::hpet)[41] = 32;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 24:
            f.at(Firmware::hpet)[42] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 25:
            f.at(Firmware::hpet)[43] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 26:
            f.put(Firmware::hpet + 44, 0, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 27:
            f.put(Firmware::hpet + 44, 0xfed00001, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 28:
            f.put(Firmware::hpet + 44, 1ull << 52, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        }
        ax::Acpi::Hpet found{123, 456};
        assert(!f.find(found, address) && found.address == 123 && found.id == 456);
    }
    ax::Acpi::Hpet unused;
    assert(!ax::Acpi::find_hpet(Firmware::base, nullptr, nullptr, unused));
    for (unsigned mutation = 0; mutation < 16000; mutation++) {
        Firmware f;
        size_t offset = random_value() % f.bytes.size();
        f.bytes[offset] ^= uint8_t(1 + random_value() % 255);
        ax::Acpi::Hpet output{123, 456};
        if (f.find(output))
            assert(output.address && !(output.address & 1023) &&
                   output.address <= (1ull << 52) - 1024);
        else
            assert(output.address == 123 && output.id == 456);
    }
    std::printf("CLOCK_FIRMWARE_PASS valid=5 malformed=%u mutations=16000 bounded_reads\n",
                malformed);
}

static void platform_tables() {
    constexpr uint64_t madt = Firmware::hpet + 128, fadt = Firmware::hpet + 512;
    Firmware firmware;
    firmware.put(Firmware::xsdt + 4, 60, 4);
    firmware.put(Firmware::xsdt + 44, madt, 8);
    firmware.put(Firmware::xsdt + 52, fadt, 8);
    firmware.sum(Firmware::xsdt, 60, 9);
    std::memcpy(firmware.at(madt), "APIC", 4);
    firmware.put(madt + 4, 104, 4);
    firmware.put(madt + 36, 0xfee00000, 4);
    firmware.at(madt)[40] = 1;
    const uint8_t apics[] = {
        0,   8,  7, 3, 1,  0, 0,    0,                              // Processor Local APIC.
        1,   12, 4, 0, 0,  0, 0xc0, 0xfe, 16, 0, 0, 0,              // I/O APIC.
        2,   10, 0, 9, 19, 0, 0,    0,    15, 0,                    // ISA override.
        128, 2,                                                     // Unrecognized OEM entry.
        9,   16, 0, 0, 3,  1, 0,    0,    2,  0, 0, 0, 7, 16, 0, 0, // Local x2APIC.
        5,   12, 0, 0, 0,  0, 0xe0, 0xfe, 1,  0, 0, 0,              // 64-bit LAPIC address.
    };
    static_assert(sizeof(apics) == 60);
    std::memcpy(firmware.at(madt + 44), apics, sizeof(apics));
    firmware.sum(madt, 104, 9);
    std::memcpy(firmware.at(fadt), "FACP", 4);
    firmware.put(fadt + 4, 116, 4);
    firmware.at(fadt)[8] = 6;
    firmware.at(fadt)[46] = 9;
    firmware.at(fadt)[109] = 3;
    firmware.put(fadt + 112, 0x100100, 4);
    firmware.sum(fadt, 116, 9);

    using namespace ax::Acpi;
    InterruptTopology topology{};
    Hpet timer;
    FixedDescription fixed{};
    assert(firmware.find(timer) && timer.address == 0xfed00000);
    assert(find_interrupt_topology(Firmware::base, Firmware::read, &firmware, topology));
    assert(topology.local_apic == 0x1fee00000 && topology.legacy_pic);
    assert(topology.processor_count == 2 && topology.processors[0].uid == 7 &&
           topology.processors[0].apic_id == 3 && topology.processors[0].flags == 1 &&
           topology.processors[1].apic_id == 0x103 && topology.processors[1].uid == 0x1007 &&
           topology.processors[1].flags == 2);
    assert(topology.io_apic_count == 1 && topology.io_apics[0].id == 4 &&
           topology.io_apics[0].address == 0xfec00000 && topology.io_apics[0].first_gsi == 16);
    assert(!topology.isa[0].present && topology.isa[9].present && topology.isa[9].gsi == 19 &&
           topology.isa[9].flags == 15);
    assert(find_fixed_description(Firmware::base, Firmware::read, &firmware, fixed));
    assert(fixed.flags == 0x100100 && fixed.sci == 9 && fixed.boot_flags == 3 &&
           fixed.revision == 6);

    for (unsigned variant = 0; variant < 8; ++variant) {
        Firmware damaged = firmware;
        switch (variant) {
        case 0:
            damaged.at(madt + 44)[1] = 0;
            break; // Zero-length record.
        case 1:
            damaged.at(madt + 92)[1] = 13;
            break; // Record crosses table end.
        case 2:
            damaged.at(madt + 52)[1] = 11;
            break; // Truncated I/O APIC.
        case 3:
            damaged.at(madt + 64)[8] = 2;
            break; // Reserved interrupt polarity.
        case 4:
            damaged.at(madt + 52)[4] = 1;
            break; // Unaligned MMIO aperture.
        case 5:
            damaged.put(madt + 76 + 12, 7, 4);
            break; // Duplicate ACPI processor UID.
        case 6:
            damaged.put(madt + 92 + 4, 1ull << 52, 8);
            break; // Physical bound.
        case 7:
            damaged.put(madt + 92 + 4, 0xfec00000, 8);
            break; // Colliding MMIO pages.
        }
        damaged.sum(madt, 104, 9);
        assert(!find_interrupt_topology(Firmware::base, Firmware::read, &damaged, topology));
        assert(topology.processor_count == 2 && topology.local_apic == 0x1fee00000);
        assert(find_fixed_description(Firmware::base, Firmware::read, &damaged, fixed));
    }
    Firmware mixed = firmware;
    mixed.put(madt + 76 + 4, 3, 4);
    mixed.sum(madt, 104, 9);
    assert(find_interrupt_topology(Firmware::base, Firmware::read, &mixed, topology));
    assert(topology.processor_count == 1 && topology.processors[0].uid == 7);
    mixed.at(madt + 44)[3] = 0xff;
    mixed.sum(madt, 104, 9);
    assert(find_interrupt_topology(Firmware::base, Firmware::read, &mixed, topology));
    assert(topology.processor_count == 1 && topology.processors[0].uid == 0x1007);
    mixed.put(madt + 76 + 4, UINT32_MAX, 4);
    mixed.sum(madt, 104, 9);
    assert(!find_interrupt_topology(Firmware::base, Firmware::read, &mixed, topology));

    firmware.at(fadt)[8] = 1;
    firmware.sum(fadt, 116, 9);
    assert(find_fixed_description(Firmware::base, Firmware::read, &firmware, fixed));
    assert(fixed.revision == 1 && !fixed.boot_flags && fixed.sci == 9);
    firmware.at(fadt)[9]++;
    assert(!find_fixed_description(Firmware::base, Firmware::read, &firmware, fixed));
    assert(fixed.revision == 1 && fixed.sci == 9);
    std::puts("ACPI_PLATFORM_TABLES_PASS malformed=9");
}

static void pm_timer_tables() {
    using namespace ax::Acpi;
    constexpr auto table = Firmware::hpet;
    Firmware fixture;
    std::memcpy(fixture.at(table), "FACP", 4);
    fixture.put(table + 4, 220, 4);
    fixture.at(table)[8] = 6;
    fixture.put(table + 76, 0x408, 4);
    fixture.at(table)[91] = 4;
    fixture.sum(table, 220, 9);
    PmTimer timer{};
    auto find = [&] { return find_pm_timer(Firmware::base, Firmware::read, &fixture, timer); };
    assert(find() && timer.port == 0x408 && timer.mask == 0xffffff);

    fixture.at(table)[208] = 1;
    fixture.at(table)[209] = 32;
    fixture.at(table)[211] = 3;
    fixture.put(table + 212, 0x1808, 8);
    fixture.sum(table, 220, 9);
    assert(find() && timer.port == 0x1808 && timer.mask == 0xffffff);

    fixture.put(table + 112, 1u << 8, 4);
    fixture.sum(table, 220, 9);
    assert(find() && timer.port == 0x1808 && timer.mask == UINT32_MAX);
    for (auto [offset, invalid] :
         {std::pair{91u, 2u}, std::pair{114u, 16u}, std::pair{208u, 0u}, std::pair{209u, 24u},
          std::pair{210u, 8u}, std::pair{211u, 2u}, std::pair{214u, 1u}}) {
        uint8_t& field = fixture.at(table)[offset];
        const uint8_t saved = field;
        field = uint8_t(invalid);
        fixture.sum(table, 220, 9);
        assert(!find());
        field = saved;
    }
    fixture.put(table + 4, 116, 4);
    fixture.at(table)[8] = 1;
    fixture.sum(table, 116, 9);
    assert(find() && timer.port == 0x408 && timer.mask == UINT32_MAX);
    fixture.at(table)[9]++;
    assert(!find());
    std::puts("ACPI_PM_TIMER_PASS legacy extended malformed");
}

static void ecam_tables() {
    constexpr uint64_t mcfg = Firmware::hpet + 128;
    Firmware fixture;
    fixture.put(Firmware::xsdt + 4, 44, 4);
    fixture.put(Firmware::xsdt + 36, mcfg, 8);
    fixture.sum(Firmware::xsdt, 44, 9);
    std::memcpy(fixture.at(mcfg), "MCFG", 4);
    fixture.put(mcfg + 4, 76, 4);
    fixture.put(mcfg + 8, 1, 1);
    fixture.put(mcfg + 44, 0xe0000000, 8);
    fixture.put(mcfg + 54, 16, 1);
    fixture.put(mcfg + 55, 31, 1);
    fixture.put(mcfg + 60, 0x100000000, 8);
    fixture.put(mcfg + 68, 7, 2);
    fixture.put(mcfg + 71, 255, 1);
    fixture.sum(mcfg, 76, 9);

    using namespace ax::Acpi;
    Mcfg result{};
    assert(find_mcfg(Firmware::base, Firmware::read, &fixture, result));
    assert(result.count == 2 && result.regions[0].segment == 0 && result.regions[1].segment == 7);
    assert(result.regions[0].contains(16) && result.regions[0].contains(31));
    assert(!result.regions[0].contains(15) && !result.regions[0].contains(32));
    assert(result.regions[0].bus_address(16) == 0xe1000000);
    assert(result.regions[1].bus_address(255) == 0x10ff00000);

    for (unsigned variant = 0; variant < 10; ++variant) {
        Firmware damaged = fixture;
        size_t length = 76;
        switch (variant) {
        case 0:
            length = 75;
            break;
        case 1:
            length = 44;
            break;
        case 2:
            damaged.put(mcfg + 36, 1, 1);
            break;
        case 3:
            damaged.put(mcfg + 56, 1, 1);
            break;
        case 4:
            damaged.put(mcfg + 44, 0xe0000001, 8);
            break;
        case 5:
            damaged.put(mcfg + 54, 32, 1);
            break;
        case 6:
            damaged.put(mcfg + 60, (1ull << 52) - EcamRegion::bus_bytes, 8);
            break;
        case 7:
            damaged.put(mcfg + 68, 0, 2);
            break;
        case 8:
            damaged.put(mcfg + 60, 0xe1000000, 8);
            break;
        case 9:
            damaged.put(mcfg + 8, 0, 1);
            break;
        }
        damaged.put(mcfg + 4, length, 4);
        damaged.sum(mcfg, length, 9);
        assert(!find_mcfg(Firmware::base, Firmware::read, &damaged, result));
        assert(result.count == 2 && result.regions[1].segment == 7);
    }
    std::puts("ACPI_MCFG_PASS regions=2 malformed=10");
}

static void isa_routes() {
    using namespace ax::Irq;
    constexpr GsiRange ranges[] = {{0, 24}, {32, 16}};
    Route route{};
    assert(isa_route(0, 0, ranges, 2, route) && !route.controller && !route.input && !route.mode);
    assert(isa_route(2, 5, ranges, 2, route) && !route.controller && route.input == 2 &&
           !route.mode);
    assert(isa_route(47, 15, ranges, 2, route) && route.controller == 1 && route.input == 15 &&
           route.mode == (active_low | level_triggered));
    assert(isa_route(36, 3, ranges, 2, route) && route.controller == 1 && route.input == 4 &&
           route.mode == active_low);
    assert(!isa_route(24, 0, ranges, 2, route));
    assert(!isa_route(48, 0, ranges, 2, route));
    assert(!isa_route(0, 2, ranges, 2, route));
    assert(!isa_route(0, 8, ranges, 2, route));
    assert(!isa_route(0, 16, ranges, 2, route));
    constexpr GsiRange overlap[] = {{0, 24}, {20, 24}};
    assert(!isa_route(21, 0, overlap, 2, route));
    constexpr GsiRange overflow[] = {{UINT32_MAX, 2}};
    assert(!isa_route(UINT32_MAX, 0, overflow, 1, route));
    constexpr GsiRange too_many[] = {{0, max_inputs + 1}};
    assert(!isa_route(0, 0, too_many, 1, route));
    constexpr GsiRange empty[] = {{0, 0}};
    assert(!isa_route(0, 0, empty, 1, route));
    assert(route.controller == 1 && route.input == 4 && route.mode == active_low);
    std::puts("ISA_INTERRUPT_ROUTE_PASS valid=4 rejected=9");
}

static void definition_blocks() {
    using ax::Acpi::DefinitionBlocks;
    constexpr auto rsdp = Firmware::base, rsdt = Firmware::rsdt, xsdt = Firmware::xsdt;
    constexpr auto fadt = Firmware::hpet + 512, dsdt32 = fadt + 256, dsdt64 = dsdt32 + 64;
    constexpr auto ssdt_a = dsdt64 + 128, ssdt_b = ssdt_a + 64;
    constexpr uint64_t high = 1ull << 32;
    Firmware f;
    auto table = [&](uint64_t address, const char* signature, size_t length) {
        std::memcpy(f.at(address), signature, 4);
        f.put(address + 4, length, 4);
        f.sum(address, length, 9);
    };
    table(fadt, "FACP", 148);
    f.put(fadt + 40, dsdt32, 4);
    f.put(fadt + 140, high + dsdt64, 8);
    f.sum(fadt, 148, 9);
    table(dsdt32, "DSDT", 40);
    table(dsdt64, "DSDT", 41);
    table(ssdt_a, "SSDT", 42);
    table(ssdt_b, "SSDT", 43);
    f.put(xsdt + 36, ssdt_b, 8);
    f.put(xsdt + 44, fadt, 8);
    f.put(xsdt + 52, ssdt_a, 8);
    f.put(xsdt + 60, ssdt_b, 8);
    table(xsdt, "XSDT", 68);
    f.put(rsdt + 36, fadt, 4);
    f.put(rsdt + 40, ssdt_a, 4);
    table(rsdt, "RSDT", 44);
    f.put(rsdp + 16, rsdt, 4);
    f.rsdp_sum();

    auto reader = +[](uint64_t address, size_t length, void* context) -> const uint8_t* {
        if (address >= high)
            address -= high;
        return Firmware::read(address, length, context);
    };
    DefinitionBlocks blocks;
    auto find = [&]() { return ax::Acpi::find_definition_blocks(rsdp, reader, &f, blocks); };
    assert(find() && blocks.dsdt.table == f.at(dsdt64) && blocks.dsdt.address == high + dsdt64 &&
           blocks.dsdt.length == 41 && blocks.ssdt_count == 2);
    assert(blocks.ssdt[0].address == ssdt_b && blocks.ssdt[0].length == 43 &&
           blocks.ssdt[1].address == ssdt_a && blocks.ssdt[1].length == 42);

    f.at(ssdt_a)[9]++;
    assert(!find() && !blocks.dsdt.table && !blocks.ssdt_count && !blocks.ssdt[0].table);
    f.sum(ssdt_a, 42, 9);
    f.at(dsdt64)[9]++;
    assert(!find() && !blocks.dsdt.table);
    f.sum(dsdt64, 41, 9);
    f.put(dsdt64 + 4, 1024 * 1024 + 1, 4);
    assert(!find() && !blocks.dsdt.table);
    table(dsdt64, "DSDT", 41);
    f.at(xsdt)[9]++;
    assert(!find()); // A damaged XSDT cannot select a different AML namespace.
    f.sum(xsdt, 68, 9);
    f.put(xsdt + 60, 1ull << 52, 8);
    f.sum(xsdt, 68, 9);
    assert(!find() && !blocks.dsdt.table && !blocks.ssdt_count);
    f.put(xsdt + 60, 0, 8);
    f.sum(xsdt, 68, 9);
    assert(find() && blocks.ssdt_count == 2);

    f.put(fadt + 140, 0, 8);
    f.sum(fadt, 148, 9);
    assert(find() && blocks.dsdt.address == dsdt32 && blocks.ssdt_count == 2);
    // An ACPI 1.0 FADT has no extended pointer even if the following bytes are readable.
    f.put(fadt + 140, high + dsdt64, 8);
    table(fadt, "FACP", 116);
    f.at(rsdp)[15] = 0;
    f.rsdp_sum();
    assert(find() && blocks.dsdt.address == dsdt32 && blocks.ssdt_count == 1 &&
           blocks.ssdt[0].address == ssdt_a);

    constexpr uint64_t large_base = 1ull << 40, megabyte = 1024 * 1024;
    static std::array<uint8_t, megabyte> large{};
    std::memcpy(large.data(), "SSDT", 4);
    large[6] = 16; // One MiB in the little-endian table length.
    uint8_t sum = 0;
    for (uint8_t byte : large)
        sum += byte;
    large[9] = uint8_t(0 - sum);
    auto large_reader = +[](uint64_t address, size_t length, void* context) -> const uint8_t* {
        if (address >= large_base && address < large_base + 8 * megabyte && length <= large.size())
            return large.data();
        return Firmware::read(address, length, context);
    };
    f.at(rsdp)[15] = 2;
    f.rsdp_sum();
    f.put(xsdt + 36, fadt, 8);
    for (unsigned index = 0; index < 8; ++index)
        f.put(xsdt + 44 + 8 * index, large_base + index * megabyte, 8);
    table(xsdt, "XSDT", 36 + 8 * 8); // FADT and seven one-MiB SSDTs fit together.
    assert(ax::Acpi::find_definition_blocks(rsdp, large_reader, &f, blocks) &&
           blocks.ssdt_count == 7);
    table(xsdt, "XSDT", 36 + 9 * 8);
    assert(!ax::Acpi::find_definition_blocks(rsdp, large_reader, &f, blocks) &&
           !blocks.dsdt.table && !blocks.ssdt_count);
    std::puts("ACPI_DEFINITION_BLOCKS_PASS legacy extended ordered_ssdt invalid_namespace budget");
}

static void global_lock_control() {
    using namespace ax::Acpi;
    Firmware firmware;
    constexpr uint64_t fadt = Firmware::hpet + 512;
    firmware.put(Firmware::xsdt + 36, fadt, 8);
    firmware.sum(Firmware::xsdt, 44, 9);
    std::memcpy(firmware.at(fadt), "FACP", 4);
    firmware.at(fadt)[8] = 6;
    firmware.at(fadt)[89] = 2;
    firmware.put(fadt + 36, 0x123400, 4);
    firmware.put(fadt + 64, 0x1804, 4);
    GlobalLockControl output{};
    const auto read = [&](size_t length) {
        firmware.put(fadt + 4, length, 4);
        firmware.sum(fadt, length, 9);
        return find_global_lock_control(Firmware::base, Firmware::read, &firmware, output);
    };
    assert(read(116) && output.facs == 0x123400 && output.pm1a == 0x1804 && !output.pm1b);

    firmware.put(fadt + 132, 0x100123400, 8);
    firmware.put(fadt + 176, 0x1808, 8);
    firmware.put(fadt + 172, 0x02001001, 4); // 16-bit SystemIO with word access.
    assert(read(196) && output.facs == 0x100123400 && output.pm1a == 0x1808);
    firmware.put(fadt + 188, 0x180a, 8);
    firmware.put(fadt + 184, 0x02001001, 4);
    assert(read(196) && output.pm1b == 0x180a);
    firmware.put(fadt + 188, 0x1808, 8);
    assert(!read(196) && !output.facs);
    firmware.put(fadt + 188, 0, 8);
    firmware.at(fadt)[172] = 0; // Unsupported SystemMemory control register.
    assert(!read(196));
    firmware.at(fadt)[172] = 1;
    firmware.put(fadt + 132, 0x100123404, 8);
    assert(!read(196));
    firmware.put(fadt + 132, 0x100123400, 8);
    firmware.put(fadt + 112, 1u << 20, 4);
    assert(!read(196));

    volatile uint32_t word = 0x12345600;
    assert(try_acquire_global_lock(word) && word == 0x12345602);
    assert(!try_acquire_global_lock(word) && word == 0x12345602);
    word = 0x12345603;
    assert(release_global_lock(word) && word == 0x12345600);
    assert(try_acquire_global_lock(word) && !release_global_lock(word) && word == 0x12345600);
    std::puts("ACPI_GLOBAL_LOCK_PASS legacy extended rejected_control pending busy");
}

int main() {
    counter_tests();
    firmware_tests();
    platform_tables();
    pm_timer_tables();
    ecam_tables();
    isa_routes();
    definition_blocks();
    global_lock_control();
    std::puts("CLOCK_CODEC_TESTS_PASS");
}
