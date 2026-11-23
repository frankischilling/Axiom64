// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/platform/pci_interrupts.cpp
 * @brief   Tests PCI message configuration and resource validation on the host.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Supplies a synthetic configuration page and MSI-X table to the production
 * PCI implementation. Guest fixtures exercise delivery on actual QEMU devices.
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
#include <cassert>
#include <cstdio>
#include <sys/mman.h>
#include "boot/boot.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/platform/pci_bridge.hpp"

namespace {
constexpr uint32_t base = 0x10000000;
constexpr uint16_t command = 0x407;
constexpr uint8_t capability = 0x50;
unsigned mappings, registrations, retirements;
bool mapping_error, route_available = true;
uint32_t table[4];
unsigned delay_us;
bool clock_ready = true;

void handler(void*) {
}

void reset(const ax::PciFunction& pci, uint8_t id, uint16_t control, uint8_t next = 0) {
    memset(const_cast<uint8_t*>(pci.configuration), 0, 4096);
    pci.write16(4, command);
    pci.write16(6, 16);
    pci.write32(0x34, capability);
    pci.write32(capability, id | uint32_t(next) << 8 | uint32_t(control) << 16);
}

void test_power_state(const ax::PciFunction& pci) {
    using enum ax::PciPowerState;
    constexpr auto pmcsr = capability + 4;
    constexpr uint16_t pme_enable = 1 << 8, pme_status = 1 << 15;
    reset(pci, 1, 3 | (1 << 10));
    pci.write16(pmcsr, pme_status | pme_enable | 3);
    assert(pci.power_state() == d3hot);
    assert(!pci.set_power_state(d0) && delay_us == 0); // Function is decoding.
    assert(pci.read16(pmcsr) == (pme_status | pme_enable | 3));
    pci.write16(4, 0);
    assert(!pci.set_power_state(d2) && delay_us == 0);
    assert(pci.set_power_state(d0) && pci.power_state() == d0 && delay_us == 10000);
    assert(pci.read16(pmcsr) == pme_enable); // A zero write leaves hardware PME status alone.
    assert(!pci.set_power_state(d1));
    assert(pci.set_power_state(d2) && pci.power_state() == d2 && delay_us == 10200);
    assert(pci.set_power_state(d0) && pci.power_state() == d0 && delay_us == 10400);
    assert(pci.set_power_state(d3hot) && pci.power_state() == d3hot && delay_us == 20400);
    clock_ready = false;
    assert(!pci.set_power_state(d0));
    clock_ready = true;

    reset(pci, 1, 3, pmcsr); // Another capability overlaps the PMCSR.
    assert(pci.power_state() == unavailable && !pci.set_power_state(d0));
    reset(pci, 1, 0);
    assert(pci.power_state() == unavailable && !pci.set_power_state(d0));
    reset(pci, 1, 3);
    pci.write16(pmcsr, UINT16_MAX);
    assert(pci.power_state() == unavailable && !pci.set_power_state(d0));
    std::puts("PCI_POWER_PASS d3hot d2 decode_guard truncated_capability");
}

void test_msi(const ax::PciFunction& pci) {
    ax::PciMsi msi;
    reset(pci, 5, 0x24); // A firmware-selected multiple-message configuration.
    pci.write32(capability + 8, 0xabcd0000);
    assert(msi.start(pci, handler, nullptr));
    assert(pci.read32(capability + 4) == 0xfee00000);
    assert(pci.read32(capability + 8) == 0xabcd0040);
    assert(pci.read16(capability + 2) == 5);
    msi.stop(pci);
    msi.stop(pci);
    assert(!msi.active() && pci.read16(capability + 2) == 4 && retirements == 1);

    reset(pci, 5, 0x180, 0x68);
    pci.write32(0x68, 0x80000011); // Firmware left MSI-X enabled.
    pci.write32(capability + 8, UINT32_MAX);
    pci.write32(capability + 12, 0xabcd0000);
    pci.write32(capability + 16, 0x83);
    assert(msi.start(pci, handler, nullptr));
    assert(pci.read16(0x6a) == 0x4000 && pci.read32(capability + 8) == 0);
    assert(pci.read32(capability + 12) == 0xabcd0040 && pci.read32(capability + 16) == 0x82);
    msi.stop(pci);
    assert(pci.read32(capability + 16) == 0x83 && retirements == 2);

    reset(pci, 5, 0, 0x58); // The next capability overlaps the message data.
    pci.write32(0x58, 1);
    assert(!msi.start(pci, handler, nullptr) && pci.read32(0x58) == 1);
    reset(pci, 5, 0, capability);
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0, 0x70);
    pci.write32(0x70, 5); // Duplicate MSI declarations.
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0xe); // Reserved message count.
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0);
    pci.write16(4, command & ~uint16_t(0x400));
    assert(!msi.start(pci, handler, nullptr));
    assert(registrations == 2 && mappings == 0 && retirements == 2);

    reset(pci, 5, 0);
    route_available = false;
    assert(!msi.start(pci, handler, nullptr) && !msi.active());
    assert(pci.read16(capability + 2) == 0 && retirements == 2);
    route_available = true;
    std::puts("PCI_MSI_RESOURCE_PASS width32 width64 masking teardown invalid_capabilities");
}

void test_msix(const ax::PciFunction& pci) {
    ax::PciMsix msix;
    const auto prepare = [&](uint8_t at) {
        ax::PciBar bar;
        if (at <= 0xf4)
            pci.probe_bar(pci.read32(at + 4) & 7, ax::PciBarSpace::memory, bar);
        return msix.prepare(pci, at, bar, handler, nullptr);
    };
    reset(pci, 0x11, 0);
    pci.write32(0x10, base);
    assert(prepare(capability));
    assert(pci.read16(4) == command && pci.read32(0x10) == base);
    assert(pci.read16(capability + 2) == 0xc000);
    assert(table[0] == 0xfee00000 && table[1] == 0 && table[2] == 0x40 && table[3] == 1);
    assert(msix.unmask(pci) && table[3] == 0 && pci.read16(capability + 2) == 0x8000);
    msix.stop(pci);
    msix.stop(pci);
    assert(retirements == 3 && pci.read16(capability + 2) == 0x4000);

    pci.write32(capability + 4, 8);
    assert(!prepare(capability));
    pci.write32(capability + 4, 0);
    pci.write16(capability + 2, 1);
    assert(!prepare(capability));
    pci.write16(capability + 2, 0);
    pci.write32(0x10, base | 1);
    assert(!prepare(capability));
    pci.write32(0x10, base | 4);
    pci.write32(capability + 4, 1);
    assert(!prepare(capability));
    pci.write32(capability + 4, 6);
    assert(!prepare(capability));
    assert(!prepare(0xf8));
    pci.write32(capability + 4, 0);
    pci.write32(0x14, UINT32_MAX);
    assert(!prepare(capability));
    assert(pci.read16(4) == command && pci.read32(0x14) == UINT32_MAX);
    assert(registrations == 4 && mappings == 1 && retirements == 3);

    pci.write32(0x10, base);
    mapping_error = true;
    assert(!prepare(capability));
    assert(mappings == 2 && retirements == 4 && pci.read16(capability + 2) == 0x4000);
    std::puts("PCI_MSIX_RESOURCE_PASS single_entry invalid_resource_ranges failed_mapping");
}

struct ConfigModel {
    mutable uint16_t flags = command;
    mutable uint32_t bars[6]{};
    uint32_t masks[6]{};
    mutable bool sizing[6]{};
    mutable unsigned bar_writes = 0;
    uint8_t header_type = 0;
    bool refuse_quiet = false, refuse_restore = false, refuse_enable = false;

    uint8_t read8(unsigned offset) const {
        assert(offset == 0x0e);
        return header_type;
    }

    uint16_t read16(unsigned offset) const {
        assert(offset == 4);
        return flags;
    }

    uint32_t read32(unsigned offset) const {
        assert(offset >= 0x10 && offset <= 0x24 && !(offset & 3));
        unsigned index = (offset - 0x10) / 4;
        return sizing[index] ? masks[index] : bars[index];
    }

    void write16(unsigned offset, uint16_t next) const {
        assert(offset == 4);
        if ((next & 7) ? refuse_enable : refuse_quiet)
            return;
        if (next & 7)
            for (bool probing : sizing)
                assert(!probing);
        flags = next;
    }

    void write32(unsigned offset, uint32_t value) const {
        assert(!(flags & 7));
        assert(offset >= 0x10 && offset <= 0x24 && !(offset & 3));
        unsigned index = (offset - 0x10) / 4;
        ++bar_writes;
        if (value == UINT32_MAX)
            sizing[index] = true;
        else if (!refuse_restore) {
            sizing[index] = false;
            bars[index] = value;
        }
    }
};

void test_apertures() {
    using namespace ax;
    using enum PciBarStatus;
    using enum PciBarSpace;
    constexpr uint64_t limit = 1ull << 36;
    ConfigModel pci;
    PciBar resource;
    const auto probe = [&](unsigned index, PciBarSpace space) {
        return PciBarProbe::probe(pci, index, space, limit, resource);
    };

    pci.bars[0] = base | 8;
    pci.masks[0] = 0xfffe0008;
    assert(probe(0, memory) == valid);
    assert(resource.base == base && resource.size == 0x20000 && resource.index == 0);
    assert(pci.flags == command && pci.bars[0] == (base | 8) && pci.bar_writes == 2);
    uint64_t address = 0;
    assert(resource.range(0x1fff8, 8, address) && address == base + 0x1fff8);
    assert(!resource.range(0x1fff8, 9, address) && address == base + 0x1fff8);
    assert(!resource.range(0x20000, 1, address) && !resource.range(0, 0, address));

    pci.bars[2] = 4;
    pci.bars[3] = 2;
    pci.masks[2] = 0xffffc004;
    pci.masks[3] = UINT32_MAX;
    assert(probe(3, memory) == invalid && pci.bar_writes == 2);
    assert(probe(2, memory) == valid);
    assert(resource.base == 2ull << 32 && resource.size == 0x4000 && resource.index == 2);
    assert(pci.flags == command && pci.bars[2] == 4 && pci.bars[3] == 2 && pci.bar_writes == 6);
    pci.bars[3] = 16;
    assert(probe(2, memory) == invalid && pci.bar_writes == 6);
    pci.bars[5] = 4;
    assert(probe(5, memory) == invalid && probe(6, memory) == invalid && pci.bar_writes == 6);

    pci.bars[4] = 0xffe1;
    pci.masks[4] = 0x0000ffe1;
    assert(probe(4, ports) == valid && resource.base == 0xffe0 && resource.size == 32);
    assert(resource.range(20, 12, address) && address == 0xfff4);
    assert(!resource.range(20, 13, address) && probe(4, memory) == invalid);
    pci.masks[4] = 0xffffffe1;
    assert(probe(4, ports) == valid && resource.size == 32);
    pci.bars[4] = 0x10001;
    assert(probe(4, ports) == invalid);

    pci.masks[0] = 0xfffef008;
    assert(probe(0, memory) == invalid && pci.flags == command && pci.bars[0] == (base | 8));
    pci.masks[0] = 0xfffe0008;
    pci.bars[0] = base + 0x1000;
    assert(probe(0, memory) == invalid && pci.flags == command);
    pci.bars[0] = base;
    pci.header_type = 1;
    assert(probe(0, memory) == invalid);
    pci.header_type = 0;
    pci.refuse_quiet = true;
    const auto writes = pci.bar_writes;
    assert(probe(0, memory) == invalid && pci.bar_writes == writes && pci.flags == command);
    pci.refuse_quiet = false;
    pci.refuse_restore = true;
    assert(probe(0, memory) == restore_failed && !(pci.flags & 7) && pci.sizing[0]);
    assert(resource.base == 0xffe0 && resource.size == 32 && resource.index == 4);
    pci = {};
    pci.bars[0] = base;
    pci.masks[0] = 0xfffe0000;
    pci.refuse_enable = true;
    assert(probe(0, memory) == restore_failed && !(pci.flags & 7) && !pci.sizing[0]);
    std::puts("PCI_BAR_PASS mem32 mem64 ports aperture_end malformed_masks restore_readback");

    auto measure = [&] {
        return PciBarProbe::probe(pci, 0, memory, limit, resource,
                                  PciBarProbe::Assignment::unassigned);
    };
    pci = {};
    pci.bars[0] = 4;
    pci.masks[0] = 0xfffff004;
    pci.masks[1] = UINT32_MAX;
    assert(probe(0, memory) == invalid && !pci.bar_writes);
    assert(measure() == valid && resource.base == 0 && resource.size == 4096);
    assert(pci.bars[0] == 4 && !pci.bars[1] && !pci.sizing[0] && !pci.sizing[1] &&
           pci.flags == command && pci.bar_writes == 4);
    pci.bars[1] = 1;
    assert(measure() == invalid && pci.bar_writes == 4);
    pci = {};
    assert(measure() == invalid && pci.flags == command);
    pci.masks[0] = UINT32_MAX;
    assert(measure() == invalid && pci.flags == command);
    pci.masks[0] = 0xfffff000;
    pci.refuse_restore = true;
    assert(measure() == restore_failed && !(pci.flags & 7));
    std::puts("PCI_UNASSIGNED_BAR_PASS size absence readback restore");
}

void test_temporary_memory_bar() {
    using namespace ax;
    using enum PciBarStatus;
    constexpr uint64_t address = 0x200001000, limit = 1ull << 36;
    ConfigModel pci;
    pci.flags = 0x400;
    pci.bars[0] = 4;
    unsigned accesses = 0;
    auto check = [&](bool accepts) {
        return PciBarProbe::test_unassigned_memory(pci, address, 4096, limit, [&](uint64_t base) {
            assert(base == address && pci.flags == 0x402);
            assert(pci.bars[0] == 0x1004 && pci.bars[1] == 2);
            ++accesses;
            return accepts;
        });
    };
    assert(check(true) == valid && accesses == 1);
    assert(pci.flags == 0x400 && pci.bars[0] == 4 && !pci.bars[1]);
    assert(check(false) == invalid && accesses == 2);
    assert(pci.flags == 0x400 && pci.bars[0] == 4 && !pci.bars[1]);
    pci.refuse_enable = true;
    assert(check(true) == invalid && accesses == 2);
    assert(pci.flags == 0x400 && pci.bars[0] == 4 && !pci.bars[1]);
    pci.refuse_enable = false;
    pci.refuse_restore = true; // Refuse the candidate write.
    assert(check(true) == invalid && accesses == 2);
    pci.refuse_restore = false;
    assert(PciBarProbe::test_unassigned_memory(pci, address, 4096, limit, [&](uint64_t) {
               pci.refuse_restore = true;
               return true;
           }) == restore_failed);
    assert(pci.flags == 0x400 && pci.bars[0] == 0x1004 && pci.bars[1] == 2);

    pci = {};
    pci.flags = 0x400;
    pci.bars[0] = 4;
    assert(PciBarProbe::test_unassigned_memory(pci, address, 4096, limit, [&](uint64_t) {
               pci.refuse_quiet = true;
               return true;
           }) == restore_failed);
    assert(pci.flags == 0x402 && pci.bar_writes == 2 && pci.bars[0] == 0x1004 && pci.bars[1] == 2);

    pci = {};
    pci.flags = 0x400;
    assert(check(true) == invalid && !pci.bar_writes); // A 32-bit BAR cannot hold this address.
    constexpr uint64_t address32 = 0xf0001000;
    assert(PciBarProbe::test_unassigned_memory(pci, address32, 4096, limit, [&](uint64_t base) {
               return base == address32 && pci.flags == 0x402 && pci.bars[0] == address32;
           }) == valid);
    assert(pci.flags == 0x400 && !pci.bars[0] && pci.bar_writes == 2);
    pci.flags |= 4;
    assert(check(true) == invalid && pci.bar_writes == 2);
    pci = {};
    pci.flags = 0x400;
    pci.bars[0] = 4;
    assert(PciBarProbe::test_unassigned_memory(
               pci, address, 4096, limit, [](uint64_t) { return false; }, true) == invalid);
    assert(pci.flags == 0x400 && pci.bars[0] == 4 && !pci.bars[1]);
    assert(PciBarProbe::test_unassigned_memory(
               pci, address, 4096, limit, [](uint64_t) { return true; }, true) == valid);
    assert(pci.flags == 0x402 && pci.bars[0] == 0x1004 && pci.bars[1] == 2);
    std::puts("PCI_TEMPORARY_BAR_PASS width32 width64 command_guard reject restore_failure");
}

void test_firmware_gap(const ax::PciFunction& pci) {
    using namespace ax;
    constexpr uint64_t high = 0x4000000000, low = 0xd0000000;
    const BootMemory blocked[]{{high, 0x1000, BootMemoryKind::reserved},
                               {high + 0x3100, 0x1000, BootMemoryKind::usable}};
    boot_info.memory_context = blocked;
    boot_info.memory_count = 2;
    boot_info.memory_at = [](const void* context, size_t i) {
        return static_cast<const BootMemory*>(context)[i];
    };
    Acpi::MotherboardResources board{{{high + 0xff0, 0x2100}, {low, 0x2000}}, 2, false};
    Acpi::PciRootWindows roots{
        {{high, 0x50000, 7, 0, false}, {high, 0x10000, 0, 0, false}, {low, 0x10000, 0, 0, false}},
        3};
    PciMemoryInventory occupied{};
    occupied.add(high + 0x5000, 0x2000);
    occupied.add(low + 0x2000, 0x1000);
    auto preview = [&](uint64_t size, uint64_t& address) {
        return pci_preview_memory_bar(pci, size, roots, board, occupied, address);
    };
    uint64_t address = 0;
    pci.write32(0x10, 4); // Unassigned 64-bit memory BAR.
    assert(preview(0x1000, address) && address == high + 0x7000);
    assert(pci.read32(0x10) == 4);
    roots.entries[1].prefetchable = true;
    assert(preview(0x1000, address) && address == low + 0x3000);
    roots.entries[1].prefetchable = false;
    pci.write32(0x10, 0);
    assert(preview(0x1000, address) && address == low + 0x3000);
    assert(!preview(0x900, address));
    assert(!preview(0x10000, address));
    board.incomplete = true;
    assert(!preview(0x1000, address) && address == low + 0x3000);
    board.incomplete = false;
    occupied.incomplete = true;
    assert(!preview(0x1000, address) && address == low + 0x3000);
    boot_info = {};
    std::puts(
        "PCI_FIRMWARE_GAP_PASS alignment boot_map motherboard occupancy width prefetch incomplete");
}

void test_memory_inventory(const ax::PciFunction& pci) {
    using namespace ax;
    for (unsigned offset = 0; offset < 4096; offset += 4)
        pci.write32(offset, 0);
    pci.write32(0x10, 0xd0020008);
    pci.write32(0x14, 0x00123004);
    pci.write32(0x18, 7);
    pci.write32(0x1c, 0xc001);
    pci.write32(0x30, 0xcabc0801);
    PciMemoryInventory inventory{};
    pci_record_memory(pci, inventory);
    const auto& ranges = inventory.ranges;
    assert(inventory.count == 3 && !inventory.incomplete);
    assert(ranges[0].base == 0xd0020000 && ranges[0].size == 0x20000);
    assert(ranges[1].base == 0x700123000 && ranges[1].size == 0x1000);
    assert(ranges[2].base == 0xcabc0800 && ranges[2].size == 0x800);
    assert(pci.read32(0x10) == 0xd0020008 && pci.read32(0x18) == 7);

    pci.write32(0x100, 0x00010010); // SR-IOV extended capability.
    pci.write16(0x108, 1);
    inventory.count = 0;
    pci_record_memory(pci, inventory);
    assert(inventory.count == 3 && inventory.incomplete);
    pci.write32(0x100, 0x10010002); // A self-referential extended capability.
    inventory.incomplete = false;
    pci_record_memory(pci, inventory);
    assert(inventory.incomplete);

    // The chain may link back to a lower offset without forming a loop.
    pci.write32(0x100, 0x25810001);
    pci.write32(0x258, 0x12810002);
    pci.write32(0x128, 0x00010002);
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.count == 3 && !inventory.incomplete);
    pci.write32(0x128, 0x25810002); // A loop across two capabilities.
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.incomplete);
    pci.write32(0x128, 0); // A link to an empty header.
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.incomplete);

    // A legacy function may repeat its identity beyond conventional config.
    pci.write32(0, 0x6a38086);
    for (uint16_t offset = 0x100; offset < 0x1000; offset += 0x100)
        pci.write32(offset, pci.read32(0));
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.count == 3 && !inventory.incomplete);
    pci.write32(0xf00, 0); // One matching word does not establish aliasing.
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.incomplete);
    pci.write32(0x100, 0);

    pci.write32(0x0c, 1u << 16); // Type 1 header.
    pci.write32(0x10, 0);
    pci.write32(0x14, 0);
    pci.write32(0x18, 0x00010100);
    pci.write32(0x20, 0xc010c010);
    pci.write32(0x24, 0x00910081);
    pci.write32(0x28, 2);
    pci.write32(0x2c, 2);
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(inventory.count == 2 && !inventory.incomplete);
    assert(ranges[0].base == 0xc0100000 && ranges[0].size == 0x100000);
    assert(ranges[1].base == 0x200800000 && ranges[1].size == 0x200000);
    pci.write32(0x20, 0x0010fff0);
    pci.write32(0x24, 0x0000fff0);
    inventory = {};
    pci_record_memory(pci, inventory);
    assert(!inventory.count && !inventory.incomplete);
    pci.write32(0x24, 0x0000fff2);
    pci_record_memory(pci, inventory);
    assert(inventory.incomplete);
    inventory.count = sizeof(inventory.ranges) / sizeof(*inventory.ranges);
    inventory.incomplete = false;
    assert(!inventory.add(0xa0000000, 4096) && inventory.incomplete);
    std::puts("PCI_MEMORY_INVENTORY_PASS bar32 bar64 rom bridge malformed sriov capacity aliases");
}

uint32_t bridge_config[2][16];

bool read_bridge(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function, uint16_t offset,
                 uint8_t width, uint32_t& value) {
    if (segment != 0 || bus > 1 || slot != bus + 3 || function != 0)
        return false;
    assert(offset < sizeof(bridge_config[bus]) && (width == 2 || width == 4));
    value = bridge_config[bus][offset / 4] >> ((offset % 4) * 8);
    if (width == 2)
        value &= 0xffff;
    return true;
}

void test_bridge_windows() {
    using namespace ax;
    using enum PciBarSpace;
    Acpi::PciBridges topology{
        {{0, 0, 1, 3, 3, 0, false, false}, {0, 1, 2, 2, 4, 0, false, false}}, 2, false};
    for (unsigned bus = 0; bus < 2; ++bus) {
        const auto& bridge = topology.entries[bus];
        auto& config = bridge_config[bus];
        config[0x04 / 4] = 3;
        config[0x18 / 4] =
            bus | unsigned(bridge.secondary) << 8 | unsigned(bridge.subordinate) << 16;
        config[0x1c / 4] = 0x2121; // 0x2000 to 0x2fff, 32-bit I/O window.
        config[0x20 / 4] = 0x10001000;
        config[0x24 / 4] = 0x00110001; // 0x200000000 to 0x2001fffff.
        config[0x28 / 4] = config[0x2c / 4] = 2;
    }
    const auto forwards = [&](PciBarSpace space, const PciBar& bar, bool prefetchable = false) {
        return PciBridgeWindows::forwards(topology, 0, 2, space, prefetchable, bar, read_bridge);
    };
    const PciBar mmio{base, 0x100000, 0}, mmio64{2ull << 32, 0x200000, 0};
    const PciBar io{0x20e0, 32, 0};
    assert(forwards(memory, mmio) && forwards(memory, mmio, true));
    assert(!forwards(memory, {base, 0x100001, 0}));
    assert(forwards(memory, mmio64, true) && !forwards(memory, mmio64));
    assert(!forwards(memory, {2ull << 32, 0x200001, 0}, true));
    assert(forwards(ports, io) && !forwards(ports, {0x2ff0, 32, 0}));
    bridge_config[1][0x1c / 4] = 0x2020; // The same aperture with a 16-bit type.
    assert(forwards(ports, io));
    bridge_config[1][0x1c / 4] = 0x2120;
    assert(!forwards(ports, io));
    bridge_config[1][0x1c / 4] = 0x2121;
    bridge_config[1][0x30 / 4] = 0x00010001;
    assert(!forwards(ports, io));
    bridge_config[1][0x30 / 4] = 0;
    bridge_config[0][0x3c / 4] = 4u << 16;
    assert(forwards(ports, io) && !forwards(ports, {0x20e0, 64, 0}));
    assert(!forwards(ports, {0x2100, 16, 0}));
    bridge_config[0][0x3c / 4] = 0x40u << 16;
    assert(!forwards(memory, mmio));
    bridge_config[0][0x3c / 4] = 0;
    bridge_config[0][0x20 / 4] = 0;
    assert(!forwards(memory, mmio) && forwards(memory, mmio64, true));
    bridge_config[0][0x20 / 4] = 0x10001000;
    bridge_config[0][0x04 / 4] = 1;
    assert(!forwards(memory, mmio) && forwards(ports, io));
    bridge_config[0][0x04 / 4] = 3;
    bridge_config[0][0x2c / 4] = 1;
    assert(!forwards(memory, mmio64, true));
    bridge_config[0][0x2c / 4] = 2;
    bridge_config[0][0x18 / 4] ^= 1u << 16;
    assert(!forwards(memory, mmio)); // The live bridge changed since enumeration.
    bridge_config[0][0x18 / 4] ^= 1u << 16;
    topology.entries[1].invalid_primary = true;
    assert(!forwards(memory, mmio));
    topology.entries[1].invalid_primary = false;
    assert(!PciBridgeWindows::forwards(topology, 0, 3, memory, false, mmio, read_bridge));
    assert(PciBridgeWindows::forwards(topology, 1, 3, memory, false, mmio, read_bridge));
    topology.entries[2] = {0, 0, 2, 4, 5, 0, false, false};
    ++topology.count;
    assert(!forwards(memory, mmio));
    --topology.count;
    topology.entries[1].subordinate = 4;
    bridge_config[1][0x18 / 4] = 0x040201;
    assert(!forwards(memory, mmio)); // The child range extends past its parent.
    topology.overflow = true;
    assert(!forwards(memory, mmio));
    assert(PciBridgeWindows::forwards(topology, 0, 0, memory, false, mmio, read_bridge));
    std::puts("PCI_BRIDGE_WINDOWS_PASS nested mem32 mem64 ports isa commands topology");
}
} // namespace

namespace ax {
BootInfo boot_info{};

void log(const char*, ...) {
}

bool clock_delay_us(unsigned microseconds) {
    if (!clock_ready || microseconds > 1000)
        return false;
    delay_us += microseconds;
    return true;
}

void* map_mmio(uint64_t address, size_t bytes) {
    assert(address == base && bytes == sizeof(table));
    ++mappings;
    return mapping_error ? nullptr : table;
}

bool interrupt_register_message(Irq::Handler call, void*, Irq::Message& message) {
    assert(call == handler);
    ++registrations;
    if (!route_available)
        return false;
    message = {0xfee00000, 0x40};
    return true;
}

void interrupt_retire_message(uint8_t vector) {
    assert(vector == 0x40);
    ++retirements;
}
} // namespace ax

int main() {
    auto page = static_cast<uint8_t*>(
        mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    assert(page != MAP_FAILED);
    ax::PciFunction pci{0, 1, 0, 0, page};
    test_power_state(pci);
    test_msi(pci);
    test_msix(pci);
    test_apertures();
    test_temporary_memory_bar();
    test_firmware_gap(pci);
    test_memory_inventory(pci);
    test_bridge_windows();
    assert(munmap(page, 4096) == 0);
}
