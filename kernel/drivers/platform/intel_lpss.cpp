// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/intel_lpss.cpp
 * @brief   Probes Intel LPSS I²C controllers in D0.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Reports the memory aperture and controller identity without writing I²C registers.
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
#include "drivers/platform/intel_lpss.hpp"
#include "boot/boot.hpp"
#include "core/base.hpp"
#include "drivers/platform/pci.hpp"
#include "firmware/acpi.hpp"
#include "firmware/aml.hpp"

namespace ax {
namespace {
constexpr uint16_t memory_decode = 2, intx_disabled = 1 << 10;
constexpr unsigned component_type = 0xfc, lpss_capabilities = 0x2fc;
constexpr unsigned register_bytes = lpss_capabilities + sizeof(uint32_t);
constexpr uint32_t designware_i2c = 0x44570140;

struct ProbeResources {
    Acpi::PciRootWindows windows;
    Acpi::MotherboardResources board;
    PciMemoryInventory* inventory;
    unsigned controllers;
    bool test_bar;
};

void reserve_platform_memory(PciMemoryInventory& inventory,
                             const Acpi::InterruptTopology* topology) {
    if (!topology) {
        inventory.incomplete = true;
        return;
    }
    inventory.add(topology->local_apic, page_size);
    for (unsigned i = 0; i < topology->io_apic_count; ++i)
        inventory.add(topology->io_apics[i].address, page_size);
    uint32_t leaf = 1, b, c, features;
    asm volatile("cpuid" : "+a"(leaf), "=b"(b), "=c"(c), "=d"(features));
    if ((features & (1u << 9)) && (features & (1u << 5))) {
        constexpr uint32_t apic_base_msr = 0x1b;
        constexpr uint64_t apic_base_mask = 0x000ffffffffff000ull;
        const uint64_t apic = rdmsr(apic_base_msr) & apic_base_mask;
        if (apic && apic != topology->local_apic)
            inventory.add(apic, page_size);
    }
    Acpi::Hpet hpet;
    if (Acpi::find_hpet(boot_info.rsdp, firmware_read, nullptr, hpet)) {
        const uint64_t start = hpet.address & ~(page_size - 1);
        const uint64_t end = (hpet.address + 1024 + page_size - 1) & ~(page_size - 1);
        inventory.add(start, end - start);
    }
}

bool set_command(const PciFunction& pci, uint16_t command) {
    if (pci.read16(4) != command)
        pci.write16(4, command);
    return pci.read16(4) == command;
}

uint32_t report_identity(const volatile uint32_t* registers, uint64_t base, uint64_t size) {
    const uint32_t capabilities = registers[lpss_capabilities / 4];
    const uint32_t component = registers[component_type / 4];
    log("LPSS I2C: BAR0 base=%x bytes=%x caps=%x component=%x\n", base, size,
        uint64_t(capabilities), uint64_t(component));
    return component;
}

bool test_unassigned_bar(const PciFunction& pci, uint64_t size, const ProbeResources& resources) {
    log("LPSS I2C: BAR0 unassigned bytes=%x\n", size);
    uint64_t gap;
    if (resources.inventory)
        pci_record_memory(pci, *resources.inventory); // D0 can restore other BARs on this function.
    if (!resources.inventory ||
        !pci_preview_memory_bar(pci, size, resources.windows, resources.board, *resources.inventory,
                                gap)) {
        log("LPSS I2C: BAR0 no candidate\n");
        return true;
    }
    log("LPSS I2C: BAR0 candidate base=%x bytes=%x\n", gap, size);
    if (!resources.test_bar || size < register_bytes)
        return true;
    const auto result = PciBarProbe::test_unassigned_memory(
        pci, gap, size, physical_address_limit(), [&](uint64_t address) {
            auto* registers = static_cast<volatile uint32_t*>(map_mmio(address, register_bytes));
            return registers && report_identity(registers, address, size) == designware_i2c;
        });
    log("LPSS I2C: BAR0 temporary test accepted=%u address-restored=%u\n",
        uint64_t(result == PciBarStatus::valid), uint64_t(result != PciBarStatus::restore_failed));
    if (result == PciBarStatus::restore_failed) {
        resources.inventory->incomplete = true;
        return false;
    }
    return true;
}

bool probe_registers(const PciFunction& pci, uint16_t quiet_command,
                     const ProbeResources& resources) {
    PciBar bar;
    uint64_t address;
    const auto result = pci.probe_bar(0, PciBarSpace::memory, bar);
    if (result != PciBarStatus::valid || !bar.range(0, register_bytes, address)) {
        if (result == PciBarStatus::invalid) {
            uint64_t size;
            const auto measured = pci.measure_unassigned_memory_bar(0, size);
            if (measured == PciBarStatus::valid)
                return test_unassigned_bar(pci, size, resources);
            if (measured == PciBarStatus::restore_failed)
                return false;
        }
        log("LPSS I2C: BAR0 rejected status=%u size=%x\n", uint64_t(result), bar.size);
        return result != PciBarStatus::restore_failed;
    }
    auto registers = static_cast<volatile uint32_t*>(map_mmio(address, register_bytes));
    if (!registers || !set_command(pci, quiet_command | memory_decode)) {
        log("LPSS I2C: cannot enable memory aperture\n");
        return true;
    }
    report_identity(registers, bar.base, bar.size);
    return true;
}

void probe(const PciFunction& pci, void* context) {
    const uint32_t id = pci.read32(0);
    const auto device = uint16_t(id >> 16);
    if (uint16_t(id) != 0x8086 || device < 0x06e8 || device > 0x06eb ||
        (pci.read32(8) >> 16) != 0x0c80 || (pci.read8(0x0e) & 0x7f))
        return;
    auto& resources = *static_cast<ProbeResources*>(context);
    ++resources.controllers;

    const auto initial = pci.power_state();
    const uint16_t command = pci.read16(4);
    const uint16_t quiet = (command & ~7u) | intx_disabled;
    log("LPSS I2C: segment=%u bus=%x device=%x function=%u id=%x initial_power=%u command=%x "
        "BAR0=%x:%x\n",
        uint64_t(pci.segment), uint64_t(pci.bus), uint64_t(pci.slot), uint64_t(pci.function),
        uint64_t(device), uint64_t(initial), uint64_t(command), uint64_t(pci.read32(0x14)),
        uint64_t(pci.read32(0x10)));
    if (initial == PciPowerState::unavailable || command == UINT16_MAX)
        return;
    if (!set_command(pci, quiet)) {
        set_command(pci, command);
        log("LPSS I2C: cannot quiesce the PCI function\n");
        return;
    }

    const bool awake = pci.set_power_state(PciPowerState::d0);
    log("LPSS I2C: wake=%u power=%u BAR0=%x:%x\n", uint64_t(awake), uint64_t(pci.power_state()),
        uint64_t(pci.read32(0x14)), uint64_t(pci.read32(0x10)));
    const bool bar_intact =
        !awake || (set_command(pci, quiet) && probe_registers(pci, quiet, resources));

    // Leave bus mastering off unless the original power and command can be restored.
    const bool settled = awake || pci.power_state() == initial;
    const bool restored = bar_intact && settled && set_command(pci, quiet) &&
                          pci.set_power_state(initial) && set_command(pci, command);
    log("LPSS I2C: restored=%u power=%u command=%x\n", uint64_t(restored),
        uint64_t(pci.power_state()), uint64_t(pci.read16(4)));
}
} // namespace

void intel_lpss_i2c_probe(const Acpi::DefinitionBlocks& blocks,
                          const Acpi::InterruptTopology* topology, bool test_bar) {
    ProbeResources resources{};
    resources.test_bar = test_bar;
    const auto providers = pci_firmware_read_regions();
    if (Acpi::decode_pci_root_windows(blocks, resources.windows, providers))
        for (unsigned i = 0; i < resources.windows.count; ++i) {
            const auto& window = resources.windows.entries[i];
            log("PCI root window: segment=%u bus=%x base=%x bytes=%x prefetch=%u\n",
                uint64_t(window.segment), uint64_t(window.bus), window.base, window.size,
                uint64_t(window.prefetchable));
        }
    else
        log("PCI root window: no usable ACPI memory aperture\n");
    Acpi::decode_motherboard_resources(blocks, resources.board, providers);
    for (unsigned i = 0; i < resources.board.count; ++i)
        log("PCI motherboard memory: base=%x bytes=%x\n", resources.board.memory[i].base,
            resources.board.memory[i].size);
    log("PCI motherboard memory: ranges=%u incomplete=%u\n", uint64_t(resources.board.count),
        uint64_t(resources.board.incomplete));
    resources.inventory = static_cast<PciMemoryInventory*>(alloc(sizeof(PciMemoryInventory)));
    if (resources.inventory) {
        pci_memory_inventory(*resources.inventory);
        const unsigned before = resources.inventory->count;
        reserve_platform_memory(*resources.inventory, topology);
        log("PCI platform memory: ranges=%u\n", uint64_t(resources.inventory->count - before));
    }
    log("PCI occupied memory: ranges=%u incomplete=%u\n",
        uint64_t(resources.inventory ? resources.inventory->count : 0),
        uint64_t(!resources.inventory || resources.inventory->incomplete));
    pci_scan(probe, &resources);
    if (resources.inventory)
        release(resources.inventory);
    log("LPSS I2C: controllers=%u\n", uint64_t(resources.controllers));
}
} // namespace ax
