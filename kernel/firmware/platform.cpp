// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/platform.cpp
 * @brief   Discovers ACPI resources during x86 boot.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Reads platform tables through the boot memory map, reports interrupt
 * topology and definition blocks, and passes PCI apertures to the driver.
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
#include "boot/boot.hpp"
#include "drivers/platform/pci.hpp"
#include "firmware/acpi.hpp"

namespace ax {
const uint8_t* firmware_read(uint64_t address, size_t length, void*) {
    if (!boot_info.memory_at || !length || length > Acpi::max_definition_bytes ||
        address > UINT64_MAX - direct_map || length - 1 > UINT64_MAX - direct_map - address)
        return nullptr;
    for (size_t i = 0; i < boot_info.memory_count; i++) {
        auto entry = boot_info.memory_at(boot_info.memory_context, i);
        if (address < entry.base || address - entry.base > entry.length ||
            length > entry.length - (address - entry.base))
            continue;
        if (entry.kind == BootMemoryKind::retained)
            return static_cast<const uint8_t*>(physical(address));
        if (entry.kind == BootMemoryKind::reserved || entry.kind == BootMemoryKind::firmware ||
            entry.kind == BootMemoryKind::mapped_reserved)
            return static_cast<const uint8_t*>(map_mmio(address, length));
    }
    return nullptr;
}

bool firmware_discover(uint64_t rsdp, Acpi::InterruptTopology& topology,
                       Acpi::DefinitionBlocks& blocks) {
    blocks = {};
    if (!rsdp) {
        log("ACPI: no root pointer supplied by firmware\n");
        return false;
    }
    bool have_topology = Acpi::find_interrupt_topology(rsdp, firmware_read, nullptr, topology);
    if (have_topology) {
        log("ACPI MADT: local-apic=%x processors=%u io-apics=%u legacy-pic=%u\n",
            topology.local_apic, uint64_t(topology.processor_count),
            uint64_t(topology.io_apic_count), uint64_t(topology.legacy_pic));
        for (unsigned index = 0; index < topology.io_apic_count; ++index) {
            const auto& io_apic = topology.io_apics[index];
            log("ACPI I/O APIC: id=%u address=%x first-gsi=%u\n", uint64_t(io_apic.id),
                uint64_t(io_apic.address), uint64_t(io_apic.first_gsi));
        }
        for (unsigned irq = 0; irq < 16; ++irq) {
            const auto& route = topology.isa[irq];
            if (route.present)
                log("ACPI ISA override: irq=%u gsi=%u flags=%x\n", uint64_t(irq),
                    uint64_t(route.gsi), uint64_t(route.flags));
        }
    } else {
        log("ACPI: MADT absent or rejected\n");
    }
    Acpi::FixedDescription fixed;
    if (Acpi::find_fixed_description(rsdp, firmware_read, nullptr, fixed))
        log("ACPI FADT: revision=%u sci=%u boot-flags=%x flags=%x\n", uint64_t(fixed.revision),
            uint64_t(fixed.sci), uint64_t(fixed.boot_flags), uint64_t(fixed.flags));
    else
        log("ACPI: FADT absent or rejected\n");
    if (Acpi::find_definition_blocks(rsdp, firmware_read, nullptr, blocks))
        log("ACPI definition blocks: DSDT=%u bytes SSDTs=%u\n", uint64_t(blocks.dsdt.length),
            uint64_t(blocks.ssdt_count));
    else
        log("ACPI: definition blocks absent or rejected\n");
    Acpi::Mcfg mcfg;
    if (Acpi::find_mcfg(rsdp, firmware_read, nullptr, mcfg))
        pci_configure_ecam(mcfg);
    else
        log("ACPI: MCFG absent or rejected\n");
    return have_topology;
}

void firmware_configure_pci_interrupts(uint64_t rsdp, const Acpi::InterruptTopology& topology,
                                       const Acpi::DefinitionBlocks& blocks) {
    if (!interrupt_apic_ready() || !blocks.dsdt.table)
        return;
    Acpi::FixedDescription fixed;
    if (!Acpi::find_fixed_description(rsdp, firmware_read, nullptr, fixed))
        return;
    uint32_t sci = fixed.sci;
    if (sci < 16 && topology.isa[sci].present)
        sci = topology.isa[sci].gsi;
    pci_configure_intx(blocks, sci);
}
} // namespace ax
