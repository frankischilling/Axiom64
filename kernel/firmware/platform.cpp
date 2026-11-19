// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 * @brief Boot-time ACPI mapping and x86 firmware diagnostics.
 */
#include "boot/boot.hpp"
#include "firmware/acpi.hpp"

namespace ax {
const uint8_t* firmware_read(uint64_t address, size_t length, void*) {
    auto map = memmap_request.response;
    if (!map || !length || length > Acpi::max_table_bytes || address > UINT64_MAX - direct_map ||
        length - 1 > UINT64_MAX - direct_map - address)
        return nullptr;
    for (size_t i = 0; i < map->entry_count; i++) {
        auto entry = map->entries[i];
        if (address < entry->base || address - entry->base > entry->length ||
            length > entry->length - (address - entry->base))
            continue;
        // Base revision 3 does not directly map reserved/ACPI regions.
        if (entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE)
            return static_cast<const uint8_t*>(physical(address));
        if (entry->type == LIMINE_MEMMAP_RESERVED || entry->type == LIMINE_MEMMAP_ACPI_NVS ||
            entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE ||
            entry->type == LIMINE_MEMMAP_RESERVED_MAPPED)
            return static_cast<const uint8_t*>(map_mmio(address, length));
    }
    return nullptr;
}

void firmware_discover(uint64_t rsdp) {
    if (!rsdp) {
        log("ACPI: no root pointer supplied by firmware\n");
        return;
    }
    Acpi::InterruptTopology topology;
    if (Acpi::find_interrupt_topology(rsdp, firmware_read, nullptr, topology)) {
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
}
} // namespace ax
