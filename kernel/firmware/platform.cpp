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
#include "firmware/aml.hpp"
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
            entry.kind == BootMemoryKind::mapped_reserved || entry.kind == BootMemoryKind::acpi_nvs)
            return static_cast<const uint8_t*>(map_mmio(address, length));
    }
    return nullptr;
}

namespace {
volatile uint8_t* map_nvs(uint64_t address, size_t length) {
    if (!length || !boot_info.memory_at || length > UINT64_MAX - address)
        return nullptr;
    const auto end = address + length;
    bool contained = false;
    for (size_t i = 0; i < boot_info.memory_count; ++i) {
        const auto entry = boot_info.memory_at(boot_info.memory_context, i);
        if (!entry.length || entry.base >= end ||
            (entry.base < address && entry.length <= address - entry.base))
            continue;
        if (entry.kind != BootMemoryKind::acpi_nvs)
            return nullptr;
        if (entry.base <= address && end - entry.base <= entry.length)
            contained = true;
    }
    return contained ? static_cast<volatile uint8_t*>(map_mmio(address, length)) : nullptr;
}

struct FirmwareLock {
    volatile uint32_t* word;
    uint16_t pm1a, pm1b;
};

FirmwareLock find_firmware_lock() {
    Acpi::GlobalLockControl control{};
    if (!Acpi::find_global_lock_control(boot_info.rsdp, firmware_read, nullptr, control))
        return {};
    const auto* header = map_nvs(control.facs, 64);
    if (!header || header[0] != 'F' || header[1] != 'A' || header[2] != 'C' || header[3] != 'S')
        return {};
    uint32_t length = 0;
    for (unsigned i = 0; i < 4; ++i)
        length |= uint32_t(header[4 + i]) << (8 * i);
    if (length < 64 || length > 4096)
        return {};
    auto* facs = map_nvs(control.facs, length);
    if (!facs)
        return {};
    return {reinterpret_cast<volatile uint32_t*>(facs + 16), control.pm1a, control.pm1b};
}

void notify_firmware(uint16_t port) {
    if (port) {
        constexpr uint16_t sleep_enable = 1 << 13, global_lock_release = 1 << 2;
        out16(port, (in16(port) & ~sleep_enable) | global_lock_release);
    }
}
} // namespace

bool firmware_read_nvs(uint64_t address, uint8_t* bytes, size_t length, bool firmware_lock) {
    if (!bytes || length > 9)
        return false;
    const auto* source = map_nvs(address, length);
    if (!source)
        return false;
    FirmwareLock lock{};
    if (firmware_lock) {
        // This provider is only used by the boot-time diagnostics.
        static FirmwareLock platform_lock = find_firmware_lock();
        lock = platform_lock;
        if (!lock.word || !Acpi::try_acquire_global_lock(*lock.word))
            return false;
    }
    for (size_t i = 0; i < length; ++i)
        bytes[i] = source[i];
    if (lock.word && Acpi::release_global_lock(*lock.word)) {
        notify_firmware(lock.pm1a);
        notify_firmware(lock.pm1b);
    }
    return true;
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

void firmware_probe_i2c_hid(const Acpi::DefinitionBlocks& blocks) {
    Acpi::I2cHidDevices devices{};
    if (!Acpi::decode_i2c_hid_devices(blocks, devices, pci_firmware_read_regions())) {
        log("ACPI I2C HID: firmware discovery failed\n");
        return;
    }
    log("ACPI I2C HID: devices=%u\n", uint64_t(devices.count));
    for (unsigned i = 0; i < devices.count; ++i) {
        const auto& device = devices.devices[i];
        log("ACPI I2C HID: id=%s controller=%s bus=%u address=%x bits=%u speed-hz=%u\n",
            device.hardware_id, device.controller, uint64_t(device.source_index),
            uint64_t(device.address), uint64_t(device.ten_bit ? 10 : 7), uint64_t(device.max_hz));
        if (device.has_descriptor_register)
            log("ACPI I2C HID: id=%s descriptor-register=%x\n", device.hardware_id,
                uint64_t(device.descriptor_register));
    }
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
    // The PIIX router targets ISA lines. Require firmware to identify the
    // same GSI as active-high and level-triggered before changing a route.
    constexpr uint16_t active_high_level = 0x0d;
    uint32_t link_gsis = 0;
    for (unsigned irq = 0; irq < 16; ++irq) {
        const auto& route = topology.isa[irq];
        if (route.present && route.gsi == irq && route.flags == active_high_level && irq != sci &&
            interrupt_line_available(irq))
            link_gsis |= 1u << irq;
    }
    pci_configure_intx(blocks, sci, link_gsis);
}
} // namespace ax
