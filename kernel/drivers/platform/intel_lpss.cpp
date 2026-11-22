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
#include "drivers/input/hid_touchpad.hpp"
#include "drivers/platform/designware_i2c.hpp"
#include "drivers/platform/intel_gpio.hpp"
#include "drivers/platform/pci.hpp"
#include "firmware/acpi.hpp"
#include "firmware/aml.hpp"

namespace ax {
namespace {
constexpr uint16_t memory_decode = 2, intx_disabled = 1 << 10;
constexpr unsigned component_type = 0xfc, lpss_capabilities = 0x2fc;
constexpr unsigned register_bytes = lpss_capabilities + sizeof(uint32_t);
constexpr uint32_t designware_i2c = 0x44570140;
constexpr unsigned lpss_reset = 0x204, function_reset_release = 3;
constexpr uint32_t comet_lake_i2c_clock = 216000000;

struct ProbeResources {
    Acpi::PciRootWindows windows;
    Acpi::MotherboardResources board;
    Acpi::I2cHidDevices hid;
    PciMemoryInventory* inventory;
    unsigned controllers;
    LpssProbe mode;
};

struct Registers {
    volatile uint32_t* mmio;

    uint32_t read(unsigned offset) const {
        return mmio[offset / 4];
    }

    void write(unsigned offset, uint32_t value) const {
        mmio[offset / 4] = value;
    }
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

bool probe_hid_report(Registers& io, const Acpi::I2cHidDevice& device,
                      const DesignWareI2c::HidDescriptor& descriptor) {
    using namespace DesignWareI2c;

    struct Storage {
        HidTouchpad::Layouts layouts;
        uint8_t bytes[max_report_descriptor_bytes];
    };

    if (!descriptor.report_bytes || descriptor.report_bytes > max_report_descriptor_bytes) {
        log("LPSS I2C: unsupported HID report descriptor length=%u\n",
            uint64_t(descriptor.report_bytes));
        return true;
    }
    auto* storage = static_cast<Storage*>(alloc(sizeof(Storage)));
    if (!storage)
        return true;
    uint32_t abort = 0;
    const auto result =
        read_register(io, comet_lake_i2c_clock, device.max_hz, device.address,
                      descriptor.report_register, storage->bytes, descriptor.report_bytes, abort);
    log("LPSS I2C: HID report register=%x bytes=%u result=%u abort=%x\n",
        uint64_t(descriptor.report_register), uint64_t(descriptor.report_bytes), uint64_t(result),
        uint64_t(abort));
    if (result == Result::ok) {
        constexpr char digits[] = "0123456789abcdef";
        constexpr unsigned bytes_per_line = 32;
        for (unsigned offset = 0; offset < descriptor.report_bytes; offset += bytes_per_line) {
            char hex[2 * bytes_per_line + 1]{};
            const unsigned count = min(bytes_per_line, unsigned(descriptor.report_bytes) - offset);
            for (unsigned i = 0; i < count; ++i) {
                const unsigned byte = storage->bytes[offset + i];
                hex[2 * i] = digits[byte >> 4];
                hex[2 * i + 1] = digits[byte & 15];
            }
            log("LPSS I2C: HID report data offset=%x %s\n", uint64_t(offset), hex);
        }
        if (HidTouchpad::parse(storage->bytes, descriptor.report_bytes, descriptor.input_bytes,
                               storage->layouts)) {
            for (unsigned i = 0; i < storage->layouts.count; ++i) {
                const auto& report = storage->layouts.reports[i];
                log("LPSS I2C: touchpad report id=%u payload-bits=%u finger-slots=%u\n",
                    uint64_t(report.id), uint64_t(report.bits), uint64_t(report.finger_count));
            }
        } else {
            log("LPSS I2C: no supported touchpad input layout\n");
        }
    }
    release(storage);
    return result != Result::restore_failed;
}

bool read_hid_descriptors(const PciFunction& pci, const ProbeResources& resources,
                          volatile uint32_t* mmio, uint64_t base, uint64_t size, bool& identified) {
    Registers io{mmio};
    bool found = false, clean = true;
    for (unsigned i = 0; i < resources.hid.count; ++i) {
        const auto& device = resources.hid.devices[i];
        const auto& location = device.pci_controller;
        if (!location.resolved || location.segment != pci.segment || location.bus != pci.bus ||
            location.slot != pci.slot || location.function != pci.function ||
            !device.has_descriptor_register || device.ten_bit || device.source_index)
            continue;
        found = true;
        const uint32_t reset = io.read(lpss_reset);
        if (reset == UINT32_MAX)
            break;
        if ((reset & function_reset_release) != function_reset_release)
            io.write(lpss_reset, reset | function_reset_release);
        const bool released =
            (io.read(lpss_reset) & function_reset_release) == function_reset_release;
        identified = released && report_identity(mmio, base, size) == designware_i2c;
        if (identified) {
            DesignWareI2c::HidDescriptor descriptor{};
            uint32_t abort = 0;
            const auto result =
                DesignWareI2c::read_hid(io, comet_lake_i2c_clock, device.max_hz, device.address,
                                        device.descriptor_register, descriptor, abort);
            clean = result != DesignWareI2c::Result::restore_failed;
            log("LPSS I2C: HID address=%x descriptor=%x result=%u abort=%x\n",
                uint64_t(device.address), uint64_t(device.descriptor_register), uint64_t(result),
                uint64_t(abort));
            if (result == DesignWareI2c::Result::ok) {
                log("LPSS I2C: HID vendor=%x product=%x revision=%x report-bytes=%u "
                    "input-bytes=%u\n",
                    uint64_t(descriptor.vendor), uint64_t(descriptor.product),
                    uint64_t(descriptor.revision), uint64_t(descriptor.report_bytes),
                    uint64_t(descriptor.input_bytes));
                clean = probe_hid_report(io, device, descriptor);
            }
        }
        if (io.read(lpss_reset) != reset)
            io.write(lpss_reset, reset);
        if (!clean || io.read(lpss_reset) != reset)
            return false;
    }
    if (!found)
        log("LPSS I2C: no HID descriptor route for this PCI function\n");
    return true;
}

bool inspect_registers(const PciFunction& pci, const ProbeResources& resources,
                       volatile uint32_t* registers, uint64_t base, uint64_t size,
                       bool& identified) {
    if (resources.mode == LpssProbe::hid)
        return read_hid_descriptors(pci, resources, registers, base, size, identified);
    identified = report_identity(registers, base, size) == designware_i2c;
    return true;
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
    if (resources.mode == LpssProbe::inspect || size < register_bytes)
        return true;
    bool clean = true;
    const auto result = PciBarProbe::test_unassigned_memory(
        pci, gap, size, physical_address_limit(), [&](uint64_t address) {
            auto* registers = static_cast<volatile uint32_t*>(map_mmio(address, register_bytes));
            if (!registers)
                return false;
            bool identified = false;
            clean = inspect_registers(pci, resources, registers, address, size, identified);
            return clean && identified;
        });
    log("LPSS I2C: BAR0 temporary test accepted=%u address-restored=%u\n",
        uint64_t(result == PciBarStatus::valid), uint64_t(result != PciBarStatus::restore_failed));
    if (!clean || result == PciBarStatus::restore_failed) {
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
    bool identified = false;
    return inspect_registers(pci, resources, registers, bar.base, bar.size, identified);
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
                          const Acpi::InterruptTopology* topology, LpssProbe mode) {
    ProbeResources resources{};
    resources.mode = mode;
    const auto providers = pci_firmware_read_regions();
    Acpi::IntelGpioResources gpio{};
    if (mode != LpssProbe::inspect)
        Acpi::decode_intel_gpio_resources(blocks, gpio, providers);
    if (mode == LpssProbe::hid) {
        Acpi::decode_i2c_hid_devices(blocks, resources.hid, providers);
        if (!resources.hid.count) {
            auto replay = providers;
            IntelGpioPads pads{};
            if (pads.probe(gpio)) {
                replay.registers = IntelGpioPads::read;
                replay.register_context = &pads;
                replay.osi = intel_gpio_firmware_interface;
                for (unsigned i = 0; i < 4 && gpio.community_base[i]; ++i)
                    log("LPSS I2C: GPIO community=%u base=%x\n", uint64_t(i),
                        gpio.community_base[i]);
            }
            const bool complete = Acpi::decode_i2c_hid_devices(
                blocks, resources.hid, replay, Acpi::HidDiscovery::replay_initialization);
            log("LPSS I2C: HID initialization rejected=%u complete=%u\n",
                uint64_t(resources.hid.initialization_failures), uint64_t(complete));
        }
        log("LPSS I2C: HID candidates=%u\n", uint64_t(resources.hid.count));
        for (unsigned i = 0; i < resources.hid.count; ++i) {
            const auto& device = resources.hid.devices[i];
            log("LPSS I2C: HID route id=%s controller=%s address=%x speed=%u descriptor=%x "
                "gsi=%u resolved=%u\n",
                device.hardware_id, device.controller, uint64_t(device.address),
                uint64_t(device.max_hz), uint64_t(device.descriptor_register),
                uint64_t(device.interrupt.source == Acpi::I2cHidInterrupt::Source::gsi
                             ? device.interrupt.line
                             : 0),
                uint64_t(device.pci_controller.resolved && device.has_descriptor_register));
        }
    }
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
        for (auto base : gpio.community_base)
            if (base)
                resources.inventory->add(base, 0x10000);
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
