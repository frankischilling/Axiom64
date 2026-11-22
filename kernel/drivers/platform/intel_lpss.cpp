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
#include "core/base.hpp"
#include "drivers/platform/pci.hpp"
#include "firmware/aml.hpp"

namespace ax {
namespace {
constexpr uint16_t memory_decode = 2, intx_disabled = 1 << 10;
constexpr unsigned component_type = 0xfc, lpss_capabilities = 0x2fc;
constexpr unsigned register_bytes = lpss_capabilities + sizeof(uint32_t);
unsigned controllers;

bool set_command(const PciFunction& pci, uint16_t command) {
    if (pci.read16(4) != command)
        pci.write16(4, command);
    return pci.read16(4) == command;
}

bool probe_registers(const PciFunction& pci, uint16_t quiet_command) {
    PciBar bar;
    uint64_t address;
    const auto result = pci.probe_bar(0, PciBarSpace::memory, bar);
    if (result != PciBarStatus::valid || !bar.range(0, register_bytes, address)) {
        if (result == PciBarStatus::invalid) {
            uint64_t size;
            const auto measured = pci.measure_unassigned_memory_bar(0, size);
            if (measured == PciBarStatus::valid) {
                log("LPSS I2C: BAR0 unassigned bytes=%x\n", size);
                return true;
            }
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
    const uint32_t capabilities = registers[lpss_capabilities / 4];
    const uint32_t component = registers[component_type / 4];
    log("LPSS I2C: BAR0 base=%x bytes=%x caps=%x component=%x\n", bar.base, bar.size,
        uint64_t(capabilities), uint64_t(component));
    return true;
}

void probe(const PciFunction& pci) {
    const uint32_t id = pci.read32(0);
    const auto device = uint16_t(id >> 16);
    if (uint16_t(id) != 0x8086 || device < 0x06e8 || device > 0x06eb ||
        (pci.read32(8) >> 16) != 0x0c80 || (pci.read8(0x0e) & 0x7f))
        return;
    ++controllers;

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
    const bool bar_intact = !awake || !set_command(pci, quiet) || probe_registers(pci, quiet);

    // Leave bus mastering off unless the original power and command can be restored.
    const bool settled = awake || pci.power_state() == initial;
    const bool restored = settled && set_command(pci, quiet) && pci.set_power_state(initial) &&
                          bar_intact && set_command(pci, command);
    log("LPSS I2C: restored=%u power=%u command=%x\n", uint64_t(restored),
        uint64_t(pci.power_state()), uint64_t(pci.read16(4)));
}
} // namespace

void intel_lpss_i2c_probe(const Acpi::DefinitionBlocks& blocks) {
    Acpi::PciRootWindows windows{};
    if (Acpi::decode_pci_root_windows(blocks, windows))
        for (unsigned i = 0; i < windows.count; ++i) {
            const auto& window = windows.entries[i];
            log("PCI root window: segment=%u bus=%x base=%x bytes=%x prefetch=%u\n",
                uint64_t(window.segment), uint64_t(window.bus), window.base, window.size,
                uint64_t(window.prefetchable));
        }
    else
        log("PCI root window: no usable ACPI memory aperture\n");
    controllers = 0;
    pci_scan(probe);
    log("LPSS I2C: controllers=%u\n", uint64_t(controllers));
}
} // namespace ax
