// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/pci.cpp
 * @brief   Enumerates PCI devices and accesses their configuration registers.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Uses firmware ECAM windows or legacy configuration ports to locate PCI
 * functions, read capabilities and BARs, and write control registers.
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
#include "drivers/platform/pci.hpp"
#include "boot/boot.hpp"
#include "firmware/acpi.hpp"

namespace ax {
namespace {
struct EcamBus {
    volatile uint8_t* address;
    bool attempted;
};

struct EcamWindow {
    Acpi::EcamRegion region;
    EcamBus buses[256];
};

EcamWindow windows[Acpi::Mcfg::max_regions];
unsigned window_count;

uint64_t physical_limit() {
    uint32_t a = 0x80000000, b, c, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (a < 0x80000008)
        return 1ull << 36;
    a = 0x80000008;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    return 1ull << min(a & 0xff, 52u);
}

bool ecam_allowed(const Acpi::EcamRegion& region, uint64_t limit) {
    uint64_t start = region.bus_address(region.first_bus);
    uint64_t end = region.bus_address(region.last_bus + 1);
    if (end > limit)
        return false;
    const auto map = memmap_request.response;
    for (uint64_t i = 0; i < map->entry_count; ++i) {
        const auto entry = map->entries[i];
        if (entry->type == LIMINE_MEMMAP_RESERVED || entry->type == LIMINE_MEMMAP_RESERVED_MAPPED ||
            !entry->length || entry->base >= end)
            continue;
        if (entry->base >= start || entry->length > start - entry->base)
            return false;
    }
    return true;
}

volatile uint8_t* map_bus(EcamWindow& window, unsigned bus) {
    auto& mapping = window.buses[bus];
    if (!mapping.attempted) {
        mapping.attempted = true;
        mapping.address = static_cast<volatile uint8_t*>(
            map_mmio(window.region.bus_address(bus), Acpi::EcamRegion::bus_bytes));
        if (!mapping.address)
            log("PCI ECAM: cannot map segment=%u bus=%u\n", uint64_t(window.region.segment),
                uint64_t(bus));
    }
    return mapping.address;
}

uint32_t selector(const PciFunction& p, uint16_t offset) {
    return 0x80000000u | uint32_t(p.bus) << 16 | uint32_t(p.slot) << 11 |
           uint32_t(p.function) << 8 | (offset & 0xfc);
}
} // namespace

void pci_configure_ecam(const Acpi::Mcfg& mcfg) {
    uint64_t limit = physical_limit();
    for (unsigned i = 0; i < mcfg.count; ++i) {
        const auto& region = mcfg.regions[i];
        if (!ecam_allowed(region, limit)) {
            log("PCI ECAM: rejected aperture segment=%u buses=%u-%u\n", uint64_t(region.segment),
                uint64_t(region.first_bus), uint64_t(region.last_bus));
            continue;
        }
        windows[window_count++].region = region;
        log("PCI ECAM: segment=%u buses=%u-%u base=%x\n", uint64_t(region.segment),
            uint64_t(region.first_bus), uint64_t(region.last_bus), region.base);
    }
}

uint32_t PciFunction::read32(uint16_t offset) const {
    if (configuration && offset < 4096)
        return *reinterpret_cast<volatile uint32_t*>(configuration + (offset & ~3u));
    if (segment || offset >= 256)
        return UINT32_MAX;
    out32(0xcf8, selector(*this, offset));
    return in32(0xcfc);
}

uint16_t PciFunction::read16(uint16_t offset) const {
    if (configuration && offset < 4096)
        return *reinterpret_cast<volatile uint16_t*>(configuration + (offset & ~1u));
    if (segment || offset >= 256)
        return UINT16_MAX;
    out32(0xcf8, selector(*this, offset));
    return in16(0xcfc + (offset & 2));
}

uint8_t PciFunction::read8(uint16_t offset) const {
    if (configuration && offset < 4096)
        return configuration[offset];
    return uint8_t(read32(offset) >> ((offset & 3) * 8));
}

void PciFunction::write16(uint16_t offset, uint16_t value) const {
    if (configuration && offset < 4096) {
        *reinterpret_cast<volatile uint16_t*>(configuration + (offset & ~1u)) = value;
        return;
    }
    if (segment || offset >= 256)
        return;
    out32(0xcf8, selector(*this, offset));
    out16(0xcfc + (offset & 2), value);
}

bool PciFunction::memory_bar(unsigned index, uint64_t& address) const {
    if (index >= 6 || (read8(0x0e) & 0x7f) != 0)
        return false;
    for (unsigned i = 0; i < index; i++)
        if ((read32(0x10 + i * 4) & 7) == 4) {
            if (++i == index)
                return false;
        }
    uint32_t bar = read32(0x10 + index * 4);
    if ((bar & 1) || (bar & 6) == 2 || (bar & 6) == 6)
        return false;
    address = bar & ~15u;
    if ((bar & 6) == 4) {
        if (index == 5)
            return false;
        address |= uint64_t(read32(0x14 + index * 4)) << 32;
    }
    return address != 0;
}

static unsigned scan_bus(uint16_t segment, unsigned bus, volatile uint8_t* ecam,
                         void (*visit)(const PciFunction&)) {
    if (segment && !ecam)
        return 0;
    unsigned count = 0;
    for (unsigned slot = 0; slot < 32; ++slot) {
        auto configuration = ecam ? ecam + (slot << 15) : nullptr;
        PciFunction pci{uint8_t(bus), uint8_t(slot), 0, segment, configuration};
        if (pci.read16(0) == UINT16_MAX)
            continue;
        unsigned functions = pci.read8(0x0e) & 0x80 ? 8 : 1;
        visit(pci);
        ++count;
        for (unsigned function = 1; function < functions; ++function) {
            pci.function = uint8_t(function);
            if (ecam)
                pci.configuration = configuration + (function << 12);
            if (pci.read16(0) != UINT16_MAX) {
                visit(pci);
                ++count;
            }
        }
    }
    return count;
}

void pci_scan(void (*visit)(const PciFunction&)) {
    unsigned count = 0;
    for (unsigned bus = 0; bus < 256; ++bus) {
        volatile uint8_t* ecam = nullptr;
        for (unsigned i = 0; i < window_count; ++i) {
            auto& window = windows[i];
            if (!window.region.segment && window.region.contains(bus)) {
                ecam = map_bus(window, bus);
                break;
            }
        }
        count += scan_bus(0, bus, ecam, visit);
    }
    for (unsigned i = 0; i < window_count; ++i) {
        auto& window = windows[i];
        const auto& region = window.region;
        if (region.segment)
            for (unsigned bus = region.first_bus; bus <= region.last_bus; ++bus)
                count += scan_bus(region.segment, bus, map_bus(window, bus), visit);
    }
    log("PCI: %u functions discovered\n", uint64_t(count));
}
} // namespace ax
