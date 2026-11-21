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
#include "drivers/platform/pci_bridge.hpp"
#include "firmware/acpi.hpp"
#include "firmware/aml.hpp"

namespace ax {
namespace {
constexpr uint16_t msix_enable = 1u << 15, msix_function_mask = 1u << 14;
constexpr uint32_t msix_entry_mask = 1;
constexpr uint16_t msi_enable = 1, msi_message_count = 7u << 4;
constexpr uint16_t msi_wide_address = 1u << 7, msi_vector_masking = 1u << 8;
constexpr uint16_t intx_disabled = 1u << 10;

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
Acpi::PciPinRoutes pin_routes;
Acpi::PciBridges bridges;
bool bridges_discovered;
uint32_t sci_gsi;

bool ecam_allowed(const Acpi::EcamRegion& region, uint64_t limit) {
    uint64_t start = region.bus_address(region.first_bus);
    uint64_t end = region.bus_address(region.last_bus + 1);
    if (end > limit)
        return false;
    for (size_t i = 0; i < boot_info.memory_count; ++i) {
        const auto entry = boot_info.memory_at(boot_info.memory_context, i);
        if (entry.kind == BootMemoryKind::reserved ||
            entry.kind == BootMemoryKind::mapped_reserved || !entry.length || entry.base >= end)
            continue;
        if (entry.base >= start || entry.length > start - entry.base)
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
    uint64_t limit = physical_address_limit();
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

void PciFunction::write32(uint16_t offset, uint32_t value) const {
    if (configuration && offset < 4096) {
        *reinterpret_cast<volatile uint32_t*>(configuration + (offset & ~3u)) = value;
        return;
    }
    if (segment || offset >= 256)
        return;
    out32(0xcf8, selector(*this, offset));
    out32(0xcfc, value);
}

uint8_t PciFunction::find_capability(uint8_t id, unsigned* boundary) const {
    if (!(read16(6) & 16) || (read8(0x0e) & 0x7f) > 1)
        return 0;
    uint64_t visited = 0;
    uint8_t offset = read8(0x34) & 0xfc;
    uint8_t found = 0;
    while (offset) {
        if (offset < 0x40 || (visited & (1ull << (offset / 4))))
            return 0;
        visited |= 1ull << (offset / 4);
        if (read8(offset) == id) {
            if (found)
                return 0;
            found = offset;
        }
        offset = read8(offset + 1) & 0xfc;
    }
    if (found && boundary) {
        unsigned next = found + 4;
        while (next < 256 && !(visited & (1ull << (next / 4))))
            next += 4;
        *boundary = next;
    }
    return found;
}

bool PciMsi::start(const PciFunction& pci, Irq::Handler handler, void* context) {
    if (active() || !(pci.read16(4) & intx_disabled))
        return false;
    unsigned boundary;
    uint8_t offset = pci.find_capability(5, &boundary);
    if (!offset)
        return false;
    uint16_t control = pci.read16(offset + 2);
    bool wide = control & msi_wide_address;
    bool maskable = control & msi_vector_masking;
    unsigned data = offset + (wide ? 12 : 8);
    unsigned mask = data + 4;
    unsigned end = maskable ? mask + 8 : data + 2;
    if (end > boundary || (control & 0xe) > 0xa)
        return false;
    uint8_t msix = pci.find_capability(0x11);
    if (msix) {
        uint16_t other = pci.read16(msix + 2);
        if (other & msix_enable) {
            pci.write16(msix + 2, (other | msix_function_mask) & ~msix_enable);
            if (pci.read16(msix + 2) & msix_enable)
                return false;
        }
    }
    control &= ~(msi_enable | msi_message_count);
    pci.write16(offset + 2, control);
    if (pci.read16(offset + 2) & msi_enable)
        return false;
    if (maskable)
        pci.write32(mask, pci.read32(mask) | 1);

    Irq::Message message{};
    if (!interrupt_register_message(handler, context, message))
        return false;
    capability_ = offset;
    mask_ = maskable ? mask : 0;
    vector_ = message.vector;
    pci.write32(offset + 4, message.address);
    if (wide)
        pci.write32(offset + 8, 0);
    pci.write16(data, message.vector);
    if (pci.read32(offset + 4) == message.address && (!wide || pci.read32(offset + 8) == 0) &&
        pci.read16(data) == message.vector) {
        pci.write16(offset + 2, control | msi_enable);
        if ((pci.read16(offset + 2) & (msi_enable | msi_message_count)) == msi_enable) {
            if (!maskable)
                return true;
            pci.write32(mask, pci.read32(mask) & ~1u);
            if (!(pci.read32(mask) & 1))
                return true;
        }
    }
    stop(pci);
    return false;
}

void PciMsi::stop(const PciFunction& pci) {
    if (!active())
        return;
    uint16_t control = pci.read16(capability_ + 2);
    if (mask_)
        pci.write32(mask_, pci.read32(mask_) | 1);
    pci.write16(capability_ + 2, control & ~msi_enable);
    pci.read16(capability_ + 2);
    interrupt_retire_message(vector_);
    capability_ = mask_ = vector_ = 0;
}

bool PciMsix::prepare(const PciFunction& pci, uint8_t capability, const PciBar& bar,
                      Irq::Handler handler, void* context) {
    if (vector_ || capability < 0x40 || capability > 0xf4 || (capability & 3) ||
        pci.read8(capability) != 0x11)
        return false;
    uint16_t control = pci.read16(capability + 2);
    unsigned entries = (control & 0x7ff) + 1;
    uint32_t location = pci.read32(capability + 4);
    uint32_t offset = location & ~7u;
    size_t bytes = entries * 16;
    uint64_t address;
    if ((location & 7) != bar.index || !bar.range(offset, bytes, address))
        return false;

    Irq::Message message{};
    if (!interrupt_register_message(handler, context, message))
        return false;
    capability_ = capability;
    vector_ = message.vector;
    table_ = static_cast<volatile uint32_t*>(map_mmio(address, bytes));
    if (table_) {
        pci.write16(capability + 2, control | msix_enable | msix_function_mask);
        if ((pci.read16(capability + 2) & (msix_enable | msix_function_mask)) ==
            (msix_enable | msix_function_mask)) {
            for (unsigned i = 0; i < entries; ++i)
                table_[i * 4 + 3] = msix_entry_mask;
            table_[0] = message.address;
            table_[1] = 0;
            table_[2] = message.vector;
            if (table_[0] == message.address && table_[1] == 0 && table_[2] == message.vector &&
                table_[3] == msix_entry_mask)
                return true;
        }
    }
    stop(pci);
    return false;
}

bool PciMsix::unmask(const PciFunction& pci) {
    table_[3] = 0;
    if (table_[3] & msix_entry_mask)
        return false;
    uint16_t control = pci.read16(capability_ + 2);
    pci.write16(capability_ + 2, control & ~msix_function_mask);
    return (pci.read16(capability_ + 2) & (msix_enable | msix_function_mask)) == msix_enable;
}

void PciMsix::stop(const PciFunction& pci) {
    if (!vector_)
        return;
    uint16_t control = pci.read16(capability_ + 2);
    pci.write16(capability_ + 2, (control | msix_function_mask) & ~msix_enable);
    pci.read16(capability_ + 2);
    interrupt_retire_message(vector_);
    vector_ = capability_ = 0;
    table_ = nullptr;
}

bool PciIntx::start(const PciFunction& pci, Irq::LineHandler handler, void* context) {
    if (active())
        return false;
    auto* route = Acpi::find_pci_pin(pin_routes, pci.segment, pci.bus, pci.slot, pci.function,
                                     pci.read8(0x3d), &bridges);
    if (!route || !route->level || route->gsi == sci_gsi)
        return false;
    uint8_t msi = pci.find_capability(5), msix = pci.find_capability(0x11);
    if ((msi && (pci.read16(msi + 2) & msi_enable)) ||
        (msix && (pci.read16(msix + 2) & msix_enable)) ||
        !interrupt_register_line(route->gsi, route->active_low, route->shared, handler, context,
                                 subscription_))
        return false;
    pci.write16(4, pci.read16(4) & ~intx_disabled);
    if (pci.read16(4) & intx_disabled) {
        stop(pci);
        return false;
    }
    gsi_ = route->gsi;
    return true;
}

void PciIntx::stop(const PciFunction& pci) {
    if (!active())
        return;
    pci.write16(4, pci.read16(4) | intx_disabled);
    pci.read16(4);
    interrupt_retire_line(subscription_);
    gsi_ = 0;
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

static unsigned scan_pci_functions(void (*visit)(const PciFunction&)) {
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
    return count;
}

static void record_bridge(const PciFunction& pci) {
    if ((pci.read8(0x0e) & 0x7f) != 1 || pci.read16(0x0a) != 0x0604)
        return;
    uint32_t buses = pci.read32(0x18);
    uint8_t secondary = buses >> 8, subordinate = buses >> 16;
    if (!secondary)
        return;
    if (bridges.count == sizeof(bridges.entries) / sizeof(*bridges.entries)) {
        bridges.overflow = true;
        return;
    }
    unsigned boundary;
    uint8_t express = pci.find_capability(0x10, &boundary);
    bool ari = express && express + 0x2a <= int(boundary) && (pci.read16(express + 2) & 15) >= 2 &&
               (pci.read16(express + 0x28) & (1u << 5));
    bridges.entries[bridges.count++] = {pci.segment, pci.bus,  secondary,
                                        subordinate, pci.slot, pci.function,
                                        ari,         false,    uint8_t(buses) != pci.bus};
}

static void discover_bridges() {
    if (!bridges_discovered) {
        scan_pci_functions(record_bridge);
        bridges_discovered = true;
    }
}

static bool read_pci_field(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                           uint16_t offset, uint8_t width, uint32_t& result) {
    if (slot >= 32 || function >= 8 || (width != 1 && width != 2 && width != 4) ||
        (offset & (width - 1)) || unsigned(offset) + width > 4096)
        return false;
    volatile uint8_t* ecam = nullptr;
    for (unsigned i = 0; i < window_count; ++i) {
        auto& window = windows[i];
        if (window.region.segment == segment && window.region.contains(bus)) {
            ecam = map_bus(window, bus);
            break;
        }
    }
    if (!ecam && (segment || unsigned(offset) + width > 256))
        return false;
    PciFunction pci{bus, slot, function, segment,
                    ecam ? ecam + (unsigned(slot) << 15) + (unsigned(function) << 12) : nullptr};
    if (pci.read16(0) == UINT16_MAX)
        return false;
    switch (width) {
    case 1:
        result = pci.read8(offset);
        break;
    case 2:
        result = pci.read16(offset);
        break;
    case 4:
        result = pci.read32(offset);
        break;
    }
    return true;
}

PciBarStatus PciFunction::probe_bar(unsigned index, PciBarSpace space, PciBar& resource) const {
    PciBar candidate;
    const auto status =
        PciBarProbe::probe(*this, index, space, physical_address_limit(), candidate);
    if (status != PciBarStatus::valid)
        return status;
    const bool prefetchable = space == PciBarSpace::memory && (read32(0x10 + index * 4) & 8);
    if (!PciBridgeWindows::forwards(bridges, segment, bus, space, prefetchable, candidate,
                                    read_pci_field)) {
        log("PCI BAR: bridge window rejects segment=%u bus=%u slot=%u function=%u BAR=%u\n",
            uint64_t(segment), uint64_t(bus), uint64_t(slot), uint64_t(function), uint64_t(index));
        return PciBarStatus::invalid;
    }
    resource = candidate;
    return PciBarStatus::valid;
}

static bool has_piix_pirq(const PciFunction& bridge) {
    const uint32_t id = bridge.read32(0);
    return (id == 0x70008086 || id == 0x71108086) && bridge.read16(0x0a) == 0x0601;
}

static bool program_link(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                         uint16_t offset, uint8_t previous, uint8_t next) {
    const PciFunction bridge{bus, slot, function, segment, nullptr};
    if (segment || bus || slot != 1 || function || offset < 0x60 || offset > 0x63 ||
        !has_piix_pirq(bridge) || bridge.read8(offset) != previous)
        return false;
    auto write = [&](uint8_t value) {
        // PIRQ routes are individual bytes. A wider write could change another route.
        out32(0xcf8, selector(bridge, offset));
        out8(0xcfc + (offset & 3), value);
    };
    write(next);
    if (bridge.read8(offset) != next) {
        write(previous);
        if (bridge.read8(offset) != previous)
            log("PCI INTx: could not restore PIRQ register %x\n", uint64_t(offset));
        return false;
    }
    log("PCI INTx: PIRQ register %x changed %x to %x\n", uint64_t(offset), uint64_t(previous),
        uint64_t(next));
    return true;
}

void pci_configure_intx(const Acpi::DefinitionBlocks& blocks, uint32_t sci, uint32_t link_gsis) {
    sci_gsi = sci;
    discover_bridges();
    const auto allowed = has_piix_pirq({0, 1, 0, 0, nullptr}) ? link_gsis : 0;
    if (Acpi::decode_pci_pin_routes(blocks, pin_routes, &bridges, read_pci_field,
                                    {program_link, allowed}))
        log("PCI INTx: %u firmware pin routes, %u configured bridges, %u programmed links\n",
            uint64_t(pin_routes.count), uint64_t(bridges.count),
            uint64_t(pin_routes.programmed_links));
    else {
        if (pin_routes.rollback_failed)
            log("PCI INTx: interrupt link rollback failed\n");
        log("PCI INTx: no usable firmware routes\n");
    }
}

void pci_scan(void (*visit)(const PciFunction&)) {
    discover_bridges();
    log("PCI: %u functions discovered\n", uint64_t(scan_pci_functions(visit)));
}
} // namespace ax
