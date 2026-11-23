// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/firmware/acpi.hpp
 * @brief   Declares the ACPI table reader and decoded platform records.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Defines clock, interrupt, fixed-description, PCI aperture, and definition
 * block records returned by the bounded firmware parsers.
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
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax::Acpi {
constexpr size_t max_table_bytes = 65536;
constexpr size_t max_definition_bytes = 1024 * 1024;
constexpr size_t max_root_entries = 256;
using Read = const uint8_t* (*)(uint64_t physical_address, size_t length, void* context);

struct Hpet {
    uint64_t address = 0;
    uint32_t id = 0;
};

struct PmTimer {
    uint16_t port;
    uint32_t mask;
};

struct Processor {
    uint32_t apic_id;
    uint32_t uid;
    uint32_t flags;
};

struct IoApic {
    uint32_t address;
    uint32_t first_gsi;
    uint8_t id;
};

struct IsaOverride {
    uint32_t gsi;
    uint16_t flags;
    bool present;
};

struct InterruptTopology {
    uint64_t local_apic;
    bool legacy_pic;
    unsigned processor_count;
    unsigned io_apic_count;
    Processor processors[256];
    IoApic io_apics[16];
    IsaOverride isa[16];
};

struct FixedDescription {
    uint32_t flags;
    uint16_t sci;
    uint16_t boot_flags;
    uint8_t revision;
};

struct EcamRegion {
    static constexpr uint64_t bus_bytes = 1ull << 20;

    uint64_t base;
    uint16_t segment;
    uint8_t first_bus;
    uint8_t last_bus;

    uint64_t bus_address(unsigned bus) const {
        return base + bus * bus_bytes;
    }

    bool contains(unsigned bus) const {
        return bus >= first_bus && bus <= last_bus;
    }
};

struct Mcfg {
    static constexpr unsigned max_regions = 16;
    EcamRegion regions[max_regions];
    unsigned count;
};

struct DefinitionBlock {
    const uint8_t* table;
    uint64_t address;
    size_t length;
};

struct DefinitionBlocks {
    DefinitionBlock dsdt;
    DefinitionBlock ssdt[max_root_entries];
    size_t ssdt_count;
};

// Reader must return stable, mapped bytes or nullptr. Never follows unbounded lengths.
bool find_hpet(uint64_t rsdp, Read reader, void* context, Hpet& result);
bool find_pm_timer(uint64_t rsdp, Read reader, void* context, PmTimer& result);
bool find_interrupt_topology(uint64_t rsdp, Read reader, void* context, InterruptTopology& result);
bool find_fixed_description(uint64_t rsdp, Read reader, void* context, FixedDescription& result);
bool find_mcfg(uint64_t rsdp, Read reader, void* context, Mcfg& result);
// Borrows immutable table storage. SSDTs retain root-table order after the DSDT.
bool find_definition_blocks(uint64_t rsdp, Read reader, void* context, DefinitionBlocks& result);
} // namespace ax::Acpi
