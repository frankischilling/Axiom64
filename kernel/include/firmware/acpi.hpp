// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax::Acpi {
constexpr size_t max_table_bytes = 65536;
constexpr size_t max_root_entries = 256;
using Read = const uint8_t* (*)(uint64_t physical_address, size_t length, void* context);

struct Hpet {
    uint64_t address = 0;
    uint32_t id = 0;
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

// Reader must return stable, mapped bytes or nullptr. Never follows unbounded lengths.
bool find_hpet(uint64_t rsdp, Read reader, void* context, Hpet& result);
bool find_interrupt_topology(uint64_t rsdp, Read reader, void* context, InterruptTopology& result);
bool find_fixed_description(uint64_t rsdp, Read reader, void* context, FixedDescription& result);
} // namespace ax::Acpi
