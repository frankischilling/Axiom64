// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/acpi.cpp
 * @brief   Validates ACPI platform tables.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Verifies checksums and bounds before decoding clock, interrupt, and PCI
 * configuration data from the firmware root tables.
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
#include "firmware/acpi.hpp"

namespace ax::Acpi {
static constexpr uint64_t physical_limit = 1ull << 52;

static uint64_t little(const uint8_t* bytes, size_t count) {
    uint64_t value = 0;
    for (size_t i = 0; i < count; i++)
        value |= uint64_t(bytes[i]) << (i * 8);
    return value;
}

static bool match(const uint8_t* bytes, const char* text, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (bytes[i] != uint8_t(text[i]))
            return false;
    return true;
}

static bool checksum(const uint8_t* bytes, size_t count) {
    uint8_t sum = 0;
    for (size_t i = 0; i < count; i++)
        sum += bytes[i];
    return !sum;
}

static const uint8_t* read(uint64_t address, size_t length, Read reader, void* context) {
    return !address || address >= physical_limit || length > physical_limit - address
               ? nullptr
               : reader(address, length, context);
}

static const uint8_t* table(uint64_t address, const char* signature, size_t minimum, Read reader,
                            void* context) {
    const uint8_t* header = read(address, 36, reader, context);
    if (!header || !match(header, signature, 4))
        return nullptr;
    size_t length = little(header + 4, 4);
    if (length < minimum || length > max_table_bytes)
        return nullptr;
    const uint8_t* complete = read(address, length, reader, context);
    return complete && little(complete + 4, 4) == length && match(complete, signature, 4) &&
                   checksum(complete, length)
               ? complete
               : nullptr;
}

struct Query {
    const char* signature;
    size_t minimum;
    bool (*accept)(const uint8_t*, void*);
    void* output;
};

static bool find_in_root(uint64_t address, bool extended, Read reader, void* context,
                         const Query& query) {
    const uint8_t* root = table(address, extended ? "XSDT" : "RSDT", 36, reader, context);
    if (!root)
        return false;
    size_t bytes = little(root + 4, 4) - 36, stride = extended ? 8 : 4;
    if (bytes % stride || bytes / stride > max_root_entries)
        return false;
    for (size_t offset = 36; offset < 36 + bytes; offset += stride) {
        const uint8_t* entry =
            table(little(root + offset, stride), query.signature, query.minimum, reader, context);
        if (entry && query.accept(entry, query.output))
            return true;
    }
    return false;
}

static bool find(uint64_t address, Read reader, void* context, const Query& query) {
    if (!reader)
        return false;
    const uint8_t* first = read(address, 20, reader, context);
    if (!first || !match(first, "RSD PTR ", 8) || !checksum(first, 20) || first[15] == 1)
        return false;
    uint64_t rsdt = little(first + 16, 4);
    if (first[15] >= 2) {
        const uint8_t* header = read(address, 36, reader, context);
        if (!header)
            return false;
        size_t length = little(header + 20, 4);
        if (length < 36 || length > 4096)
            return false;
        const uint8_t* complete = read(address, length, reader, context);
        if (!complete || !match(complete, "RSD PTR ", 8) || little(complete + 20, 4) != length ||
            !checksum(complete, 20) || !checksum(complete, length))
            return false;
        if (find_in_root(little(complete + 24, 8), true, reader, context, query))
            return true;
    }
    return find_in_root(rsdt, false, reader, context, query);
}

static bool accept_hpet(const uint8_t* hpet, void* output) {
    if (hpet[40] || (hpet[41] && hpet[41] != 64) || hpet[42] || (hpet[43] && hpet[43] != 4))
        return false;
    uint64_t mmio = little(hpet + 44, 8);
    if (!mmio || (mmio & 1023) || mmio > physical_limit - 1024)
        return false;
    *static_cast<Hpet*>(output) = {mmio, uint32_t(little(hpet + 36, 4))};
    return true;
}

bool find_hpet(uint64_t rsdp, Read reader, void* context, Hpet& result) {
    return find(rsdp, reader, context, {"HPET", 56, accept_hpet, &result});
}

static bool apic_page(uint64_t address) {
    return address && !(address & 4095) && address <= physical_limit - 4096;
}

static bool append_processor(InterruptTopology& topology, Processor processor) {
    if (!(processor.flags & 3))
        return true;
    if (topology.processor_count == sizeof(topology.processors) / sizeof(Processor))
        return false;
    for (unsigned index = 0; index < topology.processor_count; ++index) {
        const auto& found = topology.processors[index];
        if (found.apic_id == processor.apic_id || found.uid == processor.uid)
            return false;
    }
    topology.processors[topology.processor_count++] = processor;
    return true;
}

static bool append_io_apic(InterruptTopology& topology, IoApic io_apic) {
    if (!apic_page(io_apic.address) ||
        topology.io_apic_count == sizeof(topology.io_apics) / sizeof(IoApic))
        return false;
    for (unsigned index = 0; index < topology.io_apic_count; ++index) {
        const auto& found = topology.io_apics[index];
        if (found.id == io_apic.id || found.address == io_apic.address ||
            found.first_gsi == io_apic.first_gsi)
            return false;
    }
    topology.io_apics[topology.io_apic_count++] = io_apic;
    return true;
}

static bool set_isa_override(InterruptTopology& topology, const uint8_t* entry) {
    unsigned irq = entry[3];
    if (entry[2] || irq >= 16 || topology.isa[irq].present)
        return false;
    auto flags = uint16_t(little(entry + 8, 2));
    if ((flags & ~0xf) || (flags & 3) == 2 || ((flags >> 2) & 3) == 2)
        return false;
    topology.isa[irq] = {uint32_t(little(entry + 4, 4)), flags, true};
    return true;
}

static bool accept_madt(const uint8_t* madt, void* output) {
    InterruptTopology topology{};
    topology.local_apic = little(madt + 36, 4);
    topology.legacy_pic = madt[40] & 1;
    bool address_override = false;
    size_t length = little(madt + 4, 4);
    for (size_t offset = 44; offset < length;) {
        auto entry = madt + offset;
        if (length - offset < 2 || entry[1] < 2 || entry[1] > length - offset)
            return false;
        unsigned bytes = entry[1];
        switch (entry[0]) {
        case 0: // Processor Local APIC.
            if (bytes < 8)
                return false;
            if (entry[3] != 0xff &&
                !append_processor(topology, {entry[3], entry[2], uint32_t(little(entry + 4, 4))}))
                return false;
            break;
        case 1: // I/O APIC.
            if (bytes < 12 || !append_io_apic(topology, {uint32_t(little(entry + 4, 4)),
                                                         uint32_t(little(entry + 8, 4)), entry[2]}))
                return false;
            break;
        case 2: // Interrupt Source Override.
            if (bytes < 10 || !set_isa_override(topology, entry))
                return false;
            break;
        case 5: // Local APIC Address Override.
            if (bytes < 12 || address_override)
                return false;
            topology.local_apic = little(entry + 4, 8);
            address_override = true;
            break;
        case 9: // Processor Local x2APIC.
            if (bytes < 16)
                return false;
            break;
        }
        offset += bytes;
    }
    // In a mixed table, low APIC IDs come from Processor Local APIC entries.
    bool mixed = topology.processor_count != 0;
    for (size_t offset = 44; offset < length; offset += madt[offset + 1]) {
        auto entry = madt + offset;
        if (entry[0] != 9)
            continue;
        auto id = uint32_t(little(entry + 4, 4));
        if (id != UINT32_MAX && (!mixed || id >= 0xff) &&
            !append_processor(
                topology, {id, uint32_t(little(entry + 12, 4)), uint32_t(little(entry + 8, 4))}))
            return false;
    }
    if (!topology.processor_count || !apic_page(topology.local_apic))
        return false;
    for (unsigned index = 0; index < topology.io_apic_count; ++index)
        if (topology.io_apics[index].address == topology.local_apic)
            return false;
    *static_cast<InterruptTopology*>(output) = topology;
    return true;
}

bool find_interrupt_topology(uint64_t rsdp, Read reader, void* context, InterruptTopology& result) {
    return find(rsdp, reader, context, {"APIC", 44, accept_madt, &result});
}

static bool accept_fadt(const uint8_t* fadt, void* output) {
    uint8_t revision = fadt[8];
    if (!revision)
        return false;
    auto boot_flags = uint16_t(revision >= 3 ? little(fadt + 109, 2) : 0);
    auto sci = uint16_t(little(fadt + 46, 2));
    *static_cast<FixedDescription*>(output) = {uint32_t(little(fadt + 112, 4)), sci, boot_flags,
                                               revision};
    return true;
}

bool find_fixed_description(uint64_t rsdp, Read reader, void* context, FixedDescription& result) {
    return find(rsdp, reader, context, {"FACP", 116, accept_fadt, &result});
}

static bool ecam_conflicts(const EcamRegion& first, const EcamRegion& second) {
    if (first.segment == second.segment && first.first_bus <= second.last_bus &&
        second.first_bus <= first.last_bus)
        return true;
    return first.bus_address(first.first_bus) < second.bus_address(second.last_bus + 1) &&
           second.bus_address(second.first_bus) < first.bus_address(first.last_bus + 1);
}

static bool accept_mcfg(const uint8_t* mcfg, void* output) {
    constexpr unsigned header_bytes = 44, entry_bytes = 16;
    size_t bytes = little(mcfg + 4, 4) - header_bytes;
    Mcfg result{};
    if (mcfg[8] != 1 || little(mcfg + 36, 8) || bytes % entry_bytes ||
        bytes / entry_bytes > Mcfg::max_regions)
        return false;

    for (size_t offset = header_bytes; offset < header_bytes + bytes; offset += entry_bytes) {
        const auto entry = mcfg + offset;
        EcamRegion region{little(entry, 8), uint16_t(little(entry + 8, 2)), entry[10], entry[11]};
        if (!region.base || region.base % EcamRegion::bus_bytes ||
            region.first_bus > region.last_bus ||
            region.base > physical_limit - (region.last_bus + 1) * EcamRegion::bus_bytes ||
            little(entry + 12, 4))
            return false;
        for (unsigned i = 0; i < result.count; ++i)
            if (ecam_conflicts(region, result.regions[i]))
                return false;
        result.regions[result.count++] = region;
    }
    *static_cast<Mcfg*>(output) = result;
    return true;
}

bool find_mcfg(uint64_t rsdp, Read reader, void* context, Mcfg& result) {
    return find(rsdp, reader, context, {"MCFG", 60, accept_mcfg, &result});
}
} // namespace ax::Acpi
