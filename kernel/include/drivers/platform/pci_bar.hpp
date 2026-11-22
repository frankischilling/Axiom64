// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/pci_bar.hpp
 * @brief   Assigned PCI endpoint BARs and aperture validation.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Sizes a quiescent function's BAR and verifies restoration before enabling decoding.
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once
#include "core/base.hpp"

namespace ax {
enum class PciBarSpace { memory, ports };
enum class PciBarStatus { valid, invalid, restore_failed };

struct PciBar {
    uint64_t base = 0, size = 0;
    unsigned index = 0;

    bool range(uint64_t offset, uint64_t length, uint64_t& address) const {
        if (!length || offset >= size || length > size - offset || offset > UINT64_MAX - base ||
            length - 1 > UINT64_MAX - base - offset)
            return false;
        address = base + offset;
        return true;
    }
};

struct PciMemoryInventory {
    struct Range {
        uint64_t base, size;
    };

    Range ranges[512];
    unsigned count = 0;
    bool incomplete = false;

    bool add(uint64_t base, uint64_t size) {
        if (!size)
            return true;
        if (size > UINT64_MAX - base || count == sizeof(ranges) / sizeof(*ranges)) {
            incomplete = true;
            return false;
        }
        ranges[count++] = {base, size};
        return true;
    }
};

namespace PciMemoryGap {
inline uint64_t overlap_end(uint64_t start, uint64_t end, uint64_t base, uint64_t size) {
    if (!size || base >= end)
        return 0;
    const uint64_t last = size > UINT64_MAX - base ? UINT64_MAX : base + size;
    return last > start ? last : 0;
}

// The callback returns the exclusive end of an occupied range overlapping [base, end).
template <class Exclusions>
bool find(uint64_t begin, uint64_t limit, uint64_t size, const Exclusions& exclusions,
          uint64_t& base) {
    if (!size || (size & (size - 1)))
        return false;
    const uint64_t mask = size - 1;
    while (begin < limit && begin <= UINT64_MAX - mask) {
        const uint64_t candidate = (begin + mask) & ~mask;
        if (candidate >= limit || size > limit - candidate)
            return false;
        const uint64_t end = candidate + size;
        const uint64_t blocked = exclusions(candidate, end);
        if (!blocked) {
            base = candidate;
            return true;
        }
        if (blocked <= candidate)
            return false;
        begin = blocked;
    }
    return false;
}
} // namespace PciMemoryGap

namespace PciBarProbe {
enum class Assignment { assigned, unassigned };

// The caller owns the function and must quiesce it before probing its BARs.
template <class Config>
PciBarStatus probe(const Config& pci, unsigned index, PciBarSpace space, uint64_t physical_limit,
                   PciBar& out, Assignment assignment = Assignment::assigned) {
    using enum PciBarStatus;
    if (index >= 6 || (pci.read8(0x0e) & 0x7f))
        return invalid;
    for (unsigned i = 0; i < index; ++i)
        if ((pci.read32(0x10 + i * 4) & 7) == 4 && ++i == index)
            return invalid;

    const uint16_t offset = 0x10 + index * 4;
    const uint32_t low = pci.read32(offset);
    const bool ports = low & 1;
    const bool wide = !ports && (low & 6) == 4;
    if (ports != (space == PciBarSpace::ports) || (!ports && (low & 2)) || (wide && index == 5))
        return invalid;
    const uint32_t high = wide ? pci.read32(offset + 4) : 0;
    const uint32_t address_bits = ports ? ~3u : ~15u;
    const uint64_t base = uint64_t(high) << 32 | (low & address_bits);
    const uint64_t limit = ports ? (1ull << 16) : physical_limit;
    if (base >= limit || (assignment == Assignment::unassigned ? base != 0 : base == 0))
        return invalid;

    const uint16_t command = pci.read16(4);
    const uint16_t quiet = command & ~7u; // Disable I/O, memory decoding, and bus mastering.
    if (quiet != command)
        pci.write16(4, quiet);
    if (pci.read16(4) != quiet) {
        pci.write16(4, command);
        return pci.read16(4) == command ? invalid : restore_failed;
    }

    pci.write32(offset, UINT32_MAX);
    if (wide)
        pci.write32(offset + 4, UINT32_MAX);
    const uint32_t mask_low = pci.read32(offset);
    uint64_t mask = mask_low & address_bits;
    if (wide)
        mask |= uint64_t(pci.read32(offset + 4)) << 32;
    pci.write32(offset, low);
    if (wide)
        pci.write32(offset + 4, high);
    if (pci.read32(offset) != low || (wide && pci.read32(offset + 4) != high))
        return restore_failed; // Keep decoding off if the original address did not restore.
    if (quiet != command)
        pci.write16(4, command);
    if (pci.read16(4) != command) {
        pci.write16(4, quiet);
        return restore_failed;
    }

    // The supported I/O space is 16 bits even if the device reports a 32-bit mask.
    const uint64_t size = ports ? uint16_t(-mask) : wide ? -mask : uint32_t(-mask);
    if (assignment == Assignment::unassigned && ((low ^ mask_low) & ~address_bits))
        return invalid;
    if (!size || (size & (size - 1)) || (base & (size - 1)) || size > limit - base)
        return invalid;
    out = {base, size, index};
    return valid;
}

// The caller owns a quiescent Type 0 function and measured BAR0 while unassigned.
// The address must already have passed the platform ownership check.
template <class Config, class Access>
PciBarStatus test_unassigned_memory(const Config& pci, uint64_t base, uint64_t size,
                                    uint64_t physical_limit, const Access& access) {
    using enum PciBarStatus;
    constexpr uint16_t command_register = 4, low_register = 0x10, high_register = 0x14;
    constexpr uint16_t memory_enable = 2;
    const uint32_t original = pci.read32(low_register);
    const bool wide = original & 4;
    const uint16_t quiet = pci.read16(command_register);
    if ((pci.read8(0x0e) & 0x7f) || (quiet & 7) || (original & ~12u) ||
        (wide && pci.read32(high_register)) || !base || size < 16 || (size & (size - 1)) ||
        (base & (size - 1)) || base >= physical_limit || size > physical_limit - base ||
        (!wide && (base >= (1ull << 32) || size > (1ull << 32) - base)))
        return invalid;

    const uint32_t low = uint32_t(base) | original;
    const uint32_t high = base >> 32;
    pci.write32(low_register, low);
    if (wide)
        pci.write32(high_register, high);
    bool accepted = false;
    if (pci.read32(low_register) == low && (!wide || pci.read32(high_register) == high)) {
        const uint16_t memory = quiet | memory_enable;
        pci.write16(command_register, memory);
        accepted = pci.read16(command_register) == memory && access(base);
    }

    // A half-written 64-bit BAR must never decode. Confirm the command before restoring it.
    if (pci.read16(command_register) != quiet)
        pci.write16(command_register, quiet);
    if (pci.read16(command_register) != quiet)
        return restore_failed;
    pci.write32(low_register, original);
    if (wide)
        pci.write32(high_register, 0);
    if (pci.read32(low_register) != original || (wide && pci.read32(high_register)))
        return restore_failed;
    return accepted ? valid : invalid;
}
} // namespace PciBarProbe
} // namespace ax
