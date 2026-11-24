// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/pci_bridge.hpp
 * @brief   Checks PCI endpoint BARs against upstream bridge windows.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Decodes standard Type 1 forwarding registers and checks that every bridge
 * on a configured PCI path forwards the complete endpoint aperture.
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
#include "drivers/platform/pci_bar.hpp"
#include "firmware/aml.hpp"

namespace ax::PciBridgeWindows {
inline bool contains(uint64_t base, uint64_t limit, const PciBar& bar) {
    return bar.size && bar.base >= base && bar.base <= limit && bar.size - 1 <= limit - bar.base;
}

template <class Read> bool port_window(const Read& read, uint32_t control, const PciBar& bar) {
    uint32_t low;
    if (!read(0x1c, 2, low))
        return false;
    const unsigned type = low & 0xf;
    if (type > 1 || ((low >> 8) & 0xf) != type)
        return false;
    uint64_t base = (low & 0xf0) << 8;
    uint64_t limit = (low & 0xf000) | 0xfff;
    if (type == 1) {
        uint32_t upper;
        if (!read(0x30, 4, upper))
            return false;
        base |= (upper & 0xffff) << 16;
        limit |= upper & 0xffff0000;
    }
    // ISA mode reserves the last 768 bytes of each 1 KiB I/O block.
    const auto isa_offset = bar.base & 0x3ff;
    if ((control & 4) && (isa_offset >= 0x100 || bar.size > 0x100 - isa_offset))
        return false;
    return contains(base, limit, bar);
}

template <class Read>
bool memory_bounds(const Read& read, bool prefetchable, uint64_t& base, uint64_t& limit) {
    uint32_t low;
    if (!read(prefetchable ? 0x24 : 0x20, 4, low))
        return false;
    const unsigned type = low & 0xf;
    if (type > unsigned(prefetchable) || ((low >> 16) & 0xf) != type)
        return false;
    base = (low & 0xfff0) << 16;
    limit = (low & 0xfff00000) | 0xfffff;
    if (type == 1) {
        uint32_t high_base, high_limit;
        if (!read(0x28, 4, high_base) || !read(0x2c, 4, high_limit))
            return false;
        base |= uint64_t(high_base) << 32;
        limit |= uint64_t(high_limit) << 32;
    }
    return true;
}

template <class Read> bool memory_window(const Read& read, bool prefetchable, const PciBar& bar) {
    uint64_t base, limit;
    return memory_bounds(read, prefetchable, base, limit) && contains(base, limit, bar);
}

inline bool forwards(const Acpi::PciBridges& bridges, uint16_t segment, uint8_t bus,
                     PciBarSpace space, bool prefetchable, const PciBar& bar,
                     Acpi::PciConfigRead read_config) {
    if (!bus)
        return true;
    if (bridges.overflow)
        return false;
    uint8_t subordinate = bus;
    while (bus) {
        const auto parent = Acpi::parent_bridge(bridges, segment, bus);
        if (parent.invalid)
            return false;
        if (!parent.bridge) {
            // A bus inside a bridge's claimed range still needs a direct parent.
            for (unsigned i = 0; i < bridges.count; ++i) {
                const auto& bridge = bridges.entries[i];
                if (bridge.segment == segment && bus >= bridge.secondary &&
                    bus <= bridge.subordinate)
                    return false;
            }
            return true;
        }
        const auto& bridge = *parent.bridge;
        const auto read = [&](uint16_t offset, uint8_t width, uint32_t& value) {
            return read_config(segment, bridge.primary, bridge.slot, bridge.function, offset, width,
                               value);
        };
        uint32_t buses, command, control;
        const uint32_t expected =
            bridge.primary | uint32_t(bridge.secondary) << 8 | uint32_t(bridge.subordinate) << 16;
        const bool ports = space == PciBarSpace::ports;
        if (bridge.subordinate < subordinate || !read(0x18, 4, buses) ||
            (buses & 0xffffff) != expected || !read(4, 2, command) ||
            !(command & (ports ? 1 : 2)) || !read(0x3e, 2, control) || (control & 0x40))
            return false;
        const bool forwarded = ports ? port_window(read, control, bar)
                                     : memory_window(read, false, bar) ||
                                           (prefetchable && memory_window(read, true, bar));
        if (!forwarded)
            return false;
        bus = bridge.primary;
        subordinate = bridge.subordinate;
    }
    return true;
}
} // namespace ax::PciBridgeWindows
