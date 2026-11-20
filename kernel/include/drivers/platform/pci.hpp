// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/pci.hpp
 * @brief   PCI configuration interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines PCI address and device data and exposes configuration access and
 * discovery.
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
#include "core/base.hpp"

namespace ax {
struct PciFunction {
    uint8_t bus, slot, function;

    uint32_t read32(uint8_t offset) const;

    uint16_t read16(uint8_t offset) const;

    uint8_t read8(uint8_t offset) const;

    void write16(uint8_t offset, uint16_t value) const;

    // Assigned memory BAR only. Returns false for an I/O BAR, high half, or no address.
    bool memory_bar(unsigned index, uint64_t& address) const;
};

void pci_scan(void (*visit)(const PciFunction&));
} // namespace ax
