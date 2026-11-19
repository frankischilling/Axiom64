// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/firmware/aml.hpp
 * @brief   Declares firmware PCI interrupt routing.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Resolves PCI pin routes from ACPI definition blocks and the configured
 * PCI bridge topology.
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
#include "firmware/acpi.hpp"

namespace ax::Acpi {

struct PciPinRoute {
    uint32_t gsi;
    uint16_t segment;
    uint8_t bus, slot, function, pin;
    bool active_low, level, shared;
};

struct PciPinRoutes {
    PciPinRoute entries[256];
    unsigned count;
};

struct PciBridge {
    uint16_t segment;
    uint8_t primary, secondary, subordinate, slot, function;
    bool ari;
    bool routing_rejected;
};

struct PciBridges {
    PciBridge entries[256];
    unsigned count;
    bool overflow;
};

// Evaluates the boot interrupt model and resolves routing packages and resources.
bool decode_pci_pin_routes(const DefinitionBlocks&, PciPinRoutes&, PciBridges* = nullptr);

const PciPinRoute* find_pci_pin(const PciPinRoutes&, uint16_t segment, uint8_t bus, uint8_t slot,
                                uint8_t function, uint8_t pin, const PciBridges* = nullptr);

} // namespace ax::Acpi
