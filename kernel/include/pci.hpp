// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "base.hpp"

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
