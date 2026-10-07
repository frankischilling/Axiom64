// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/platform/pci.hpp"

namespace ax {
static uint32_t selector(const PciFunction& p, uint8_t offset) {
    return 0x80000000u | uint32_t(p.bus) << 16 | uint32_t(p.slot) << 11 |
           uint32_t(p.function) << 8 | (offset & 0xfc);
}

uint32_t PciFunction::read32(uint8_t offset) const {
    out32(0xcf8, selector(*this, offset));
    return in32(0xcfc);
}

uint16_t PciFunction::read16(uint8_t offset) const {
    out32(0xcf8, selector(*this, offset));
    return in16(0xcfc + (offset & 2));
}

uint8_t PciFunction::read8(uint8_t offset) const {
    return uint8_t(read32(offset) >> ((offset & 3) * 8));
}

void PciFunction::write16(uint8_t offset, uint16_t value) const {
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

void pci_scan(void (*visit)(const PciFunction&)) {
    unsigned count = 0;
    for (unsigned bus = 0; bus < 256; bus++)
        for (unsigned slot = 0; slot < 32; slot++) {
            PciFunction first{uint8_t(bus), uint8_t(slot), 0};
            if (first.read16(0) == 0xffff)
                continue;
            unsigned functions = first.read8(0x0e) & 0x80 ? 8 : 1;
            for (unsigned function = 0; function < functions; function++) {
                PciFunction p{uint8_t(bus), uint8_t(slot), uint8_t(function)};
                if (p.read16(0) != 0xffff) {
                    count++;
                    visit(p);
                }
            }
        }
    log("PCI: %u functions discovered\n", uint64_t(count));
}
} // namespace ax
