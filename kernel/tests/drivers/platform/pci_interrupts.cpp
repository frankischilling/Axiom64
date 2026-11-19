// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/platform/pci_interrupts.cpp
 * @brief   Tests PCI message configuration and resource validation on the host.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Supplies a synthetic configuration page and MSI-X table to the production
 * PCI implementation. Guest fixtures exercise delivery on actual QEMU devices.
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
#include <cassert>
#include <cstdio>
#include <sys/mman.h>
#include "drivers/platform/pci.hpp"

namespace {
constexpr uint32_t base = 0x10000000;
constexpr uint16_t command = 0x407;
constexpr uint8_t capability = 0x50;
unsigned mappings, registrations, retirements;
bool mapping_error, route_available = true;
uint32_t table[4];

void handler(void*) {
}

void reset(const ax::PciFunction& pci, uint8_t id, uint16_t control, uint8_t next = 0) {
    memset(const_cast<uint8_t*>(pci.configuration), 0, 4096);
    pci.write16(4, command);
    pci.write16(6, 16);
    pci.write32(0x34, capability);
    pci.write32(capability, id | uint32_t(next) << 8 | uint32_t(control) << 16);
}

void test_msi(const ax::PciFunction& pci) {
    ax::PciMsi msi;
    reset(pci, 5, 0x24); // A firmware-selected multiple-message configuration.
    pci.write32(capability + 8, 0xabcd0000);
    assert(msi.start(pci, handler, nullptr));
    assert(pci.read32(capability + 4) == 0xfee00000);
    assert(pci.read32(capability + 8) == 0xabcd0040);
    assert(pci.read16(capability + 2) == 5);
    msi.stop(pci);
    msi.stop(pci);
    assert(!msi.active() && pci.read16(capability + 2) == 4 && retirements == 1);

    reset(pci, 5, 0x180, 0x68);
    pci.write32(0x68, 0x80000011); // Firmware left MSI-X enabled.
    pci.write32(capability + 8, UINT32_MAX);
    pci.write32(capability + 12, 0xabcd0000);
    pci.write32(capability + 16, 0x83);
    assert(msi.start(pci, handler, nullptr));
    assert(pci.read16(0x6a) == 0x4000 && pci.read32(capability + 8) == 0);
    assert(pci.read32(capability + 12) == 0xabcd0040 && pci.read32(capability + 16) == 0x82);
    msi.stop(pci);
    assert(pci.read32(capability + 16) == 0x83 && retirements == 2);

    reset(pci, 5, 0, 0x58); // The next capability overlaps the message data.
    pci.write32(0x58, 1);
    assert(!msi.start(pci, handler, nullptr) && pci.read32(0x58) == 1);
    reset(pci, 5, 0, capability);
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0, 0x70);
    pci.write32(0x70, 5); // Duplicate MSI declarations.
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0xe); // Reserved message count.
    assert(!msi.start(pci, handler, nullptr));
    reset(pci, 5, 0);
    pci.write16(4, command & ~uint16_t(0x400));
    assert(!msi.start(pci, handler, nullptr));
    assert(registrations == 2 && mappings == 0 && retirements == 2);

    reset(pci, 5, 0);
    route_available = false;
    assert(!msi.start(pci, handler, nullptr) && !msi.active());
    assert(pci.read16(capability + 2) == 0 && retirements == 2);
    route_available = true;
    std::puts("PCI_MSI_RESOURCE_PASS width32 width64 masking teardown invalid_capabilities");
}

void test_msix(const ax::PciFunction& pci) {
    ax::PciMsix msix;
    reset(pci, 0x11, 0);
    pci.write32(0x10, base);
    assert(msix.prepare(pci, capability, handler, nullptr));
    assert(pci.read16(4) == command && pci.read32(0x10) == base);
    assert(pci.read16(capability + 2) == 0xc000);
    assert(table[0] == 0xfee00000 && table[1] == 0 && table[2] == 0x40 && table[3] == 1);
    assert(msix.unmask(pci) && table[3] == 0 && pci.read16(capability + 2) == 0x8000);
    msix.stop(pci);
    msix.stop(pci);
    assert(retirements == 3 && pci.read16(capability + 2) == 0x4000);

    pci.write32(capability + 4, 8);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    pci.write32(capability + 4, 0);
    pci.write16(capability + 2, 1);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    pci.write16(capability + 2, 0);
    pci.write32(0x10, base | 1);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    pci.write32(0x10, base | 4);
    pci.write32(capability + 4, 1);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    pci.write32(capability + 4, 6);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    assert(!msix.prepare(pci, 0xf8, handler, nullptr));
    pci.write32(capability + 4, 0);
    pci.write32(0x14, UINT32_MAX);
    assert(!msix.prepare(pci, capability, handler, nullptr));
    assert(pci.read16(4) == command && pci.read32(0x14) == UINT32_MAX);
    assert(registrations == 4 && mappings == 1 && retirements == 3);

    pci.write32(0x10, base);
    mapping_error = true;
    assert(!msix.prepare(pci, capability, handler, nullptr));
    assert(mappings == 2 && retirements == 4 && pci.read16(capability + 2) == 0x4000);
    std::puts("PCI_MSIX_RESOURCE_PASS single_entry invalid_resource_ranges failed_mapping");
}
} // namespace

namespace ax {
void* map_mmio(uint64_t address, size_t bytes) {
    assert(address == base && bytes == sizeof(table));
    ++mappings;
    return mapping_error ? nullptr : table;
}

bool interrupt_register_message(Irq::Handler call, void*, Irq::Message& message) {
    assert(call == handler);
    ++registrations;
    if (!route_available)
        return false;
    message = {0xfee00000, 0x40};
    return true;
}

void interrupt_retire_message(uint8_t vector) {
    assert(vector == 0x40);
    ++retirements;
}
} // namespace ax

int main() {
    auto page = static_cast<uint8_t*>(
        mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    assert(page != MAP_FAILED);
    ax::PciFunction pci{0, 1, 0, 0, page};
    test_msi(pci);
    test_msix(pci);
    assert(munmap(page, 4096) == 0);
}
