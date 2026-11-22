// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/pci.hpp
 * @brief   Declares PCI enumeration and configuration interfaces.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Gives device drivers a segment, bus, slot, and function identity with
 * register access, memory BAR decoding, and MSI and MSI-X message setup.
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
#include "arch/x86_64/interrupts.hpp"
#include "core/base.hpp"
#include "drivers/platform/pci_bar.hpp"

namespace ax {
namespace Acpi {
struct Mcfg;
struct DefinitionBlocks;
} // namespace Acpi

enum class PciPowerState : uint8_t { d0, d1, d2, d3hot, unavailable };

struct PciFunction {
    uint8_t bus, slot, function;
    uint16_t segment;
    volatile uint8_t* configuration;

    uint32_t read32(uint16_t offset) const;

    uint16_t read16(uint16_t offset) const;

    uint8_t read8(uint16_t offset) const;

    void write16(uint16_t offset, uint16_t value) const;

    void write32(uint16_t offset, uint32_t value) const;

    uint8_t find_capability(uint8_t id, unsigned* boundary = nullptr) const;
    PciPowerState power_state() const;
    // Use on an owned function with I/O, MMIO, and bus mastering disabled.
    // After waking from D3hot, revalidate or restore the BAR assignment before use.
    bool set_power_state(PciPowerState) const;

    // Probe only while the function is quiescent and no driver is using its BARs.
    PciBarStatus probe_bar(unsigned index, PciBarSpace space, PciBar& resource) const;
    PciBarStatus measure_unassigned_memory_bar(unsigned index, uint64_t& size) const;
};

class PciMsi {
  public:
    // Keep the device's interrupt sources masked until start succeeds.
    bool start(const PciFunction&, Irq::Handler, void* context);

    void stop(const PciFunction&);

    bool active() const {
        return vector_ != 0;
    }

  private:
    uint8_t capability_ = 0, mask_ = 0, vector_ = 0;
};

class PciMsix {
  public:
    bool prepare(const PciFunction&, uint8_t capability, const PciBar&, Irq::Handler,
                 void* context);

    bool unmask(const PciFunction&);

    void stop(const PciFunction&);

  private:
    volatile uint32_t* table_ = nullptr;
    uint8_t capability_ = 0, vector_ = 0;
};

class PciIntx {
  public:
    bool start(const PciFunction&, Irq::LineHandler, void* context);

    void stop(const PciFunction&);

    bool active() const {
        return subscription_.index != 0;
    }

    uint32_t gsi() const {
        return gsi_;
    }

    bool delivery_failed() const {
        return active() && !interrupt_line_ready(subscription_);
    }

  private:
    Irq::Line subscription_;
    uint32_t gsi_ = 0;
};

void pci_configure_ecam(const Acpi::Mcfg&);
void pci_configure_intx(const Acpi::DefinitionBlocks&, uint32_t sci, uint32_t link_gsis);
void pci_scan(void (*visit)(const PciFunction&));
} // namespace ax
