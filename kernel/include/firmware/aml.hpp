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
#include "firmware/embedded_controller.hpp"

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
    unsigned programmed_links;
    bool rollback_failed;
};

struct PciBridge {
    uint16_t segment;
    uint8_t primary, secondary, subordinate, slot, function;
    bool ari;
    bool routing_rejected;
    bool invalid_primary = false;
};

struct PciBridges {
    PciBridge entries[256];
    unsigned count;
    bool overflow;
};

struct ParentBridge {
    const PciBridge* bridge = nullptr;
    bool invalid = false;
};

inline ParentBridge parent_bridge(const PciBridges& bridges, uint16_t segment, uint8_t bus) {
    ParentBridge result;
    for (unsigned i = 0; i < bridges.count; ++i) {
        const auto& bridge = bridges.entries[i];
        if (bridge.segment != segment || bridge.secondary != bus)
            continue;
        if (result.bridge || bridge.invalid_primary || bridge.primary >= bus ||
            bridge.subordinate < bus)
            return {nullptr, true};
        result.bridge = &bridge;
    }
    if (result.bridge)
        for (unsigned i = 0; i < bridges.count; ++i) {
            const auto& peer = bridges.entries[i];
            if (&peer != result.bridge && peer.segment == segment &&
                peer.primary == result.bridge->primary &&
                peer.secondary <= result.bridge->subordinate && peer.subordinate >= bus)
                return {nullptr, true};
        }
    return result;
}

using PciConfigRead = bool (*)(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                               uint16_t offset, uint8_t width, uint32_t& value);

// Replace one routing register after checking its old value. Verify the new
// value and attempt to restore the old one if readback fails.
using PciLinkWrite = bool (*)(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                              uint16_t offset, uint8_t previous, uint8_t next);

struct PciLinkProgram {
    PciLinkWrite write = nullptr;
    uint32_t allowed_gsis = 0;
};

// Evaluates the boot interrupt model and resolves routing packages and resources.
bool decode_pci_pin_routes(const DefinitionBlocks&, PciPinRoutes&, PciBridges* = nullptr,
                           PciConfigRead = nullptr, PciLinkProgram = {});

struct PciRootWindow {
    uint64_t base, size;
    uint16_t segment;
    uint8_t bus;
    bool prefetchable;
};

struct PciRootWindows {
    PciRootWindow entries[64];
    unsigned count;
};

// The provider validates the physical span and enforces the requested lock.
using SystemMemoryRead = bool (*)(uint64_t address, uint8_t* bytes, size_t length,
                                  bool firmware_lock);

// Read from device registers already validated by the caller. No writes reach this provider.
using RegisterRead = bool (*)(void* context, uint64_t address, uint8_t* bytes, size_t length);
using OsiQuery = bool (*)(const uint8_t* name, size_t length);
using PciBarRead = bool (*)(uint64_t address, uint32_t* values, size_t words);
using PciEcamRead = bool (*)(uint64_t address, unsigned bytes, uint32_t& value);
using EmbeddedControllerRead = bool (*)(void* context, uint8_t offset, uint8_t* bytes,
                                        size_t length);
using EmbeddedControllerWrite = bool (*)(void* context, uint8_t offset, const uint8_t* bytes,
                                         size_t length);
using CmosRead = bool (*)(void* context, uint8_t offset, uint8_t* bytes, size_t length,
                          bool firmware_lock);

struct PowerRegisters {
    void* context = nullptr;
    EmbeddedControllerRead read_ec = nullptr;
    EmbeddedControllerWrite write_ec = nullptr;
    CmosRead read_cmos = nullptr;
    EmbeddedControllerPorts ports{};
};

struct ReadRegions {
    SystemMemoryRead memory = nullptr;
    PciConfigRead pci = nullptr;
    const PciBridges* bridges = nullptr;
    RegisterRead registers = nullptr;
    void* register_context = nullptr;
    OsiQuery osi = nullptr;
    PciBarRead pci_bars = nullptr;
    PciEcamRead pci_ecam = nullptr;
};

// Decode fixed, identity-mapped memory apertures. An aperture is not a reservation.
bool decode_pci_root_windows(const DefinitionBlocks&, PciRootWindows&, ReadRegions = {});

struct MemoryReservation {
    uint64_t base, size;
};

struct MotherboardResources {
    MemoryReservation memory[128];
    unsigned count;
    bool incomplete;
};

// Validated PNP0C01/PNP0C02 ranges may be listed even if other declarations fail.
// An incomplete result cannot be used by an allocator as an exclusion list.
bool decode_motherboard_resources(const DefinitionBlocks&, MotherboardResources&, ReadRegions = {});

// Read the active PNP0C09 controller's data and command ports from _CRS.
bool decode_embedded_controller_ports(const DefinitionBlocks&, EmbeddedControllerPorts&,
                                      ReadRegions = {});

// ACPI battery capacities and rates are milli-units. Unknown numeric readings
// use UINT32_MAX, including values firmware returns as AML Ones.
struct BatteryReading {
    char name[5], model[32], serial[32], technology[16], manufacturer[32];
    uint32_t unit, state, design_capacity, full_capacity, remaining_capacity;
    uint32_t rate, voltage, design_voltage;
    bool present;
};

struct AcAdapterReading {
    char name[5];
    bool online;
};

struct PowerSupplySnapshot {
    BatteryReading batteries[8];
    AcAdapterReading adapters[8];
    unsigned battery_count, adapter_count;
};

struct PowerSupplyReader;

// The reader connects its controller once. The caller keeps its providers alive
// and serializes sampling and teardown.
PowerSupplyReader* open_power_supply_reader(const DefinitionBlocks&, ReadRegions = {},
                                            PowerRegisters = {}, const char** failure = nullptr);
bool sample_power_supplies(PowerSupplyReader&, PowerSupplySnapshot&);
void close_power_supply_reader(PowerSupplyReader*);

// If EC access is supplied, the provider must own the named controller and honor
// its Global Lock requirement. A failed evaluation produces no snapshot.
bool read_power_supplies(const DefinitionBlocks&, PowerSupplySnapshot&, ReadRegions = {},
                         PowerRegisters = {});

struct IntelGpioResources {
    enum class Model { none, cannon_lake_lp, cannon_lake_h };
    uint64_t community_base[4];
    Model model;
};

bool decode_intel_gpio_resources(const DefinitionBlocks&, IntelGpioResources&, ReadRegions = {});

struct I2cHidInterrupt {
    enum class Source : uint8_t { none, legacy_irq, gsi, gpio };
    enum class Polarity : uint8_t { active_high, active_low, both_edges };
    Source source;
    Polarity polarity;
    uint32_t line;
    bool edge, shared, wake;
    char gpio_controller[82];
    uint16_t gpio_debounce;
    uint8_t gpio_pull;
};

struct I2cHidDevice {
    char hardware_id[16];
    char controller[82];
    uint32_t max_hz;
    uint16_t address, descriptor_register;
    uint8_t source_index;
    bool ten_bit, has_descriptor_register;

    struct {
        uint16_t segment;
        uint8_t bus, slot, function;
        bool resolved;
    } pci_controller;

    I2cHidInterrupt interrupt;
};

struct I2cHidDevices {
    I2cHidDevice devices[8];
    unsigned count;
    unsigned initialization_failures;
};

enum class HidDiscovery { resources, replay_initialization };

// Inspect firmware HID-over-I2C resources without programming the controller.
bool decode_i2c_hid_devices(const DefinitionBlocks&, I2cHidDevices&, ReadRegions = {},
                            HidDiscovery = HidDiscovery::resources);

const PciPinRoute* find_pci_pin(const PciPinRoutes&, uint16_t segment, uint8_t bus, uint8_t slot,
                                uint8_t function, uint8_t pin, const PciBridges* = nullptr);

} // namespace ax::Acpi
