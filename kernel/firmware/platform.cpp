// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/platform.cpp
 * @brief   Discovers ACPI resources during x86 boot.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Reads platform tables through the boot memory map, reports interrupt
 * topology and definition blocks, and passes PCI apertures to the driver.
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
#include "boot/boot.hpp"
#include "core/time.hpp"
#include "drivers/platform/fb_console.hpp"
#include "drivers/platform/pci.hpp"
#include "firmware/aml.hpp"
#include "firmware/acpi.hpp"

namespace ax {
const uint8_t* firmware_read(uint64_t address, size_t length, void*) {
    if (!boot_info.memory_at || !length || length > Acpi::max_definition_bytes ||
        address > UINT64_MAX - direct_map || length - 1 > UINT64_MAX - direct_map - address)
        return nullptr;
    for (size_t i = 0; i < boot_info.memory_count; i++) {
        auto entry = boot_info.memory_at(boot_info.memory_context, i);
        if (address < entry.base || address - entry.base > entry.length ||
            length > entry.length - (address - entry.base))
            continue;
        if (entry.kind == BootMemoryKind::retained)
            return static_cast<const uint8_t*>(physical(address));
        if (entry.kind == BootMemoryKind::reserved || entry.kind == BootMemoryKind::firmware ||
            entry.kind == BootMemoryKind::mapped_reserved || entry.kind == BootMemoryKind::acpi_nvs)
            return static_cast<const uint8_t*>(map_mmio(address, length));
    }
    return nullptr;
}

namespace {
volatile uint8_t* map_acpi_memory(uint64_t address, size_t length, bool allow_reserved) {
    if (!length || !boot_info.memory_at || length > UINT64_MAX - address)
        return nullptr;
    const auto end = address + length;
    bool contained = false;
    auto kind = BootMemoryKind::other;
    for (size_t i = 0; i < boot_info.memory_count; ++i) {
        const auto entry = boot_info.memory_at(boot_info.memory_context, i);
        if (!entry.length || entry.base >= end ||
            (entry.base < address && entry.length <= address - entry.base))
            continue;
        if (entry.kind != BootMemoryKind::acpi_nvs &&
            !(allow_reserved && entry.kind == BootMemoryKind::reserved))
            return nullptr;
        if (kind != BootMemoryKind::other && kind != entry.kind)
            return nullptr;
        kind = entry.kind;
        if (entry.base <= address && end - entry.base <= entry.length)
            contained = true;
    }
    return contained ? static_cast<volatile uint8_t*>(map_mmio(address, length)) : nullptr;
}

struct FirmwareLock {
    volatile uint32_t* word;
    uint16_t pm1a, pm1b;
};

FirmwareLock find_firmware_lock() {
    Acpi::GlobalLockControl control{};
    if (!Acpi::find_global_lock_control(boot_info.rsdp, firmware_read, nullptr, control))
        return {};
    const auto* header = map_acpi_memory(control.facs, 64, false);
    if (!header || header[0] != 'F' || header[1] != 'A' || header[2] != 'C' || header[3] != 'S')
        return {};
    uint32_t length = 0;
    for (unsigned i = 0; i < 4; ++i)
        length |= uint32_t(header[4 + i]) << (8 * i);
    if (length < 64 || length > 4096)
        return {};
    auto* facs = map_acpi_memory(control.facs, length, false);
    if (!facs)
        return {};
    return {reinterpret_cast<volatile uint32_t*>(facs + 16), control.pm1a, control.pm1b};
}

void notify_firmware(uint16_t port) {
    if (port) {
        constexpr uint16_t sleep_enable = 1 << 13, global_lock_release = 1 << 2;
        out16(port, (in16(port) & ~sleep_enable) | global_lock_release);
    }
}

class FirmwareLockGuard {
  public:
    explicit FirmwareLockGuard(bool required) {
        if (!required) {
            acquired = true;
            return;
        }
        static const auto platform_lock = find_firmware_lock();
        lock = platform_lock;
        acquired = lock.word && Acpi::try_acquire_global_lock(*lock.word);
    }

    ~FirmwareLockGuard() {
        if (acquired && lock.word && Acpi::release_global_lock(*lock.word)) {
            notify_firmware(lock.pm1a);
            notify_firmware(lock.pm1b);
        }
    }

    explicit operator bool() const {
        return acquired;
    }

  private:
    FirmwareLock lock{};
    bool acquired = false;
};

struct PowerIo {
    Acpi::EmbeddedControllerPorts ports;
    unsigned delay_budget;
    const char* error;
};

PowerIo power_io;
constexpr unsigned boot_ec_delay_budget = 500000, runtime_ec_delay_budget = 10000;

Acpi::EmbeddedControllerIo controller_io(PowerIo& power) {
    return {&power, [](void*, uint16_t port) { return in8(port); },
            [](void*, uint16_t port, uint8_t value) { out8(port, value); },
            [](void* context, unsigned us) {
                auto& power = *static_cast<PowerIo*>(context);
                if (us > power.delay_budget) {
                    power.error = "embedded controller wait budget exhausted";
                    return false;
                }
                power.delay_budget -= us;
                if (clock_delay_us(us))
                    return true;
                power.error = "embedded controller wait timer failed";
                return false;
            }};
}

bool power_read_ec(void* context, uint8_t offset, uint8_t* bytes, size_t length) {
    auto& power = *static_cast<PowerIo*>(context);
    const FirmwareLockGuard guard(power.ports.global_lock);
    if (!guard) {
        power.error = "ACPI global lock unavailable during embedded controller read";
        return false;
    }
    const bool read =
        Acpi::read_embedded_controller(power.ports, controller_io(power), offset, bytes, length);
    if (!read && !power.error)
        power.error = "embedded controller read timed out";
    return read;
}

bool power_write_ec(void* context, uint8_t offset, const uint8_t* bytes, size_t length) {
    auto& power = *static_cast<PowerIo*>(context);
    const FirmwareLockGuard guard(power.ports.global_lock);
    if (!guard) {
        power.error = "ACPI global lock unavailable during embedded controller write";
        return false;
    }
    const bool written =
        Acpi::write_embedded_controller(power.ports, controller_io(power), offset, bytes, length);
    if (!written && !power.error)
        power.error = "embedded controller write timed out";
    return written;
}

bool power_read_cmos(void*, uint8_t offset, uint8_t* bytes, size_t length, bool lock) {
    // The connection method uses ordinary RTC fields. Reading status C would
    // acknowledge RTC interrupts, and other CMOS fields are outside this probe.
    if (offset >= 10 || length > size_t(10 - offset))
        return false;
    const FirmwareLockGuard guard(lock);
    if (!guard) {
        power_io.error = "ACPI global lock unavailable during RTC read";
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        out8(0x70, uint8_t(offset + i));
        bytes[i] = in8(0x71);
    }
    return true;
}

void power_probe_text(const char* text) {
    log("%s", text);
    while (*text)
        fb_console_put(*text++);
}

void power_probe_value(const char* label, uint64_t value) {
    char digits[21];
    char* begin = digits + sizeof(digits);
    *--begin = 0;
    do {
        *--begin = char('0' + value % 10);
        value /= 10;
    } while (value);
    power_probe_text(label);
    power_probe_text(begin);
}
} // namespace

bool firmware_read_system_memory(uint64_t address, uint8_t* bytes, size_t length,
                                 bool firmware_lock) {
    if (!bytes || length > 9)
        return false;
    // A boot-time AML field can refer to a firmware reservation outside ACPI NVS.
    const auto* source = map_acpi_memory(address, length, true);
    if (!source)
        return false;
    const FirmwareLockGuard guard(firmware_lock);
    if (!guard)
        return false;
    for (size_t i = 0; i < length; ++i)
        bytes[i] = source[i];
    return true;
}

Acpi::PowerSupplyReader* firmware_open_power_supply_reader(const Acpi::DefinitionBlocks& blocks,
                                                           const char** failure) {
    const auto regions = pci_firmware_read_regions();
    auto& ports = power_io.ports;
    Acpi::PowerRegisters registers{};
    if (decode_embedded_controller_ports(blocks, ports, regions)) {
        if (ports.data != 0x62 || ports.command != 0x66) {
            if (failure)
                *failure = "unsupported embedded-controller ports";
            log("ACPI power: unsupported EC at data=%x command=%x\n", uint64_t(ports.data),
                uint64_t(ports.command));
            return nullptr;
        }
        registers = {&power_io, power_read_ec, power_write_ec, power_read_cmos, ports};
    }
    // _REG can issue several controller transactions. Retain the per-transfer
    // deadline and allow a longer aggregate wait before userspace starts.
    power_io.delay_budget = boot_ec_delay_budget;
    power_io.error = nullptr;
    auto* reader = Acpi::open_power_supply_reader(blocks, regions, registers, failure);
    if (!reader && failure && power_io.error)
        *failure = power_io.error;
    return reader;
}

bool firmware_sample_power_supplies(Acpi::PowerSupplyReader& reader,
                                    Acpi::PowerSupplySnapshot& readings, bool initial,
                                    const char** failure) {
    // An EC wait can hold the kernel lock. Bound the total delay per sample.
    power_io.delay_budget = initial ? boot_ec_delay_budget : runtime_ec_delay_budget;
    power_io.error = nullptr;
    const bool sampled = Acpi::sample_power_supplies(reader, readings);
    if (failure)
        *failure = sampled ? nullptr : power_io.error ? power_io.error : "firmware sample failed";
    return sampled;
}

void firmware_probe_power_supplies(const Acpi::DefinitionBlocks& blocks) {
    auto* reader = firmware_open_power_supply_reader(blocks);
    Acpi::PowerSupplySnapshot readings{};
    const bool success = reader && firmware_sample_power_supplies(*reader, readings, true);
    Acpi::close_power_supply_reader(reader);
    if (!success) {
        power_probe_value("ACPI power: firmware evaluation failed ec=", power_io.ports.data != 0);
        power_probe_text("\n");
        return;
    }
    power_probe_value("ACPI power: batteries=", readings.battery_count);
    power_probe_value(" adapters=", readings.adapter_count);
    power_probe_text("\n");
    for (unsigned i = 0; i < readings.adapter_count; ++i) {
        const auto& adapter = readings.adapters[i];
        power_probe_text("ACPI AC: ");
        power_probe_text(adapter.name);
        power_probe_value(" online=", adapter.online);
        power_probe_text("\n");
    }
    for (unsigned i = 0; i < readings.battery_count; ++i) {
        const auto& battery = readings.batteries[i];
        power_probe_text("ACPI battery: ");
        power_probe_text(battery.name);
        if (!battery.present) {
            power_probe_text(" empty bay\n");
            continue;
        }
        power_probe_text(" model=");
        power_probe_text(battery.model);
        power_probe_value(" unit=", battery.unit);
        power_probe_value(" state=", battery.state);
        power_probe_text("\n");
        power_probe_value("ACPI battery: remaining=", battery.remaining_capacity);
        power_probe_value(" full=", battery.full_capacity);
        power_probe_value(" design=", battery.design_capacity);
        power_probe_value(" voltage_mv=", battery.voltage);
        power_probe_value(" rate=", battery.rate);
        power_probe_text("\n");
    }
}

bool firmware_discover(uint64_t rsdp, Acpi::InterruptTopology& topology,
                       Acpi::DefinitionBlocks& blocks) {
    blocks = {};
    if (!rsdp) {
        log("ACPI: no root pointer supplied by firmware\n");
        return false;
    }
    bool have_topology = Acpi::find_interrupt_topology(rsdp, firmware_read, nullptr, topology);
    if (have_topology) {
        log("ACPI MADT: local-apic=%x processors=%u io-apics=%u legacy-pic=%u\n",
            topology.local_apic, uint64_t(topology.processor_count),
            uint64_t(topology.io_apic_count), uint64_t(topology.legacy_pic));
        for (unsigned index = 0; index < topology.io_apic_count; ++index) {
            const auto& io_apic = topology.io_apics[index];
            log("ACPI I/O APIC: id=%u address=%x first-gsi=%u\n", uint64_t(io_apic.id),
                uint64_t(io_apic.address), uint64_t(io_apic.first_gsi));
        }
        for (unsigned irq = 0; irq < 16; ++irq) {
            const auto& route = topology.isa[irq];
            if (route.present)
                log("ACPI ISA override: irq=%u gsi=%u flags=%x\n", uint64_t(irq),
                    uint64_t(route.gsi), uint64_t(route.flags));
        }
    } else {
        log("ACPI: MADT absent or rejected\n");
    }
    Acpi::FixedDescription fixed;
    if (Acpi::find_fixed_description(rsdp, firmware_read, nullptr, fixed))
        log("ACPI FADT: revision=%u sci=%u boot-flags=%x flags=%x\n", uint64_t(fixed.revision),
            uint64_t(fixed.sci), uint64_t(fixed.boot_flags), uint64_t(fixed.flags));
    else
        log("ACPI: FADT absent or rejected\n");
    if (Acpi::find_definition_blocks(rsdp, firmware_read, nullptr, blocks))
        log("ACPI definition blocks: DSDT=%u bytes SSDTs=%u\n", uint64_t(blocks.dsdt.length),
            uint64_t(blocks.ssdt_count));
    else
        log("ACPI: definition blocks absent or rejected\n");
    Acpi::Mcfg mcfg;
    if (Acpi::find_mcfg(rsdp, firmware_read, nullptr, mcfg))
        pci_configure_ecam(mcfg);
    else
        log("ACPI: MCFG absent or rejected\n");
    return have_topology;
}

void firmware_probe_i2c_hid(const Acpi::DefinitionBlocks& blocks) {
    Acpi::I2cHidDevices devices{};
    if (!Acpi::decode_i2c_hid_devices(blocks, devices, pci_firmware_read_regions())) {
        log("ACPI I2C HID: firmware discovery failed\n");
        return;
    }
    log("ACPI I2C HID: devices=%u\n", uint64_t(devices.count));
    for (unsigned i = 0; i < devices.count; ++i) {
        const auto& device = devices.devices[i];
        log("ACPI I2C HID: id=%s controller=%s bus=%u address=%x bits=%u speed-hz=%u\n",
            device.hardware_id, device.controller, uint64_t(device.source_index),
            uint64_t(device.address), uint64_t(device.ten_bit ? 10 : 7), uint64_t(device.max_hz));
        if (device.has_descriptor_register)
            log("ACPI I2C HID: id=%s descriptor-register=%x\n", device.hardware_id,
                uint64_t(device.descriptor_register));
        using Source = Acpi::I2cHidInterrupt::Source;
        using Polarity = Acpi::I2cHidInterrupt::Polarity;
        const auto& irq = device.interrupt;
        if (irq.source == Source::none)
            continue;
        const char* source = irq.source == Source::gpio  ? "gpio"
                             : irq.source == Source::gsi ? "gsi"
                                                         : "isa";
        const char* polarity = irq.polarity == Polarity::active_high  ? "high"
                               : irq.polarity == Polarity::active_low ? "low"
                                                                      : "both";
        log("ACPI I2C HID: id=%s irq-source=%s line=%u trigger=%s polarity=%s shared=%u wake=%u\n",
            device.hardware_id, source, uint64_t(irq.line), irq.edge ? "edge" : "level", polarity,
            uint64_t(irq.shared), uint64_t(irq.wake));
        if (irq.source == Source::gpio)
            log("ACPI I2C HID: id=%s gpio-controller=%s pull=%u debounce-10us=%u\n",
                device.hardware_id, irq.gpio_controller, uint64_t(irq.gpio_pull),
                uint64_t(irq.gpio_debounce));
    }
}

void firmware_configure_pci_interrupts(uint64_t rsdp, const Acpi::InterruptTopology& topology,
                                       const Acpi::DefinitionBlocks& blocks) {
    if (!interrupt_apic_ready() || !blocks.dsdt.table)
        return;
    Acpi::FixedDescription fixed;
    if (!Acpi::find_fixed_description(rsdp, firmware_read, nullptr, fixed))
        return;
    uint32_t sci = fixed.sci;
    if (sci < 16 && topology.isa[sci].present)
        sci = topology.isa[sci].gsi;
    // The PIIX router targets ISA lines. Require firmware to identify the
    // same GSI as active-high and level-triggered before changing a route.
    constexpr uint16_t active_high_level = 0x0d;
    uint32_t link_gsis = 0;
    for (unsigned irq = 0; irq < 16; ++irq) {
        const auto& route = topology.isa[irq];
        if (route.present && route.gsi == irq && route.flags == active_high_level && irq != sci &&
            interrupt_line_available(irq))
            link_gsis |= 1u << irq;
    }
    pci_configure_intx(blocks, sci, link_gsis);
}
} // namespace ax
