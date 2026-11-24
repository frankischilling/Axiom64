// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/power_supply.cpp
 * @brief   Publishes ACPI power readings and emits device state changes.
 * @author  frankischilling
 * @date    2026-11-23
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
#include "drivers/platform/power_supply.hpp"
#include "boot/boot.hpp"
#include "core/time.hpp"
#include "drivers/platform/devices.hpp"
#include "drivers/platform/inventory.hpp"
#include "firmware/aml.hpp"

namespace ax::DeviceInventory {
namespace {
constexpr char class_path[] = "/sys/class/power_supply";
constexpr char device_path[] = "/sys/devices/virtual/power_supply";
constexpr uint64_t refresh_ticks = 200;

enum Attribute {
    type,
    present,
    online,
    status,
    scope,
    technology,
    model,
    manufacturer,
    serial_number,
    capacity,
    voltage_now,
    voltage_min_design,
    charge_now,
    charge_full,
    charge_full_design,
    current_now,
    energy_now,
    energy_full,
    energy_full_design,
    power_now
};

constexpr const char* attribute_names[]{"type",
                                        "present",
                                        "online",
                                        "status",
                                        "scope",
                                        "technology",
                                        "model_name",
                                        "manufacturer",
                                        "serial_number",
                                        "capacity",
                                        "voltage_now",
                                        "voltage_min_design",
                                        "charge_now",
                                        "charge_full",
                                        "charge_full_design",
                                        "current_now",
                                        "energy_now",
                                        "energy_full",
                                        "energy_full_design",
                                        "power_now"};

struct Supply {
    char name[5];
    char path[64];
    char values[sizeof(attribute_names) / sizeof(*attribute_names)][48];
    char event[1536];
    bool changed;
    bool published;

    Node* set_file(const char* name, char* storage, size_t limit, const char* value);
    bool set(Attribute, const char*);
    bool set_number(Attribute, uint32_t, unsigned scale = 1);
    bool write_event();
};

Acpi::PowerSupplyReader* reader;
Acpi::PowerSupplySnapshot initial_readings;
Supply supplies[16];
uint64_t next_refresh;
bool sample_failed;
bool initial_sample_ready;
const char* startup_failure;

Node* Supply::set_file(const char* name, char* storage, size_t limit, const char* value) {
    const size_t length = value ? strlen(value) : 0;
    char attribute[96];
    if (length >= limit || !inventory_path(attribute, path, name))
        return nullptr;
    auto* node = lookup(attribute, false);
    if (!node) {
        if (!value)
            return nullptr;
        node = make_node(attribute, regular_file | 0444);
        if (!node)
            return nullptr;
        node->data = reinterpret_cast<uint8_t*>(storage);
        node->capacity = limit;
    } else if (node->data != reinterpret_cast<uint8_t*>(storage) ||
               (node->mode & 0170000) != regular_file) {
        return nullptr;
    }
    const size_t size = value ? length + 1 : 0;
    if (node->size == size && (!length || !memcmp(storage, value, length)))
        return node;
    if (value) {
        memcpy(storage, value, length);
        storage[length] = '\n';
    }
    node->size = size;
    changed = true;
    return node;
}

bool Supply::set(Attribute attribute, const char* value) {
    auto& storage = values[attribute];
    auto* node = set_file(attribute_names[attribute], storage, sizeof(storage), value);
    if (!value)
        return true;
    return node;
}

bool Supply::set_number(Attribute attribute, uint32_t value, unsigned scale) {
    if (value == UINT32_MAX)
        return set(attribute, nullptr);
    uint64_t number = uint64_t(value) * scale;
    char digits[21];
    auto* text = digits + sizeof(digits);
    *--text = 0;
    do {
        *--text = char('0' + number % 10);
        number /= 10;
    } while (number);
    return set(attribute, text);
}

bool Supply::write_event() {
    if (published && !changed)
        return true;
    char environment[sizeof(event)] = "POWER_SUPPLY_NAME=";
    size_t used = strlen(environment);
    auto append = [&](const char* text, size_t length) {
        if (length >= sizeof(environment) - used)
            return false;
        memcpy(environment + used, text, length);
        used += length;
        return true;
    };
    if (!append(name, strlen(name)) || !append("\n", 1))
        return false;
    for (unsigned i = 0; i < sizeof(attribute_names) / sizeof(*attribute_names); ++i) {
        char path_to_value[96];
        if (!inventory_path(path_to_value, path, attribute_names[i]))
            return false;
        const auto* node = lookup(path_to_value, false);
        if (!node || !node->size || node->data != reinterpret_cast<const uint8_t*>(values[i]))
            continue;
        if (!append("POWER_SUPPLY_", sizeof("POWER_SUPPLY_") - 1))
            return false;
        for (const char* c = attribute_names[i]; *c; ++c) {
            const char upper = *c >= 'a' && *c <= 'z' ? char(*c - 'a' + 'A') : *c;
            if (!append(&upper, 1))
                return false;
        }
        if (!append("=", 1) || !append(values[i], node->size))
            return false;
    }
    // set_file appends the final newline itself.
    environment[used - 1] = 0;
    auto* endpoint = set_file("uevent", event, sizeof(event), environment);
    if (!endpoint)
        return false;
    if (!published) {
        char target[96];
        if (!inventory_path(target, "../..", path + sizeof("/sys/") - 1) ||
            !inventory_link(path, "subsystem", "../../../../class/power_supply") ||
            !inventory_link(class_path, name, target))
            return false;
        endpoint->mode = regular_file | 0644;
        endpoint->device = Device::power_supply_uevent;
        inventory_device_added(endpoint, false);
        published = true;
    } else {
        inventory_device_changed(endpoint);
    }
    changed = false;
    return true;
}

Supply* supply_for(const char* acpi_name) {
    char name[5];
    memcpy(name, acpi_name, sizeof(name));
    size_t length = strlen(name);
    while (length > 1 && name[length - 1] == '_')
        name[--length] = 0;
    for (auto& entry : supplies) {
        if (!strcmp(entry.name, name))
            return &entry;
        if (entry.name[0])
            continue;
        if (!inventory_path(entry.path, device_path, name) || !inventory_directories(entry.path))
            return nullptr;
        memcpy(entry.name, name, sizeof(name));
        return &entry;
    }
    return nullptr;
}

const char* battery_status(const Acpi::BatteryReading& battery) {
    if (battery.state & 1)
        return "Discharging";
    if (battery.state & 2)
        return "Charging";
    if (!(battery.state & 8) && battery.full_capacity && battery.full_capacity != UINT32_MAX &&
        battery.remaining_capacity != UINT32_MAX &&
        battery.remaining_capacity >= battery.full_capacity)
        return "Full";
    return "Not charging";
}

const char* battery_technology(const char* value) {
    if (!strcmp(value, "Li-I") || !strcmp(value, "LION") || !strcmp(value, "Li-ion"))
        return "Li-ion";
    if (!strcmp(value, "LiP") || !strcmp(value, "Li-poly"))
        return "Li-poly";
    return "Unknown";
}

bool publish_battery(const Acpi::BatteryReading& battery) {
    auto* supply = supply_for(battery.name);
    if (!supply || !supply->set(type, "Battery") || !supply->set(scope, "System") ||
        !supply->set(present, battery.present ? "1" : "0"))
        return false;
    if (!battery.present) {
        supply->set(status, nullptr);
        for (unsigned i = technology; i < sizeof(attribute_names) / sizeof(*attribute_names); ++i)
            supply->set(Attribute(i), nullptr);
        return supply->write_event();
    }
    uint32_t percent = UINT32_MAX;
    if (battery.full_capacity && battery.full_capacity != UINT32_MAX &&
        battery.remaining_capacity != UINT32_MAX)
        percent = uint32_t(
            min(uint64_t(100), uint64_t(battery.remaining_capacity) * 100 / battery.full_capacity));
    const bool charge = battery.unit == 1;
    const auto clear = [&](Attribute field) { return supply->set(field, nullptr); };
    return supply->set(status, battery_status(battery)) &&
           supply->set(technology, battery_technology(battery.technology)) &&
           supply->set(model, battery.model) && supply->set(manufacturer, battery.manufacturer) &&
           supply->set(serial_number, battery.serial) && supply->set_number(capacity, percent) &&
           supply->set_number(voltage_now, battery.voltage, 1000) &&
           supply->set_number(voltage_min_design, battery.design_voltage, 1000) &&
           supply->set_number(charge ? charge_now : energy_now, battery.remaining_capacity, 1000) &&
           supply->set_number(charge ? charge_full : energy_full, battery.full_capacity, 1000) &&
           supply->set_number(charge ? charge_full_design : energy_full_design,
                              battery.design_capacity, 1000) &&
           supply->set_number(charge ? current_now : power_now, battery.rate, 1000) &&
           clear(charge ? energy_now : charge_now) && clear(charge ? energy_full : charge_full) &&
           clear(charge ? energy_full_design : charge_full_design) &&
           clear(charge ? power_now : current_now) && supply->write_event();
}

bool publish_adapter(const Acpi::AcAdapterReading& adapter) {
    auto* supply = supply_for(adapter.name);
    return supply && supply->set(type, "Mains") && supply->set(scope, "System") &&
           supply->set(online, adapter.online ? "1" : "0") && supply->write_event();
}

bool publish_readings(const Acpi::PowerSupplySnapshot& readings) {
    bool ready = true;
    for (unsigned i = 0; i < readings.battery_count; ++i)
        ready = publish_battery(readings.batteries[i]) && ready;
    for (unsigned i = 0; i < readings.adapter_count; ++i)
        ready = publish_adapter(readings.adapters[i]) && ready;
    return ready;
}
} // namespace

void power_supply_refresh() {
    if (!reader || ticks < next_refresh)
        return;
    next_refresh = ticks + refresh_ticks;
    Acpi::PowerSupplySnapshot readings{};
    const bool ready =
        firmware_sample_power_supplies(*reader, readings) && publish_readings(readings);
    if (!ready && !sample_failed)
        log("ACPI power: cannot refresh power-supply devices\n");
    sample_failed = !ready;
}

void power_supply_prepare(const Acpi::DefinitionBlocks& blocks) {
    reader = firmware_open_power_supply_reader(blocks, &startup_failure);
    initial_sample_ready =
        reader && firmware_sample_power_supplies(*reader, initial_readings, true, &startup_failure);
}

void power_supply_init() {
    char class_directory[] = "/sys/class/power_supply";
    if (!inventory_directories(class_directory)) {
        Acpi::close_power_supply_reader(reader);
        reader = nullptr;
        log("ACPI power: cannot initialize the power-supply class\n");
        return;
    }
    const char* initial_status = "ready";
    if (!initial_sample_ready)
        initial_status = startup_failure;
    else if (!initial_readings.battery_count && !initial_readings.adapter_count)
        initial_status = "no battery or adapter";
    else if (!publish_readings(initial_readings))
        initial_status = "device publication failed";
    char firmware_directory[] = "/sys/firmware/acpi";
    if (inventory_directories(firmware_directory))
        inventory_attribute(firmware_directory, "axiom64_power_status", initial_status);
    log("ACPI power: %s batteries=%u adapters=%u\n", initial_status,
        uint64_t(initial_readings.battery_count), uint64_t(initial_readings.adapter_count));
    next_refresh = ticks + refresh_ticks;
}
} // namespace ax::DeviceInventory
