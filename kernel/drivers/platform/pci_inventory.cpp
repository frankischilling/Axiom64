// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/pci_inventory.cpp
 * @brief   Publishes PCI device identities to userspace.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Publishes device identities after the boot drivers finish their setup.
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
#include "drivers/platform/pci_inventory.hpp"
#include "drivers/platform/device_event.hpp"
#include "drivers/platform/pci.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
constexpr char device_root[] = "/sys/devices/pci";
constexpr char bus_devices[] = "/sys/bus/pci/devices";
constexpr size_t address_length = sizeof("0000:00:00.0") - 1;

size_t published;
bool incomplete;

char* append(char* out, const char* suffix) {
    while (*suffix)
        *out++ = *suffix++;
    *out = 0;
    return out;
}

char* hex(char* out, uint32_t value, unsigned width, bool uppercase = false) {
    const char* digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    for (unsigned i = 0; i < width; ++i)
        *out++ = digits[(value >> (4 * (width - i - 1))) & 0xf];
    *out = 0;
    return out;
}

char* address_name(char* out, const PciAddress& address) {
    out = hex(out, address.segment, 4);
    *out++ = ':';
    out = hex(out, address.bus, 2);
    *out++ = ':';
    out = hex(out, address.slot, 2);
    *out++ = '.';
    return hex(out, address.function, 1);
}

bool ensure_directory(const char* path) {
    if (auto node = lookup(path, false))
        return (node->mode & 0170000) == directory;
    return make_node(path, directory | 0755);
}

bool link_at(Node* parent, const char* name, const char* target) {
    Path relative{.base = parent};
    memcpy(relative.text, name, strlen(name) + 1);
    Node* node = nullptr;
    return create_node(relative, symlink | 0777, node, target) == 0;
}

Node* publish_file(Node* parent, const char* name, const void* data, size_t size,
                   unsigned mode = 0444) {
    auto bytes = static_cast<uint8_t*>(alloc(size));
    if (!bytes)
        return nullptr;
    Path relative{.base = parent};
    memcpy(relative.text, name, strlen(name) + 1);
    Node* node = nullptr;
    if (create_node(relative, regular_file | mode, node)) {
        release(bytes);
        return nullptr;
    }
    memcpy(bytes, data, size);
    node->data = bytes;
    node->size = node->capacity = size;
    node->owned = true;
    return node;
}

bool publish_hex(Node* parent, const char* name, uint32_t value, unsigned width) {
    char line[9];
    auto end = hex(append(line, "0x"), value, width);
    *end++ = '\n';
    return publish_file(parent, name, line, end - line);
}

Node* canonical_device(const PciAddress& address, char (&path)[sizeof(Path::text)]) {
    constexpr size_t root_length = sizeof(device_root) - 1 + sizeof("0000:00") - 1;
    PciAddress chain[(sizeof(path) - root_length - 1) / (address_length + 1)];
    size_t depth = 1;
    chain[0] = address;
    PciAddress parent{};
    for (;;) {
        const auto result = pci_bus_parent(address.segment, chain[depth - 1].bus, parent);
        if (result == PciBusParent::root)
            break;
        if (result == PciBusParent::ambiguous || depth == sizeof(chain) / sizeof(*chain))
            return nullptr;
        chain[depth++] = parent;
    }

    auto end = hex(append(path, device_root), address.segment, 4);
    *end++ = ':';
    end = hex(end, chain[depth - 1].bus, 2);
    if (!ensure_directory(path))
        return nullptr;
    while (depth) {
        *end++ = '/';
        end = address_name(end, chain[--depth]);
        if (!ensure_directory(path))
            return nullptr;
    }
    return lookup(path, false);
}

uint32_t dword(const uint8_t* config, unsigned offset) {
    uint32_t value;
    memcpy(&value, config + offset, sizeof(value));
    return value;
}

bool publish_function(const PciFunction& function) {
    const auto identity = function.read32(0);
    const auto header = function.read8(0x0e) & 0x7f;
    if (uint16_t(identity) == UINT16_MAX || header > 2)
        return true;

    uint8_t config[128];
    const unsigned config_size = header == 2 ? sizeof(config) : 64;
    for (unsigned offset = 0; offset < config_size; offset += 4) {
        const auto word = function.read32(offset);
        memcpy(config + offset, &word, sizeof(word));
    }

    if (dword(config, 0) != identity || (config[0x0e] & 0x7f) != header)
        return false;
    const auto vendor = uint16_t(identity);
    const auto device = uint16_t(identity >> 16);
    const uint32_t class_revision = dword(config, 8);
    uint32_t subsystem = 0;
    if (header != 1)
        subsystem = dword(config, header == 2 ? 0x40 : 0x2c);
    else {
        unsigned boundary;
        const unsigned capability = function.find_capability(0x0d, &boundary);
        if (capability && capability + 8 <= boundary)
            subsystem = function.read32(capability + 4);
    }

    const PciAddress address{function.segment, function.bus, function.slot, function.function};
    char name[address_length + 1];
    address_name(name, address);
    char path[sizeof(Path::text)];
    auto node = canonical_device(address, path);
    if (!node)
        return false;
    char modalias[64];
    auto end = hex(append(modalias, "pci:v"), vendor, 8, true);
    end = hex(append(end, "d"), device, 8, true);
    end = hex(append(end, "sv"), uint16_t(subsystem), 8, true);
    end = hex(append(end, "sd"), uint16_t(subsystem >> 16), 8, true);
    end = hex(append(end, "bc"), uint8_t(class_revision >> 24), 2, true);
    end = hex(append(end, "sc"), uint8_t(class_revision >> 16), 2, true);
    end = hex(append(end, "i"), uint8_t(class_revision >> 8), 2, true);
    *end++ = '\n';

    if (!publish_hex(node, "vendor", vendor, 4) || !publish_hex(node, "device", device, 4) ||
        !publish_hex(node, "class", class_revision >> 8, 6) ||
        !publish_hex(node, "revision", uint8_t(class_revision), 2) ||
        !publish_hex(node, "subsystem_vendor", uint16_t(subsystem), 4) ||
        !publish_hex(node, "subsystem_device", uint16_t(subsystem >> 16), 4) ||
        !publish_file(node, "modalias", modalias, end - modalias) ||
        !publish_file(node, "config", config, config_size) ||
        !link_at(node, "subsystem", "/sys/bus/pci") || !link_at(lookup(bus_devices), name, path))
        return false;
    char properties[200];
    const unsigned class_code = class_revision >> 8;
    auto property = hex(append(properties, "SUBSYSTEM=pci\nPCI_CLASS="), class_code,
                        class_code > 0xfffff  ? 6
                        : class_code > 0xffff ? 5
                                              : 4,
                        true);
    property = hex(append(property, "\nPCI_ID="), vendor, 4, true);
    property = hex(append(property, ":"), device, 4, true);
    property = hex(append(property, "\nPCI_SUBSYS_ID="), uint16_t(subsystem), 4, true);
    property = hex(append(property, ":"), uint16_t(subsystem >> 16), 4, true);
    property = append(append(property, "\nPCI_SLOT_NAME="), name);
    property = append(property, "\nMODALIAS=");
    memcpy(property, modalias, end - modalias);
    auto uevent =
        publish_file(node, "uevent", properties, property - properties + (end - modalias), 0644);
    if (!uevent || publish_device_event(uevent))
        return false;
    ++published;
    return true;
}
} // namespace

void publish_pci_inventory() {
    constexpr const char* directories[] = {"/sys", "/sys/bus", "/sys/bus/pci", bus_devices,
                                           "/sys/devices"};
    for (auto path : directories)
        if (!ensure_directory(path)) {
            log("PCI inventory: cannot create %s\n", path);
            return;
        }
    pci_scan([](const PciFunction& function) { incomplete |= !publish_function(function); });
    log("PCI inventory: %u devices%s\n", uint64_t(published), incomplete ? " (incomplete)" : "");
}
} // namespace ax
