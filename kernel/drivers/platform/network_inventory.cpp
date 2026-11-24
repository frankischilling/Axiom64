// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/network_inventory.cpp
 * @brief   Network device inventory and discovery events.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Publishes interface identity and connects it to the underlying PCI device.
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
#include "drivers/platform/inventory.hpp"
#include "drivers/platform/devices.hpp"
#include "drivers/platform/pci.hpp"
#include "net/ipv4.hpp"

namespace ax::DeviceInventory {
namespace {
constexpr char net_class[] = "/sys/class/net";

bool publish_interface(const NetInfo& info, const char* parent, const char* type) {
    char path[256], target[256], index[16];
    if (!inventory_path(path, parent, info.name) || !inventory_directories(path) ||
        !inventory_path(target, "../..", path + sizeof("/sys/") - 1))
        return false;
    number_path(index, "", info.index);
    char address[18];
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 6; ++i) {
        address[3 * i] = digits[info.mac[i] >> 4];
        address[3 * i + 1] = digits[info.mac[i] & 15];
        address[3 * i + 2] = i == 5 ? 0 : ':';
    }
    char event[64] = "INTERFACE=";
    const size_t offset = strlen(event);
    const size_t name = strlen(info.name);
    memcpy(event + offset, info.name, name);
    number_path(event + offset + name, "\nIFINDEX=", info.index);
    if (info.wireless) {
        constexpr char kind[] = "\nDEVTYPE=wlan";
        memcpy(event + strlen(event), kind, sizeof(kind));
    }
    auto* endpoint = inventory_attribute(path, "uevent", event);
    if (!endpoint || !inventory_attribute(path, "ifindex", index) ||
        !inventory_attribute(path, "iflink", index) || !inventory_attribute(path, "type", type) ||
        !inventory_attribute(path, "address", address) ||
        !inventory_attribute(path, "addr_assign_type", "0") ||
        !inventory_link(path, "subsystem", net_class) ||
        (info.driver && !inventory_link(path, "device", "../..")) ||
        !inventory_link(net_class, info.name, target))
        return false;
    endpoint->mode = regular_file | 0644;
    endpoint->device = Device::network_uevent;
    inventory_device_added(endpoint, false);
    return true;
}

bool publish_pci_parent(const NetInfo& info, const char* path) {
    char driver[128];
    constexpr char drivers[] = "/sys/bus/pci/drivers";
    if (!inventory_path(driver, drivers, info.driver) || !inventory_directories(driver) ||
        !inventory_link(path, "subsystem", "/sys/bus/pci") ||
        !inventory_link(path, "driver", driver) ||
        !inventory_link("/sys/bus/pci/devices", info.bus_address, path))
        return false;
    char event[64] = "DRIVER=";
    constexpr char slot[] = "\nPCI_SLOT_NAME=";
    const size_t offset = strlen(event), name = strlen(info.driver);
    if (offset + name + sizeof(slot) - 1 + sizeof(info.bus_address) > sizeof(event))
        return false;
    memcpy(event + offset, info.driver, name);
    char endpoint_path[256];
    if (!inventory_path(endpoint_path, path, "uevent"))
        return false;
    if (auto endpoint = lookup(endpoint_path, false)) {
        if (endpoint->device != Device::pci_uevent || !endpoint->owned)
            return false;
        const size_t length = offset + name + 1;
        event[length - 1] = '\n';
        if (endpoint->size >= length &&
            !memcmp(endpoint->data + endpoint->size - length, event, length))
            return true;
        const size_t size = endpoint->size + length;
        auto bytes = static_cast<uint8_t*>(alloc(size));
        if (!bytes)
            return false;
        memcpy(bytes, endpoint->data, endpoint->size);
        memcpy(bytes + endpoint->size, event, length);
        release(endpoint->data);
        endpoint->data = bytes;
        endpoint->size = endpoint->capacity = size;
        inventory_device_changed(endpoint);
        return true;
    }
    memcpy(event + offset + name, slot, sizeof(slot) - 1);
    memcpy(event + offset + name + sizeof(slot) - 1, info.bus_address, sizeof(info.bus_address));
    return inventory_attribute(path, "uevent", event);
}
} // namespace

void network_inventory_init() {
    char class_path[] = "/sys/class/net";
    char pci_devices[] = "/sys/bus/pci/devices";
    NetInfo loopback{};
    loopback.index = ipv4_loopback;
    memcpy(loopback.name, "lo", 3);
    if (!inventory_directories(class_path) || !inventory_directories(pci_devices) ||
        !publish_interface(loopback, "/sys/devices/virtual/net", "772"))
        log("net: cannot publish loopback inventory\n");
}

void publish_ethernet(const NetInfo& info, const PciFunction* pci) {
    char device[256], network[256];
    if (!pci || !info.driver || !pci_device_path(*pci, device, sizeof(device)) ||
        !inventory_directories(device) || !publish_pci_parent(info, device) ||
        !inventory_path(network, device, "net") || !publish_interface(info, network, "1"))
        log("net: cannot publish inventory for %s\n", info.name);
}
} // namespace ax::DeviceInventory
