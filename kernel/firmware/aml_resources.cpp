// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml_resources.cpp
 * @brief   Evaluates ACPI interrupt, PCI and HID resources.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Exports resources for platform discovery and PCI interrupt routing.
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
#include "aml_internal.hpp"

namespace ax::Acpi::Aml {

bool resource_payload(Cursor resources, size_t& length) {
    length = 0;
    if (!resources.left)
        return true;
    const auto original = resources;
    while (resources.left) {
        const auto* start = resources.next;
        const unsigned tag = resources.peek();
        resources.skip(1);
        uint64_t size = tag & 7;
        Cursor item;
        if (((tag & 0x80) && !resources.read(2, size)) || !resources.take(size, item))
            return false;
        if ((tag & 0xf8) != 0x78)
            continue;
        if (tag != 0x79)
            return false;
        const size_t payload = start - original.next;
        if (item.peek()) {
            uint8_t sum = 0;
            for (size_t i = 0; i < payload + 2; ++i)
                sum += original.next[i];
            if (sum)
                return false;
        }
        while (resources.left) {
            if (resources.peek())
                return false;
            resources.skip(1);
        }
        length = payload;
        return true;
    }
    return false;
}

bool interrupt_resource(Cursor resources, uint64_t index, PciPinRoute& route) {
    const Cursor original = resources;
    bool found = false;
    while (resources.left) {
        unsigned tag = resources.peek();
        resources.skip(1);
        uint64_t length = tag & 7;
        if ((tag & 0x80) && !resources.read(2, length))
            return false;
        Cursor item;
        if (!resources.take(length, item))
            return false;
        if (tag == 0x79) { // EndTag
            if (!found || resources.left)
                return false;
            if (!item.peek())
                return true;
            uint8_t sum = 0;
            for (size_t i = 0; i < original.left; ++i)
                sum += original.next[i];
            return !sum;
        }
        if (found)
            continue;
        if (index) {
            --index;
            continue;
        }
        uint64_t flags, irq;
        if (tag == 0x89) { // Extended Interrupt
            uint64_t count;
            if (!item.read(1, flags) || !item.read(1, count) || count != 1 || !item.read(4, irq) ||
                !(flags & 1))
                return false;
            route.gsi = irq;
            route.active_low = flags & 4;
            route.level = !(flags & 2);
            route.shared = flags & 8;
        } else if (tag == 0x22 || tag == 0x23) { // IRQ
            flags = 1;
            if (!item.read(2, irq) || !irq || (irq & (irq - 1)) ||
                (tag == 0x23 && !item.read(1, flags)))
                return false;
            route.gsi = __builtin_ctz(unsigned(irq));
            route.active_low = flags & 8;
            route.level = !(flags & 1);
            route.shared = flags & 16;
        } else {
            return false;
        }
        found = true;
    }
    return false;
}

// A programmable PIIX link uses an extended interrupt descriptor for
// shared, active-high, level-triggered IRQs.
uint8_t select_link_gsi(Cursor resources, uint32_t allowed) {
    const Cursor original = resources;
    uint64_t size, flags, count;
    if (resources.peek() != 0x89 || !resources.skip(1) || !resources.read(2, size) ||
        !resources.read(1, flags) || flags != 9 || !resources.read(1, count) || !count ||
        count > 32 || size != 2 + count * 4)
        return 0;

    uint32_t possible = 0;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t gsi;
        if (!resources.read(4, gsi))
            return 0;
        if (gsi < 32)
            possible |= 1u << gsi;
    }
    if (resources.left != 2 || resources.next[0] != 0x79)
        return 0;
    if (resources.next[1]) {
        uint8_t sum = 0;
        for (size_t i = 0; i < original.left; ++i)
            sum += original.next[i];
        if (sum)
            return 0;
    }
    constexpr uint8_t preference[]{10, 11, 5};
    for (auto gsi : preference)
        if (possible & allowed & (1u << gsi))
            return gsi;
    return 0;
}

bool restore_link(Namespace& space, const Object& device, uint64_t index, PciPinRoute& route) {
    if (!space.link_program.write || !space.link_program.allowed_gsis || index || !route.level ||
        route.active_low || !route.shared ||
        space.change_count == sizeof(space.changes) / sizeof(*space.changes))
        return false;

    Value id{}, possible{}, state{};
    const auto* method = space.child(device.path, name_segment("_SRS"));
    if (!method || !space.config(device.path, name_segment("_HID"), id) ||
        id.type != Type::Integer || id.number != 0x0f0cd041 ||
        !space.config(device.path, name_segment("_PRS"), possible) || possible.type != Type::Buffer)
        return false;
    const auto* sta = space.child(device.path, name_segment("_STA"));
    if (sta && (!space.config(device.path, name_segment("_STA"), state) ||
                state.type != Type::Integer || (state.number & 3) != 1))
        return false;

    const auto selected = select_link_gsi(possible.content, space.link_program.allowed_gsis);
    if (!selected)
        return false;

    uint8_t setting[]{0x89, 6, 0, 9, 1, selected, 0, 0, 0, 0x79, 0};
    Value argument{Type::Buffer, 0, {setting, sizeof(setting)}, nullptr, nullptr, setting};
    Value ignored{};
    unsigned initial_changes = space.change_count;
    space.programming_gsi = selected;
    space.change_emitted = false;
    bool executed = space.method(*method, &argument, 1, ignored);
    space.programming_gsi = 0;

    // Read through the staged field and require firmware to report exactly what was requested.
    Value current{};
    state = {};
    auto verified = route;
    if (!executed || space.change_count != initial_changes + 1 ||
        !space.config(device.path, name_segment("_CRS"), current) || current.type != Type::Buffer ||
        !interrupt_resource(current.content, index, verified) || verified.gsi != selected ||
        !verified.level || verified.active_low || !verified.shared ||
        (sta && (!space.config(device.path, name_segment("_STA"), state) ||
                 state.type != Type::Integer || (state.number & 3) != 3))) {
        space.change_count = initial_changes;
        return false;
    }
    route = verified;
    return true;
}

bool string_name(Cursor text, Name& name) {
    name = {};
    if (text.peek() == root_prefix) {
        name.absolute = true;
        text.skip(1);
    }
    while (!name.absolute && text.peek() == parent_prefix) {
        text.skip(1);
        ++name.parents;
    }
    while (text.left) {
        if (name.path.count == max_depth)
            return false;
        uint32_t segment = 0;
        unsigned i = 0;
        while (text.left && text.peek() != '.') {
            unsigned letter = text.peek();
            if (i == 4 || !name_character(letter, i == 0))
                return false;
            text.skip(1);
            segment |= uint32_t(letter) << (8 * i++);
        }
        if (!i)
            return false;
        while (i < 4)
            segment |= uint32_t('_') << (8 * i++);
        name.path.segments[name.path.count++] = segment;
        if (text.left && (!text.skip(1) || !text.left))
            return false;
    }
    return name.path.count;
}

bool copy_resource_path(Cursor path, char (&destination)[82]) {
    Name source{};
    if (path.left < 2 || path.left > sizeof(destination) || path.next[path.left - 1] ||
        !string_name({path.next, path.left - 1}, source))
        return false;
    memcpy(destination, path.next, path.left);
    return true;
}

bool i2c_line_interrupt(unsigned tag, Cursor item, I2cHidInterrupt& irq) {
    using Polarity = I2cHidInterrupt::Polarity;
    using Source = I2cHidInterrupt::Source;
    uint64_t flags, line;
    if (tag == 0x89) {
        uint64_t count;
        // A named producer needs routing in that controller's domain.
        if (!item.read(1, flags) || (flags & 0xe0) || !(flags & 1) || !item.read(1, count) ||
            count != 1 || !item.read(4, line) || item.left || line == UINT32_MAX)
            return false;
        irq = {};
        irq.source = Source::gsi;
        irq.line = line;
        irq.polarity = flags & 4 ? Polarity::active_low : Polarity::active_high;
        irq.edge = flags & 2;
        irq.shared = flags & 8;
        irq.wake = flags & 16;
        return true;
    }
    flags = 1;
    if (!item.read(2, line) || !line || (line & (line - 1)) ||
        (tag == 0x23 &&
         (!item.read(1, flags) || (flags & 0xc0) || ((flags & 9) != 1 && (flags & 9) != 8))))
        return false;
    irq = {};
    irq.source = Source::legacy_irq;
    irq.line = __builtin_ctz(unsigned(line));
    irq.polarity = flags & 8 ? Polarity::active_low : Polarity::active_high;
    irq.edge = flags & 1;
    irq.shared = flags & 16;
    irq.wake = flags & 32;
    return true;
}

bool i2c_gpio_interrupt(Cursor item, I2cHidInterrupt& irq) {
    using Polarity = I2cHidInterrupt::Polarity;
    uint64_t revision, type, general, flags, pull, debounce, pins, index, source, vendor, size;
    const auto* descriptor = item.next - 3;
    const size_t length = item.left + 3;
    if (!item.read(1, revision) || revision != 1 || !item.read(1, type) || type != 0 ||
        !item.read(2, general) || general != 1 || !item.read(2, flags) || (flags & ~0x1fu) ||
        !item.read(1, pull) || (pull > 3 && pull < 0x80) || !item.skip(2) ||
        !item.read(2, debounce) || !item.read(2, pins) || !item.read(1, index) || index ||
        !item.read(2, source) || !item.read(2, vendor) || !item.read(2, size) || pins < 23 ||
        source <= pins || ((source - pins) & 1) || vendor <= source || vendor > length ||
        size != length - vendor)
        return false;
    const unsigned polarity = (flags >> 1) & 3;
    if (polarity == 3 || (polarity == 2 && !(flags & 1)))
        return false;
    Cursor pin_table{descriptor + pins, source - pins};
    uint64_t pin;
    do {
        if (!pin_table.read(2, pin))
            return false;
    } while (pin == UINT16_MAX);
    if (!copy_resource_path({descriptor + source, vendor - source}, irq.gpio_controller))
        return false;
    irq.source = I2cHidInterrupt::Source::gpio;
    irq.line = pin;
    irq.polarity = Polarity(polarity);
    irq.edge = flags & 1;
    irq.shared = flags & 8;
    irq.wake = flags & 16;
    irq.gpio_pull = pull;
    irq.gpio_debounce = debounce;
    return true;
}

bool i2c_connection(Cursor resources, I2cHidDevice& device) {
    const Cursor original = resources;
    bool found = false;
    using Source = I2cHidInterrupt::Source;
    while (resources.left) {
        const unsigned tag = resources.peek();
        resources.skip(1);
        uint64_t length = tag & 7;
        Cursor item;
        if (((tag & 0x80) && !resources.read(2, length)) || !resources.take(length, item))
            return false;
        if (tag == 0x79) {
            uint8_t sum = 0;
            if (item.peek())
                for (size_t i = 0; i < original.left; ++i)
                    sum += original.next[i];
            return found && !resources.left && !sum;
        }
        // Prefer the first usable direct IRQ. GPIO is the fallback.
        if (tag == 0x89 || tag == 0x22 || tag == 0x23) {
            if (device.interrupt.source == Source::none || device.interrupt.source == Source::gpio)
                i2c_line_interrupt(tag, item, device.interrupt);
            continue;
        }
        if (tag == 0x8c) {
            if (device.interrupt.source == Source::none)
                i2c_gpio_interrupt(item, device.interrupt);
            continue;
        }
        if (tag != 0x8e) // Generic Serial Bus connection.
            continue;
        uint64_t revision, index, type;
        if (!item.read(1, revision) || !item.read(1, index) || !item.read(1, type))
            return false;
        if (type != 1)
            continue;
        uint64_t flags, mode, version, data_size, speed, address;
        Cursor bus;
        if (found || (revision != 1 && revision != 2) || !item.read(1, flags) || (flags & ~6u) ||
            !item.read(2, mode) || mode > 1 || !item.read(1, version) || version != 1 ||
            !item.read(2, data_size) || !item.take(data_size, bus) || !bus.read(4, speed) ||
            !speed || !bus.read(2, address) || address > (mode ? 0x3ffu : 0x7fu) ||
            !copy_resource_path(item, device.controller))
            return false;
        device.source_index = index;
        device.ten_bit = mode != 0;
        device.max_hz = speed;
        device.address = address;
        found = true;
    }
    return false;
}

bool i2c_hid_id(const Value& id) {
    if (id.type == Type::Integer)
        return id.number == 0x500cd041; // PNP0C50 EISA ID.
    return id.type == Type::String &&
           ((id.content.left == 7 && !memcmp(id.content.next, "PNP0C50", 7)) ||
            (id.content.left == 8 && !memcmp(id.content.next, "ACPI0C50", 8)));
}

bool i2c_hid_compatible(const Value& compatible) {
    if (compatible.type != Type::Package)
        return i2c_hid_id(compatible);
    for (unsigned i = 0; i < compatible.number; ++i)
        if (i2c_hid_id(compatible.entries[i]))
            return true;
    return false;
}

bool i2c_hid_identity(Namespace& space, const Path& path, Value& id) {
    Value compatible{};
    return space.config(path, name_segment("_HID"), id) &&
           (i2c_hid_id(id) || (space.config(path, name_segment("_CID"), compatible) &&
                               i2c_hid_compatible(compatible)));
}

bool device_status(Namespace& space, const Path& path, uint64_t& flags) {
    flags = 0x0f;
    if (!space.child(path, name_segment("_STA")))
        return true;
    Value status{};
    if (!space.config(path, name_segment("_STA"), status) || status.type != Type::Integer)
        return false;
    flags = status.number;
    return true;
}

enum class InitResult { ready, absent, rejected };

InitResult replay_hid_initialization(Namespace& space, const Path& path) {
    space.replay_initialization = true;
    Path scope = path;
    for (unsigned depth = 0; depth <= path.count; ++depth) {
        scope.count = depth;
        const auto* node = space.find(scope);
        uint64_t flags = 0x0f;
        if (node && node->kind == Kind::Device && !device_status(space, scope, flags))
            return InitResult::rejected;
        if (!(flags & 1)) {
            // A functional parent may expose children even when it has no resources.
            if ((flags & 8) && depth != path.count)
                continue;
            return InitResult::absent;
        }
        if (const auto* method = space.child(scope, name_segment("_INI"))) {
            Value ignored{};
            if (!space.method(*method, nullptr, 0, ignored))
                return InitResult::rejected;
        }
        space.used_values = 0;
        space.used_bytes = 0;
    }
    return InitResult::ready;
}

bool i2c_hid_device(Namespace& space, const Object& object, I2cHidDevice& device) {
    Value id{}, resources{};
    uint64_t status;
    if (!i2c_hid_identity(space, object.path, id) || !device_status(space, object.path, status) ||
        !(status & 1) || !space.config(object.path, name_segment("_CRS"), resources) ||
        resources.type != Type::Buffer || !i2c_connection(resources.content, device))
        return false;
    if (id.type == Type::String && id.content.left < sizeof(device.hardware_id))
        memcpy(device.hardware_id, id.content.next, id.content.left);
    else
        memcpy(device.hardware_id, "PNP0C50", 7);

    Name bus{};
    if (string_name(
            {reinterpret_cast<const uint8_t*>(device.controller), strlen(device.controller)},
            bus)) {
        const auto* controller = space.lookup(object.path, bus);
        ConfigField location{};
        if (controller && space.pci_address(controller->path, location))
            device.pci_controller = {location.segment, location.bus, location.slot,
                                     location.function, true};
    }

    // HID-over-I2C _DSM function 1 returns the descriptor register.
    constexpr uint8_t guid[]{0xf7, 0xf6, 0xdf, 0x3c, 0x67, 0x42, 0x55, 0x45,
                             0xad, 0x05, 0xb3, 0x0a, 0x3d, 0x89, 0x38, 0xde};
    Value arguments[]{{Type::Buffer, 0, {guid, sizeof(guid)}, nullptr},
                      {Type::Integer, 1, {}, nullptr},
                      {Type::Integer, 1, {}, nullptr},
                      {Type::Package, 0, {}, nullptr}};
    Value descriptor{};
    if (const auto method = space.child(object.path, name_segment("_DSM"));
        method && space.method(*method, arguments, 4, descriptor) &&
        descriptor.type == Type::Integer && descriptor.number <= UINT16_MAX) {
        device.descriptor_register = descriptor.number;
        device.has_descriptor_register = true;
    }
    return true;
}

bool route_package(Namespace& space, Value package, unsigned segment, unsigned bus,
                   PciPinRoutes& result) {
    if (package.type != Type::Package || package.number > 256)
        return false;
    for (unsigned i = 0; i < package.number; ++i) {
        const auto& row = package.entries[i];
        if (row.type != Type::Package || row.number != 4)
            return false;
        const auto& address = row.entries[0];
        const auto& pin = row.entries[1];
        const auto& source = row.entries[2];
        const auto& index = row.entries[3];
        if (address.type != Type::Integer || address.number >> 16 >= 32 ||
            pin.type != Type::Integer || pin.number >= 4 || index.type != Type::Integer)
            return false;
        unsigned function = address.number & 0xffff;
        if (function >= 8 && function != 0xffff)
            return false;
        PciPinRoute route{0,
                          uint16_t(segment),
                          uint8_t(bus),
                          uint8_t(address.number >> 16),
                          uint8_t(function),
                          uint8_t(pin.number + 1),
                          true,
                          true,
                          true};
        if (source.type == Type::Integer && !source.number && index.number <= UINT32_MAX) {
            route.gsi = index.number;
        } else {
            const Object* device = source.object;
            if (source.type == Type::String) {
                Name name;
                if (!string_name(source.content, name))
                    return false;
                device = space.lookup(row.object ? row.object->path : Path{}, name);
            }
            Value crs{};
            unsigned values = space.used_values, bytes = space.used_bytes;
            bool valid = device && device->kind == Kind::Device &&
                         space.config(device->path, name_segment("_CRS"), crs) &&
                         crs.type == Type::Buffer &&
                         interrupt_resource(crs.content, index.number, route);
            if (valid && !route.gsi) {
                space.link_evaluation = true;
                restore_link(space, *device, index.number, route);
                space.link_evaluation = false;
            }
            space.used_values = values;
            space.used_bytes = bytes;
            if (!valid)
                return false;
            if (!route.gsi)
                continue;
        }
        if (result.count == sizeof(result.entries) / sizeof(*result.entries))
            return false;
        result.entries[result.count++] = route;
    }
    return true;
}

bool scope_routes(Namespace& space, const Path& scope, uint16_t segment, uint8_t bus,
                  PciPinRoutes& output) {
    if (!space.child(scope, name_segment("_PRT")))
        return true;
    space.used_values = 0;
    space.used_bytes = 0;
    Value routes{};
    const auto first_change = space.change_count;
    if (space.config(scope, name_segment("_PRT"), routes) &&
        route_package(space, routes, segment, bus, output))
        return true;
    space.change_count = first_change;
    return false;
}

void bridge_routes(Namespace& space, const Path& scope, uint16_t segment, uint8_t bus,
                   uint8_t subordinate, PciBridges& bridges, bool* bound, PciPinRoutes& output) {
    for (unsigned i = 0; i < space.count; ++i) {
        const auto& device = space.objects[i];
        Value address{};
        if (device.kind != Kind::Device || device.path.count != scope.count + 1 ||
            !match(parent(device.path), scope) ||
            !space.config(device.path, name_segment("_ADR"), address) ||
            address.type != Type::Integer || address.number >> 16 >= 32)
            continue;
        unsigned function = address.number & 0xffff;
        if (function >= 8 && function != UINT16_MAX)
            continue;
        for (unsigned j = 0; j < bridges.count; ++j) {
            auto& bridge = bridges.entries[j];
            if (bridge.segment != segment || bridge.primary != bus ||
                bridge.slot != (address.number >> 16) ||
                (function != UINT16_MAX && bridge.function != function) ||
                bridge.subordinate > subordinate ||
                parent_bridge(bridges, segment, bridge.secondary).bridge != &bridge)
                continue;
            if (bound[j]) {
                bridge.routing_rejected = true;
                continue;
            }
            bound[j] = true;
            unsigned first = output.count;
            if (!scope_routes(space, device.path, segment, bridge.secondary, output)) {
                output.count = first;
                bridge.routing_rejected = true;
            }
            bridge_routes(space, device.path, segment, bridge.secondary, bridge.subordinate,
                          bridges, bound, output);
        }
    }
}

bool routing(Namespace& space, PciPinRoutes& output, PciBridges* bridges) {
    if (auto pic = space.child({}, name_segment("_PIC"))) {
        Value mode{Type::Integer, 1, {}, nullptr}, ignored{};
        if (!space.method(*pic, &mode, 1, ignored))
            return false;
    }
    bool bound[256]{};
    for (unsigned i = 0; i < space.count; ++i) {
        const auto& device = space.objects[i];
        Value hid{};
        if (device.kind != Kind::Device || !space.config(device.path, name_segment("_HID"), hid) ||
            !pci_root_id(hid))
            continue;
        Value seg{Type::Integer, 0, {}, nullptr}, bus = seg;
        if ((space.child(device.path, name_segment("_SEG")) &&
             !space.config(device.path, name_segment("_SEG"), seg)) ||
            (space.child(device.path, name_segment("_BBN")) &&
             !space.config(device.path, name_segment("_BBN"), bus)) ||
            seg.type != Type::Integer || seg.number > UINT16_MAX || bus.type != Type::Integer ||
            bus.number > UINT8_MAX)
            return false;
        if (!scope_routes(space, device.path, seg.number, bus.number, output))
            return false;
        if (bridges && !bridges->overflow)
            bridge_routes(space, device.path, seg.number, bus.number, UINT8_MAX, *bridges, bound,
                          output);
    }
    return output.count != 0;
}

struct AddressResource {
    uint64_t type, general, flags;
    uint64_t granularity, minimum, maximum, translation, length, attributes;
};

bool address_resource_tag(unsigned tag) {
    return tag == 0x87 || tag == 0x88 || tag == 0x8a || tag == 0x8b;
}

bool read_address_resource(unsigned tag, Cursor item, AddressResource& address) {
    const unsigned width = tag == 0x87 ? 4 : tag == 0x88 ? 2 : 8;
    if (!item.read(1, address.type) || !item.read(1, address.general) ||
        !item.read(1, address.flags))
        return false;
    if (tag == 0x8b) {
        uint64_t revision;
        if (!item.read(2, revision) || revision != 1)
            return false;
    }
    return item.read(width, address.granularity) && item.read(width, address.minimum) &&
           item.read(width, address.maximum) && item.read(width, address.translation) &&
           item.read(width, address.length) &&
           (tag != 0x8b || (item.read(8, address.attributes) && !item.left));
}

bool accept_root_window(unsigned tag, Cursor item, uint16_t segment, uint8_t bus,
                        PciRootWindows& windows) {
    if (!address_resource_tag(tag))
        return true;
    AddressResource address{};
    if (!read_address_resource(tag, item, address))
        return false;
    const auto& [type, general, flags, granularity, minimum, maximum, translation, length,
                 attributes] = address;
    const bool extended = tag == 0x8b;
    // Only Extended Address Space defines the consumer bit on a PCI root bridge.
    if (type || (general & ~1u) != 0x0c || (extended && (general & 1)) || (flags & 0xf9) != 1 ||
        !length || granularity || translation)
        return true;
    if (maximum < minimum || maximum - minimum != length - 1 ||
        windows.count == sizeof(windows.entries) / sizeof(*windows.entries))
        return false;
    const bool prefetchable = extended ? attributes & 2 : flags & 6;
    windows.entries[windows.count++] = {minimum, length, segment, bus, prefetchable};
    return true;
}

bool root_windows(Cursor resources, uint16_t segment, uint8_t bus, PciRootWindows& output) {
    const auto original = resources;
    while (resources.left) {
        unsigned tag = resources.peek();
        resources.skip(1);
        uint64_t length = tag & 7;
        Cursor item;
        if (((tag & 0x80) && !resources.read(2, length)) || !resources.take(length, item))
            return false;
        if (tag == 0x79) {
            uint8_t sum = 0;
            if (item.peek())
                for (size_t i = 0; i < original.left; ++i)
                    sum += original.next[i];
            return !resources.left && !sum;
        }
        if (!accept_root_window(tag, item, segment, bus, output))
            return false;
    }
    return false;
}

bool pci_root_windows(Namespace& space, PciRootWindows& output) {
    for (unsigned i = 0; i < space.count; ++i) {
        const auto& device = space.objects[i];
        Value hid{}, resources{}, status{}, segment{Type::Integer, 0, {}, nullptr}, bus = segment;
        if (device.kind != Kind::Device || !space.config(device.path, name_segment("_HID"), hid) ||
            !pci_root_id(hid) || !space.child(device.path, name_segment("_CRS")))
            continue;
        const unsigned values = space.used_values, bytes = space.used_bytes;
        if (space.child(device.path, name_segment("_STA"))) {
            if (!space.config(device.path, name_segment("_STA"), status) ||
                status.type != Type::Integer)
                return false;
            if (!(status.number & 1)) {
                space.used_values = values;
                space.used_bytes = bytes;
                continue;
            }
        }
        if ((space.child(device.path, name_segment("_SEG")) &&
             !space.config(device.path, name_segment("_SEG"), segment)) ||
            (space.child(device.path, name_segment("_BBN")) &&
             !space.config(device.path, name_segment("_BBN"), bus)) ||
            segment.type != Type::Integer || segment.number > UINT16_MAX ||
            bus.type != Type::Integer || bus.number > UINT8_MAX ||
            !space.config(device.path, name_segment("_CRS"), resources) ||
            resources.type != Type::Buffer ||
            !root_windows(resources.content, segment.number, bus.number, output))
            return false;
        space.used_values = values;
        space.used_bytes = bytes;
    }
    return output.count != 0;
}

bool add_motherboard_range(MotherboardResources& result, uint64_t base, uint64_t size) {
    if (!size)
        return true;
    if (size > UINT64_MAX - base || result.count == sizeof(result.memory) / sizeof(*result.memory))
        return false;
    result.memory[result.count++] = {base, size};
    return true;
}

bool reserve_motherboard_item(unsigned tag, Cursor item, MotherboardResources& result) {
    if (tag == 0x86) { // Memory32Fixed
        uint64_t base, length;
        return item.skip(1) && item.read(4, base) && item.read(4, length) && !item.left &&
               length <= (1ull << 32) - base && add_motherboard_range(result, base, length);
    }
    if (tag == 0x81 || tag == 0x85) { // Memory24 and Memory32
        const unsigned width = tag == 0x81 ? 2 : 4;
        const unsigned shift = tag == 0x81 ? 8 : 0;
        uint64_t minimum, maximum, length;
        if (!item.skip(1) || !item.read(width, minimum) || !item.read(width, maximum) ||
            !item.skip(width) || !item.read(width, length) || item.left)
            return false;
        if (!length)
            return true;
        // Minimum and maximum describe possible base addresses.
        return maximum >= minimum && length <= (1ull << (8 * width)) - maximum &&
               add_motherboard_range(result, minimum << shift,
                                     (maximum - minimum + length) << shift);
    }
    if (!address_resource_tag(tag))
        return true;
    AddressResource address{};
    if (!read_address_resource(tag, item, address))
        return false;
    if (address.type || !address.length)
        return true;
    if (address.maximum < address.minimum || address.maximum == UINT64_MAX)
        return false;
    const uint64_t span = address.maximum - address.minimum + 1;
    if (address.length > span || address.translation > UINT64_MAX - address.maximum)
        return false;
    return add_motherboard_range(result, address.minimum + address.translation, span);
}

bool motherboard_ranges(Cursor resources, MotherboardResources& result) {
    size_t payload;
    if (!resource_payload(resources, payload))
        return false;
    resources.left = payload;
    while (resources.left) {
        const unsigned tag = resources.peek();
        resources.skip(1);
        uint64_t length = tag & 7;
        Cursor item;
        if (((tag & 0x80) && !resources.read(2, length)) || !resources.take(length, item) ||
            !reserve_motherboard_item(tag, item, result))
            return false;
    }
    return true;
}

bool motherboard_id(Value id) {
    if (id.type == Type::Integer)
        return id.number == 0x010cd041 || id.number == 0x020cd041;
    return id.type == Type::String && id.content.left == 7 &&
           !memcmp(id.content.next, "PNP0C0", 6) &&
           (id.content.next[6] == '1' || id.content.next[6] == '2');
}

bool motherboard_compatible(Value id) {
    if (id.type != Type::Package)
        return motherboard_id(id);
    for (unsigned i = 0; i < id.number; ++i)
        if (motherboard_id(id.entries[i]))
            return true;
    return false;
}

bool collect_motherboard_device(Namespace& space, const Object& device,
                                MotherboardResources& result) {
    const auto& path = device.path;
    Value id{}, compatible{}, status{}, current{};
    if (space.child(path, name_segment("_HID")) && !space.config(path, name_segment("_HID"), id))
        return false;
    if (!motherboard_id(id)) {
        if (!space.child(path, name_segment("_CID")))
            return true;
        if (!space.config(path, name_segment("_CID"), compatible))
            return false;
        if (!motherboard_compatible(compatible))
            return true;
    }
    if (space.child(path, name_segment("_STA"))) {
        if (!space.config(path, name_segment("_STA"), status) || status.type != Type::Integer)
            return false;
        if (!(status.number & 1))
            return true;
    }
    return space.config(path, name_segment("_CRS"), current) && current.type == Type::Buffer &&
           motherboard_ranges(current.content, result);
}

const PciPinRoute* bus_route(const PciPinRoutes& routes, uint16_t segment, uint8_t bus,
                             uint8_t slot, uint8_t function, uint8_t pin, bool& ambiguous) {
    const PciPinRoute* exact = nullptr;
    const PciPinRoute* wildcard = nullptr;
    for (unsigned i = 0; i < routes.count; ++i) {
        const auto& route = routes.entries[i];
        if (route.segment != segment || route.bus != bus || route.slot != slot || route.pin != pin)
            continue;
        if (route.function == function) {
            if (exact) {
                ambiguous = true;
                return nullptr;
            }
            exact = &route;
        } else if (route.function == UINT8_MAX) {
            if (wildcard) {
                ambiguous = true;
                return nullptr;
            }
            wildcard = &route;
        }
    }
    return exact ? exact : wildcard;
}

} // namespace ax::Acpi::Aml

namespace ax::Acpi {
using namespace Aml;

bool decode_pci_root_windows(const DefinitionBlocks& blocks, PciRootWindows& result,
                             ReadRegions regions) {
    result.count = 0;
    auto* space = load_namespace(blocks, regions.bridges, regions.pci, {}, regions.nvs);
    if (!space)
        return false;
    const bool ok = pci_root_windows(*space, result);
    release(space);
    if (!ok)
        result.count = 0;
    return ok;
}

bool decode_motherboard_resources(const DefinitionBlocks& blocks, MotherboardResources& result,
                                  ReadRegions regions) {
    result.count = 0;
    result.incomplete = false;
    auto* space = load_namespace(blocks, regions.bridges, regions.pci, {}, regions.nvs);
    if (!space) {
        result.incomplete = true;
        return false;
    }
    for (unsigned i = 0; i < space->count; ++i) {
        const auto& device = space->objects[i];
        if (device.kind != Kind::Device || !space->child(device.path, name_segment("_CRS")))
            continue;
        const unsigned values = space->used_values, bytes = space->used_bytes;
        const unsigned count = result.count;
        if (!collect_motherboard_device(*space, device, result)) {
            result.incomplete = true;
            result.count = count;
        }
        space->used_values = values;
        space->used_bytes = bytes;
    }
    release(space);
    return true;
}

bool decode_intel_gpio_resources(const DefinitionBlocks& blocks, IntelGpioResources& result,
                                 ReadRegions regions) {
    result = {};
    auto* space = load_namespace(blocks, regions.bridges, regions.pci, {}, regions.nvs);
    if (!space)
        return false;

    using Model = IntelGpioResources::Model;
    bool valid = true;
    for (unsigned i = 0; valid && i < space->count; ++i) {
        const auto& object = space->objects[i];
        if (object.kind != Kind::Device || !space->child(object.path, name_segment("_CRS")))
            continue;
        space->used_values = 0;
        space->used_bytes = 0;
        Value id{};
        if (!space->config(object.path, name_segment("_HID"), id) || id.type != Type::String ||
            id.content.left != 7)
            continue;
        const auto* text = id.content.next;
        const auto model = !memcmp(text, "INT34BB", 7)   ? Model::cannon_lake_lp
                           : !memcmp(text, "INT3450", 7) ? Model::cannon_lake_h
                                                         : Model::none;
        if (model == Model::none)
            continue;

        uint64_t status;
        if (!device_status(*space, object.path, status)) {
            valid = false;
            break;
        }
        if ((status & 3) != 3)
            continue;
        Value current{};
        MotherboardResources memory{};
        const bool low_power = model == Model::cannon_lake_lp;
        const unsigned count = low_power ? 3 : 4;
        valid = result.model == Model::none &&
                space->config(object.path, name_segment("_CRS"), current) &&
                current.type == Type::Buffer && motherboard_ranges(current.content, memory) &&
                memory.count == count;
        if (!valid)
            break;

        constexpr uint64_t host_mask = ~uint64_t(0xffffff);
        const auto base = memory.memory[0].base & host_mask;
        const uint32_t offsets[]{0x6e0000, 0x6d0000, low_power ? 0x6a0000u : 0x6b0000u, 0x6a0000u};
        valid = base && base <= UINT32_MAX;
        for (unsigned j = 0; valid && j < count; ++j) {
            valid = memory.memory[j].base == base + offsets[j] && memory.memory[j].size == 0x10000;
            result.community_base[j] = memory.memory[j].base;
        }
        result.model = model;
    }
    release(space);
    if (!valid)
        result = {};
    return valid && result.model != Model::none;
}

bool decode_initialized_hid_devices(const DefinitionBlocks& blocks, I2cHidDevices& result,
                                    ReadRegions regions, Namespace& inventory) {
    Path candidates[16]{};
    unsigned count = 0;
    for (unsigned i = 0; i < inventory.count; ++i) {
        const auto& object = inventory.objects[i];
        if (object.kind != Kind::Device || !inventory.child(object.path, name_segment("_CRS")))
            continue;
        Value id{};
        const bool candidate = i2c_hid_identity(inventory, object.path, id);
        inventory.used_values = 0;
        inventory.used_bytes = 0;
        if (candidate) {
            if (count == sizeof(candidates) / sizeof(*candidates))
                return false;
            candidates[count++] = object.path;
        }
    }

    for (unsigned i = 0; i < count; ++i) {
        const auto& path = candidates[i];
        // Reload AML so a candidate's writes cannot change the next device's resources.
        auto* space = load_namespace(blocks, regions.bridges, regions.pci, {}, regions.nvs);
        if (!space)
            return false;
        space->read_registers = regions.registers;
        space->register_context = regions.register_context;
        space->query_osi = regions.osi;
        if (space->query_osi && !space->child({}, name_segment("_OSI"))) {
            Path osi{{name_segment("_OSI")}, 1};
            if (!space->add(osi, Kind::InterfaceQuery, {}, 1)) {
                release(space);
                return false;
            }
        }
        const auto* object = space->find(path);
        const auto initialization =
            object ? replay_hid_initialization(*space, path) : InitResult::rejected;
        I2cHidDevice device{};
        const bool found =
            initialization == InitResult::ready && i2c_hid_device(*space, *object, device);
        release(space);
        if (initialization == InitResult::rejected)
            ++result.initialization_failures;
        if (!found)
            continue;
        if (result.count == sizeof(result.devices) / sizeof(*result.devices))
            return false;
        result.devices[result.count++] = device;
    }
    return true;
}

bool decode_i2c_hid_devices(const DefinitionBlocks& blocks, I2cHidDevices& result,
                            ReadRegions regions, HidDiscovery mode) {
    result.count = 0;
    result.initialization_failures = 0;
    auto* space = load_namespace(blocks, regions.bridges, regions.pci, {}, regions.nvs);
    if (!space)
        return false;
    if (mode == HidDiscovery::replay_initialization) {
        const bool ok = decode_initialized_hid_devices(blocks, result, regions, *space);
        release(space);
        if (!ok)
            result.count = 0;
        return ok;
    }
    bool ok = true;
    for (unsigned i = 0; i < space->count; ++i) {
        const auto& object = space->objects[i];
        if (object.kind != Kind::Device || !space->child(object.path, name_segment("_CRS")))
            continue;
        const unsigned values = space->used_values, bytes = space->used_bytes;
        I2cHidDevice device{};
        const bool found = i2c_hid_device(*space, object, device);
        space->used_values = values;
        space->used_bytes = bytes;
        if (!found)
            continue;
        if (result.count == sizeof(result.devices) / sizeof(*result.devices)) {
            result.count = 0;
            ok = false;
            break;
        }
        result.devices[result.count++] = device;
    }
    release(space);
    return ok;
}

bool decode_pci_pin_routes(const DefinitionBlocks& blocks, PciPinRoutes& result,
                           PciBridges* bridges, PciConfigRead read_pci, PciLinkProgram program) {
    result.count = 0;
    result.programmed_links = 0;
    result.rollback_failed = false;
    if (blocks.ssdt_count > max_root_entries ||
        (bridges && bridges->count > sizeof(bridges->entries) / sizeof(*bridges->entries)))
        return false;
    if (bridges)
        for (unsigned i = 0; i < bridges->count; ++i)
            bridges->entries[i].routing_rejected = false;
    auto* space = load_namespace(blocks, bridges, read_pci, program);
    if (!space)
        return false;
    bool ok = routing(*space, result, bridges);
    if (ok && space->change_count) {
        auto apply = [&](const LinkChange& change, bool undo) {
            const auto& field = change.field;
            return program.write(field.segment, field.bus, field.slot, field.function, field.offset,
                                 undo ? change.next : change.previous,
                                 undo ? change.previous : change.next);
        };
        for (unsigned i = 0; i < space->change_count; ++i) {
            if (!apply(space->changes[i], false)) {
                while (i)
                    if (!apply(space->changes[--i], true))
                        result.rollback_failed = true;
                ok = false;
                break;
            }
        }
        if (ok)
            result.programmed_links = space->change_count;
    }
    release(space);
    if (!ok)
        result.count = 0;
    return ok;
}

const PciPinRoute* find_pci_pin(const PciPinRoutes& routes, uint16_t segment, uint8_t bus,
                                uint8_t slot, uint8_t function, uint8_t pin,
                                const PciBridges* bridges) {
    if (!pin || pin > 4 || slot >= 32 || function >= 8)
        return nullptr;
    uint8_t subordinate = bus;
    for (;;) {
        ParentBridge parent;
        if (bridges && !bridges->overflow)
            parent = parent_bridge(*bridges, segment, bus);
        const auto* bridge = parent.bridge;
        if (parent.invalid ||
            (bridge && (bridge->subordinate < subordinate || bridge->routing_rejected)))
            return nullptr;
        bool ambiguous = false;
        const auto* route = bus_route(routes, segment, bus, slot, function, pin, ambiguous);
        if (ambiguous || route || !bridge)
            return route;
        // An ARI-enabled downstream port interprets every function as slot zero.
        unsigned device = bridge->ari ? 0 : slot;
        pin = ((pin - 1 + device) & 3) + 1;
        bus = bridge->primary;
        slot = bridge->slot;
        function = bridge->function;
        subordinate = bridge->subordinate;
    }
}

} // namespace ax::Acpi
