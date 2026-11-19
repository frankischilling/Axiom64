// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml.cpp
 * @brief   Decodes ACPI PCI interrupt routing from firmware AML.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Indexes the AML namespace and evaluates the objects used for PCI interrupt\n * routing.
 * Evaluations can update AML integers and never perform device I/O.
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
#include "firmware/aml.hpp"
#include "core/base.hpp"

namespace ax::Acpi {
namespace {

constexpr unsigned max_depth = 16, max_objects = 768;
constexpr uint8_t root_prefix = 0x5c, parent_prefix = 0x5e;

constexpr uint32_t name_segment(const char (&s)[5]) {
    return uint32_t(s[0]) | uint32_t(s[1]) << 8 | uint32_t(s[2]) << 16 | uint32_t(s[3]) << 24;
}

struct Cursor {
    const uint8_t* next = nullptr;
    size_t left = 0;

    unsigned peek() const {
        return left ? *next : 0x100;
    }

    bool take(size_t count, Cursor& result) {
        if (count > left)
            return false;
        result = {next, count};
        if (count)
            next += count;
        left -= count;
        return true;
    }

    bool skip(size_t count) {
        Cursor unused;
        return take(count, unused);
    }

    bool read(size_t count, uint64_t& value) {
        Cursor span;
        if (!take(count, span))
            return false;
        value = 0;
        for (size_t i = 0; i < count; ++i)
            value |= uint64_t(span.next[i]) << (i * 8);
        return true;
    }

    bool block(Cursor& result) {
        unsigned first = peek();
        if (!skip(1))
            return false;
        unsigned following = first >> 6;
        unsigned length = first & (following ? 15 : 63);
        if (following && (first & 0x30))
            return false;
        uint64_t bytes;
        if (!read(following, bytes))
            return false;
        length |= unsigned(bytes) << 4;
        return length > following && take(length - following - 1, result);
    }
};

bool integer(Cursor& stream, uint64_t& value) {
    switch (stream.peek()) {
    case 0x00:
        value = 0;
        return stream.skip(1);
    case 0x01:
        value = 1;
        return stream.skip(1);
    case 0xff:
        value = UINT64_MAX;
        return stream.skip(1);
    case 0x0a:
        return stream.skip(1) && stream.read(1, value);
    case 0x0b:
        return stream.skip(1) && stream.read(2, value);
    case 0x0c:
        return stream.skip(1) && stream.read(4, value);
    case 0x0e:
        return stream.skip(1) && stream.read(8, value);
    default:
        return false;
    }
}

struct Path {
    uint32_t segments[max_depth];
    unsigned count;
};

struct Name {
    Path path;
    unsigned parents;
    bool absolute;
};

bool name_character(uint8_t byte, bool first) {
    return byte == '_' || (byte >= 'A' && byte <= 'Z') || (!first && byte >= '0' && byte <= '9');
}

bool read_name(Cursor& stream, Name& name) {
    name = {};
    if (stream.peek() == root_prefix) {
        name.absolute = true;
        stream.skip(1);
    } else {
        while (stream.peek() == parent_prefix) {
            stream.skip(1);
            if (++name.parents > max_depth)
                return false;
        }
    }
    unsigned count = 1;
    switch (stream.peek()) {
    case 0:
        return stream.skip(1);
    case 0x2e:
        stream.skip(1);
        count = 2;
        break;
    case 0x2f:
        stream.skip(1);
        count = stream.peek();
        if (!stream.skip(1) || !count)
            return false;
        break;
    }
    if (count > max_depth)
        return false;
    name.path.count = count;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t segment;
        if (!stream.read(4, segment))
            return false;
        for (unsigned character = 0; character < 4; ++character)
            if (!name_character(uint8_t(segment >> (character * 8)), character == 0))
                return false;
        name.path.segments[i] = segment;
    }
    return true;
}

Path parent(Path path) {
    if (path.count)
        --path.count;
    return path;
}

bool append(const Path& scope, const Name& name, Path& result) {
    result = name.absolute ? Path{} : scope;
    if (name.parents > result.count || result.count - name.parents + name.path.count > max_depth)
        return false;
    result.count -= name.parents;
    for (unsigned i = 0; i < name.path.count; ++i)
        result.segments[result.count++] = name.path.segments[i];
    return true;
}

bool match(const Path& a, const Path& b) {
    return a.count == b.count && !memcmp(a.segments, b.segments, a.count * sizeof(uint32_t));
}

bool data(Cursor& stream) {
    switch (stream.peek()) {
    case 0x0d: {
        stream.skip(1);
        while (stream.left && stream.peek())
            stream.skip(1);
        return stream.skip(1);
    }
    case 0x11:   // Buffer
    case 0x12:   // Package
    case 0x13: { // VarPackage
        stream.skip(1);
        Cursor ignored;
        return stream.block(ignored);
    }
    }
    Cursor encoded = stream;
    uint64_t number;
    if (integer(encoded, number)) {
        stream = encoded;
        return true;
    }
    Name name;
    return read_name(stream, name) && name.path.count;
}

enum class Kind : uint8_t { Scope, Device, Data, Method, Opaque };

struct Object {
    Path path;
    Cursor content;
    uint64_t integer;
    Kind kind;
    unsigned arguments;
    bool assigned;
};

enum class Type : uint8_t { None, Integer, Buffer, Package, Device, String };

struct Value {
    Type type;
    uint64_t number;
    Cursor content;
    const Object* object;
};

struct Namespace {
    Object objects[max_objects];
    unsigned count;
    unsigned steps;

    Object* find(const Path& path) {
        for (unsigned i = 0; i < count; ++i)
            if (match(objects[i].path, path))
                return &objects[i];
        return nullptr;
    }

    Object* lookup(Path scope, const Name& name) {
        Path path;
        if (!append(scope, name, path))
            return nullptr;
        if (name.absolute || name.parents || name.path.count != 1)
            return find(path);
        for (;;) {
            if (auto object = find(path))
                return object;
            if (!scope.count)
                return nullptr;
            --scope.count;
            append(scope, name, path);
        }
    }

    Object* child(const Path& scope, uint32_t segment) {
        Path path = scope;
        if (path.count == max_depth)
            return nullptr;
        path.segments[path.count++] = segment;
        return find(path);
    }

    bool add(const Path& path, Kind kind, Cursor content = {}, unsigned arguments = 0) {
        if (!path.count || count == max_objects || find(path))
            return false;
        objects[count++] = {path, content, 0, kind, arguments, false};
        return true;
    }

    bool load(Cursor stream, const Path& scope, unsigned depth);

    bool evaluate(Cursor& stream, const Path& scope, const Value* args, unsigned count,
                  Value& result, unsigned depth);

    bool execute(Cursor stream, const Path& scope, const Value* args, unsigned count, Value& result,
                 unsigned depth);

    bool value(const Object& object, Value& result, unsigned depth) {
        if (object.kind == Kind::Device) {
            result = {Type::Device, 0, {}, &object};
            return true;
        }
        if (object.kind != Kind::Data)
            return false;
        if (object.assigned) {
            result = {Type::Integer, object.integer, {}, nullptr};
            return true;
        }
        Cursor stream = object.content;
        if (!evaluate(stream, parent(object.path), nullptr, 0, result, depth) || stream.left)
            return false;
        if (result.type == Type::Package && !result.object)
            result.object = &object;
        return true;
    }

    bool method(const Object& object, const Value* args, unsigned count, Value& result) {
        return object.kind == Kind::Method && count == object.arguments &&
               execute(object.content, parent(object.path), args, count, result, 0);
    }

    bool config(const Path& scope, uint32_t segment, Value& result) {
        const auto* object = child(scope, segment);
        return object && (object->kind == Kind::Method ? method(*object, nullptr, 0, result)
                                                       : value(*object, result, 0));
    }
};

bool Namespace::load(Cursor stream, const Path& scope, unsigned depth) {
    if (depth >= max_depth)
        return false;
    while (stream.left) {
        unsigned opcode = stream.peek();
        stream.skip(1);
        if (opcode == 0x5b) {
            opcode = 0x5b00 | stream.peek();
            if (!stream.skip(1))
                return false;
        }
        Cursor block;
        Name name, other;
        Path path;
        uint64_t info;
        switch (opcode) {
        case 0x08: { // Name
            if (!read_name(stream, name) || !append(scope, name, path))
                return false;
            Cursor initial = stream;
            if (!data(stream) || !add(path, Kind::Data, {initial.next, initial.left - stream.left}))
                return false;
            break;
        }
        case 0x10:   // Scope
        case 0x14:   // Method
        case 0x5b82: // Device
        case 0x5b83: // Processor
        case 0x5b84: // PowerResource
        case 0x5b85: // ThermalZone
            if (!stream.block(block) || !read_name(block, name) || !append(scope, name, path))
                return false;
            if (opcode == 0x14) {
                if (!block.read(1, info) || !add(path, Kind::Method, block, info & 7))
                    return false;
                break;
            }
            if (opcode == 0x10) {
                if (auto target = lookup(scope, name)) {
                    if (target->kind != Kind::Scope && target->kind != Kind::Device)
                        return false;
                    path = target->path;
                } else if (path.count && !add(path, Kind::Scope)) {
                    return false;
                }
            } else if (!add(path, opcode == 0x5b82 ? Kind::Device : Kind::Scope)) {
                return false;
            }
            if ((opcode == 0x5b83 && !block.skip(6)) || (opcode == 0x5b84 && !block.skip(3)) ||
                !load(block, path, depth + 1))
                return false;
            break;
        case 0x06: // Alias
            if (!read_name(stream, other) || !other.path.count)
                return false;
            [[fallthrough]];
        case 0x5b01: // Mutex
        case 0x5b02: // Event
        case 0x5b80: // OperationRegion
            if (!read_name(stream, name) || !append(scope, name, path) || !add(path, Kind::Opaque))
                return false;
            if ((opcode == 0x5b01 && !stream.skip(1)) ||
                (opcode == 0x5b80 && (!stream.skip(1) || !data(stream) || !data(stream))))
                return false;
            break;
        case 0x5b81: // Field
        case 0x5b86: // IndexField
        case 0x5b87: // BankField
            if (!stream.block(block))
                return false;
            break;
        case 0x15: // External
            if (!read_name(stream, name) || !name.path.count || !stream.skip(2))
                return false;
            break;
        case 0xa3: // NoOp
            break;
        default:
            return false;
        }
    }
    return true;
}

bool Namespace::evaluate(Cursor& stream, const Path& scope, const Value* args, unsigned count,
                         Value& result, unsigned depth) {
    if (depth >= max_depth || !steps)
        return false;
    --steps;
    uint64_t number;
    Cursor encoded = stream;
    if (integer(encoded, number)) {
        stream = encoded;
        result = {Type::Integer, number, {}, nullptr};
        return true;
    }
    Cursor block;
    unsigned opcode = stream.peek();
    if (opcode >= 0x68 && opcode <= 0x6e) {
        if (opcode - 0x68 >= count)
            return false;
        result = args[opcode - 0x68];
        return stream.skip(1);
    }
    switch (opcode) {
    case 0x0d: {
        stream.skip(1);
        Cursor text = stream;
        while (stream.left && stream.peek())
            stream.skip(1);
        result = {Type::String, 0, {text.next, text.left - stream.left}, nullptr};
        return stream.skip(1);
    }
    case 0x11:
        if (!stream.skip(1) || !stream.block(block) || !integer(block, number) ||
            number != block.left)
            return false;
        result = {Type::Buffer, 0, block, nullptr};
        return true;
    case 0x12:
        if (!stream.skip(1) || !stream.block(block) || !block.read(1, number))
            return false;
        result = {Type::Package, number, block, nullptr};
        return true;
    case 0x92:   // LNot
    case 0x93: { // LEqual
        stream.skip(1);
        Value left{}, right{};
        if (!evaluate(stream, scope, args, count, left, depth + 1) || left.type != Type::Integer)
            return false;
        if (opcode == 0x93 && (!evaluate(stream, scope, args, count, right, depth + 1) ||
                               right.type != Type::Integer))
            return false;
        result = {Type::Integer,
                  opcode == 0x92 ? !left.number : left.number == right.number,
                  {},
                  nullptr};
        return true;
    }
    }
    Name name;
    if (!read_name(stream, name) || !name.path.count)
        return false;
    const auto* object = lookup(scope, name);
    return object && value(*object, result, depth + 1);
}

bool Namespace::execute(Cursor stream, const Path& scope, const Value* args, unsigned count,
                        Value& result, unsigned depth) {
    if (depth >= max_depth)
        return false;
    while (stream.left && result.type == Type::None) {
        if (!steps)
            return false;
        --steps;
        auto opcode = stream.peek();
        stream.skip(1);
        switch (opcode) {
        case 0x70: { // Store
            Value input{}, old{};
            Name target;
            if (!evaluate(stream, scope, args, count, input, depth) ||
                input.type != Type::Integer || !read_name(stream, target))
                return false;
            auto object = lookup(scope, target);
            if (!object || !value(*object, old, depth) || old.type != Type::Integer)
                return false;
            object->assigned = true;
            object->integer = input.number;
            break;
        }
        case 0xa0: { // If and optional Else
            Cursor yes, no;
            Value test{};
            if (!stream.block(yes) || !evaluate(yes, scope, args, count, test, depth) ||
                test.type != Type::Integer)
                return false;
            if (stream.peek() == 0xa1 && (!stream.skip(1) || !stream.block(no)))
                return false;
            if (!execute(test.number ? yes : no, scope, args, count, result, depth + 1))
                return false;
            break;
        }
        case 0xa3: // NoOp
            break;
        case 0xa4: // Return
            return evaluate(stream, scope, args, count, result, depth);
        default:
            return false;
        }
    }
    return true;
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

bool route_package(Namespace& space, const Path& scope, Value package, unsigned segment,
                   unsigned bus, PciPinRoutes& result) {
    if (package.type != Type::Package || package.number > 256)
        return false;
    Path origin = package.object ? parent(package.object->path) : scope;
    for (unsigned i = 0; i < package.number; ++i) {
        Value row{}, address{}, pin{}, source{}, index{};
        if (!space.evaluate(package.content, origin, nullptr, 0, row, 0) ||
            row.type != Type::Package || row.number != 4)
            return false;
        const Path entry_scope = row.object ? parent(row.object->path) : origin;
        if (!space.evaluate(row.content, entry_scope, nullptr, 0, address, 0) ||
            !space.evaluate(row.content, entry_scope, nullptr, 0, pin, 0) ||
            !space.evaluate(row.content, entry_scope, nullptr, 0, source, 0) ||
            !space.evaluate(row.content, entry_scope, nullptr, 0, index, 0) || row.content.left ||
            address.type != Type::Integer || address.number >> 16 >= 32 ||
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
                device = space.lookup(entry_scope, name);
            }
            Value crs{};
            if (!device || device->kind != Kind::Device ||
                !space.config(device->path, name_segment("_CRS"), crs) ||
                crs.type != Type::Buffer || !interrupt_resource(crs.content, index.number, route))
                return false;
        }
        if (result.count == sizeof(result.entries) / sizeof(*result.entries))
            return false;
        result.entries[result.count++] = route;
    }
    return !package.content.left;
}

bool pci_root_id(Value id) {
    // EISA IDs PNP0A03 (PCI) and PNP0A08 (PCI Express).
    if (id.type == Type::Integer)
        return id.number == 0x030ad041 || id.number == 0x080ad041;
    return id.type == Type::String && id.content.left == 7 &&
           (!memcmp(id.content.next, "PNP0A03", 7) || !memcmp(id.content.next, "PNP0A08", 7));
}

bool routing(Namespace& space, PciPinRoutes& output) {
    if (auto pic = space.child({}, name_segment("_PIC"))) {
        Value mode{Type::Integer, 1, {}, nullptr}, ignored{};
        if (!space.method(*pic, &mode, 1, ignored))
            return false;
    }
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
        Value routes{};
        if (space.child(device.path, name_segment("_PRT")) &&
            (!space.config(device.path, name_segment("_PRT"), routes) ||
             !route_package(space, device.path, routes, seg.number, bus.number, output)))
            return false;
    }
    return output.count != 0;
}

} // namespace

bool decode_pci_pin_routes(const DefinitionBlocks& blocks, PciPinRoutes& result) {
    result.count = 0;
    if (blocks.ssdt_count > max_root_entries)
        return false;
    auto* space = static_cast<Namespace*>(alloc(sizeof(Namespace)));
    if (!space)
        return false;
    space->count = 0;
    space->steps = 32768;
    auto load = [&](const DefinitionBlock& block) {
        return block.table && block.length >= 36 &&
               space->load({block.table + 36, block.length - 36}, {}, 0);
    };
    bool ok = load(blocks.dsdt);
    for (size_t i = 0; ok && i < blocks.ssdt_count; ++i)
        ok = load(blocks.ssdt[i]);
    ok = ok && routing(*space, result);
    release(space);
    if (!ok)
        result.count = 0;
    return ok;
}

const PciPinRoute* find_pci_pin(const PciPinRoutes& routes, uint16_t segment, uint8_t bus,
                                uint8_t slot, uint8_t function, uint8_t pin) {
    const PciPinRoute* exact = nullptr;
    const PciPinRoute* wildcard = nullptr;
    for (unsigned i = 0; i < routes.count; ++i) {
        const auto& route = routes.entries[i];
        if (route.segment != segment || route.bus != bus || route.slot != slot || route.pin != pin)
            continue;
        if (route.function == function) {
            if (exact)
                return nullptr;
            exact = &route;
        } else if (route.function == UINT8_MAX) {
            if (wildcard)
                return nullptr;
            wildcard = &route;
        }
    }
    return exact ? exact : wildcard;
}

} // namespace ax::Acpi
