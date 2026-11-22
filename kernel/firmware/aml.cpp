// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml.cpp
 * @brief   Decodes ACPI PCI and I²C resources from firmware AML.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Indexes the AML namespace and evaluates the objects used for PCI interrupt
 * routing. The evaluator can read PCI configuration fields and stores
 * temporary packages and buffers in bounded storage.
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

    bool length(unsigned& length, unsigned& bytes_read) {
        unsigned first = peek();
        if (!skip(1))
            return false;
        unsigned following = first >> 6;
        length = first & (following ? 15 : 63);
        if (following && (first & 0x30))
            return false;
        uint64_t bytes;
        if (!read(following, bytes))
            return false;
        length |= unsigned(bytes) << 4;
        bytes_read = following + 1;
        return true;
    }

    bool block(Cursor& result) {
        unsigned size, bytes;
        return length(size, bytes) && size >= bytes && take(size - bytes, result);
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

bool region_operand(Cursor& stream, unsigned depth = 0) {
    if (depth == max_depth)
        return false;
    switch (stream.peek()) {
    case 0x72:   // Add
    case 0x74:   // Subtract
    case 0x77:   // Multiply
    case 0x79:   // ShiftLeft
    case 0x7a:   // ShiftRight
    case 0x7b:   // And
    case 0x7d: { // Or
        stream.skip(1);
        if (!region_operand(stream, depth + 1) || !region_operand(stream, depth + 1))
            return false;
        if (stream.peek() == 0)
            return stream.skip(1); // NullName discards the result.
        Name target;
        return read_name(stream, target) && target.path.count;
    }
    default:
        return data(stream);
    }
}

enum class Kind : uint8_t { Scope, Device, Data, Method, Opaque, Region, PciField };

struct Object {
    Path path;
    Cursor content;
    uint64_t integer;
    Kind kind;
    unsigned arguments;
    bool assigned;
    const Object* region = nullptr;
};

enum class Type : uint8_t {
    None,
    Integer,
    Buffer,
    Package,
    Device,
    String,
    Reference,
    BufferField
};

struct Value {
    Type type;
    uint64_t number;
    Cursor content;
    const Object* object;
    Value* entries = nullptr;
    uint8_t* bytes = nullptr;
};

struct Frame {
    struct Named {
        uint32_t name;
        Value value;
    };

    const Value* arguments;
    unsigned count;
    Value locals[8]{};
    Named names[8]{};
    unsigned named = 0;

    Value* find(const Name& name) {
        if (name.absolute || name.parents || name.path.count != 1)
            return nullptr;
        for (unsigned i = 0; i < named; ++i)
            if (names[i].name == name.path.segments[0])
                return &names[i].value;
        return nullptr;
    }

    bool add(const Name& name, Value value) {
        if (name.absolute || name.parents || name.path.count != 1 ||
            named == sizeof(names) / sizeof(*names) || find(name))
            return false;
        names[named++] = {name.path.segments[0], value};
        return true;
    }
};

struct ConfigField {
    uint16_t segment, offset;
    uint8_t bus, slot, function;
    bool operator==(const ConfigField&) const = default;
};

struct LinkChange {
    ConfigField field;
    uint8_t previous, next;
};

struct Namespace {
    Object objects[max_objects];
    Value values[4096];
    uint8_t buffers[8192];
    unsigned count;
    unsigned steps;
    unsigned used_values;
    unsigned used_bytes;
    uint64_t integer_mask;
    const PciBridges* bridges;
    PciConfigRead read_pci;
    PciLinkProgram link_program;
    LinkChange changes[4];
    unsigned change_count;
    uint8_t programming_gsi;
    bool change_emitted;
    bool link_evaluation;

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
    bool load_fields(Cursor, const Path&);
    bool field_address(const Object&, ConfigField&, unsigned depth);
    bool read_field(const Object&, Value&, unsigned depth);
    bool stage_field(const Object&, Value, unsigned depth);

    bool evaluate(Cursor&, const Path&, Frame*, Value&, unsigned depth);
    bool execute(Cursor, const Path&, Frame&, Value&, unsigned depth);
    bool store(Cursor&, const Path&, Frame*, Value, unsigned depth);

    bool value(const Object& object, Value& result, unsigned depth) {
        if (object.kind == Kind::Device) {
            result = {Type::Device, 0, {}, &object};
            return true;
        }
        if (object.kind == Kind::PciField)
            return read_field(object, result, depth);
        if (object.kind != Kind::Data)
            return false;
        if (object.assigned) {
            result = {Type::Integer, object.integer, {}, nullptr};
            return true;
        }
        Cursor stream = object.content;
        return evaluate(stream, parent(object.path), nullptr, result, depth) && !stream.left;
    }

    bool method(const Object& object, const Value* args, unsigned count, Value& result,
                unsigned depth = 0) {
        Frame frame{args, count};
        return object.kind == Kind::Method && count == object.arguments &&
               execute(object.content, parent(object.path), frame, result, depth);
    }

    bool config(const Path& scope, uint32_t segment, Value& result, unsigned depth = 0) {
        const auto* object = child(scope, segment);
        return object && (object->kind == Kind::Method ? method(*object, nullptr, 0, result, depth)
                                                       : value(*object, result, depth));
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
        case 0xa0: { // Module-level If with a constant predicate.
            uint64_t condition;
            if (!stream.block(block) || !integer(block, condition) ||
                ((condition & integer_mask) && !load(block, scope, depth + 1)))
                return false;
            if (stream.peek() == 0xa1) {
                Cursor alternative;
                if (!stream.skip(1) || !stream.block(alternative) ||
                    (!(condition & integer_mask) && !load(alternative, scope, depth + 1)))
                    return false;
            }
            break;
        }
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
            if (!read_name(stream, name) || !append(scope, name, path) || !add(path, Kind::Opaque))
                return false;
            if (opcode == 0x5b01 && !stream.skip(1))
                return false;
            break;
        case 0x5b80: { // OperationRegion
            if (!read_name(stream, name) || !append(scope, name, path))
                return false;
            Cursor operands = stream;
            if (!stream.skip(1) || !region_operand(stream) || !region_operand(stream) ||
                !add(path, Kind::Region, {operands.next, operands.left - stream.left}))
                return false;
            break;
        }
        case 0x5b81: // Field
            if (!stream.block(block) || !load_fields(block, scope))
                return false;
            break;
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

bool Namespace::load_fields(Cursor field, const Path& scope) {
    Name name;
    if (!read_name(field, name) || !field.left)
        return false;
    auto* region = lookup(scope, name);
    if (!region || region->kind != Kind::Region || region->content.peek() != 2)
        return true;
    unsigned access = field.peek() & 15;
    field.skip(1);
    uint64_t offset = 0;
    while (field.left) {
        auto term = field.peek();
        if (term == 1) { // AccessField
            uint64_t operands;
            if (!field.skip(1) || !field.read(2, operands))
                return false;
            access = operands & 15;
            continue;
        }
        if (term == 2 || term == 3)
            return true; // Connections and extended accesses are outside this provider.
        unsigned bits, bytes;
        uint64_t segment = 0;
        if (!(term ? field.read(4, segment) : field.skip(1)) || !field.length(bits, bytes) ||
            offset + bits > 4096 * 8)
            return false;
        if (term && !(offset & 7) && (bits == 8 || bits == 16 || bits == 32) &&
            (!access || (access <= 3 && (8u << (access - 1)) == bits))) {
            Path path = scope;
            if (path.count == max_depth)
                return false;
            for (unsigned i = 0; i < 4; ++i)
                if (!name_character(uint8_t(segment >> (8 * i)), !i))
                    return false;
            path.segments[path.count++] = segment;
            if (!add(path, Kind::PciField, {}, bits / 8))
                return false;
            objects[count - 1].integer = offset / 8;
            objects[count - 1].region = region;
        }
        offset += bits;
    }
    return true;
}

bool Namespace::store(Cursor& stream, const Path& scope, Frame* frame, Value input,
                      unsigned depth) {
    unsigned target = stream.peek();
    if (target >= 0x60 && target <= 0x67 && frame) {
        frame->locals[target - 0x60] = input;
        return stream.skip(1);
    }
    if (target == 0x88) {
        Value reference{};
        if (link_evaluation || !evaluate(stream, scope, frame, reference, depth + 1) ||
            reference.type != Type::Reference || input.type == Type::Reference)
            return false;
        *reference.entries = input;
        return true;
    }
    Name name;
    if (!read_name(stream, name))
        return false;
    if (!name.path.count)
        return !name.absolute && !name.parents; // NullName target of a Type 2 opcode.
    if (auto local = frame ? frame->find(name) : nullptr) {
        if (local->type == Type::BufferField) {
            if (input.type != Type::Integer)
                return false;
            for (unsigned i = 0; i < local->number; ++i)
                local->bytes[i] = uint8_t(input.number >> (8 * i));
        } else {
            *local = input;
        }
        return true;
    }
    auto* object = lookup(scope, name);
    if (object && object->kind == Kind::PciField)
        return stage_field(*object, input, depth + 1);
    Value old{};
    if (link_evaluation || input.type != Type::Integer || !object || object->kind != Kind::Data ||
        !value(*object, old, depth + 1) || old.type != Type::Integer)
        return false;
    object->assigned = true;
    object->integer = input.number;
    return true;
}

bool integer_result(unsigned opcode, uint64_t left, uint64_t right, uint64_t& result) {
    switch (opcode) {
    case 0x72:
        result = left + right;
        break;
    case 0x79:
        result = right < 64 ? left << right : 0;
        break;
    case 0x7a:
        result = right < 64 ? left >> right : 0;
        break;
    case 0x7b:
        result = left & right;
        break;
    case 0x7d:
        result = left | right;
        break;
    case 0x92:
        result = !left;
        break;
    case 0x93:
        result = left == right;
        break;
    case 0x94:
        result = left > right;
        break;
    case 0x95:
        result = left < right;
        break;
    default:
        return false;
    }
    return true;
}

bool Namespace::evaluate(Cursor& stream, const Path& scope, Frame* frame, Value& result,
                         unsigned depth) {
    if (depth >= max_depth || !steps)
        return false;
    --steps;
    uint64_t number;
    Cursor encoded = stream;
    if (integer(encoded, number)) {
        stream = encoded;
        result = {Type::Integer, number & integer_mask, {}, nullptr};
        return true;
    }
    Cursor block;
    unsigned opcode = stream.peek();
    if (opcode >= 0x60 && opcode <= 0x6e) {
        if (!frame || (opcode >= 0x68 && opcode - 0x68 >= frame->count))
            return false;
        result = opcode < 0x68 ? frame->locals[opcode - 0x60] : frame->arguments[opcode - 0x68];
        return result.type != Type::None && stream.skip(1);
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
        if (frame) {
            if (number > sizeof(buffers) - used_bytes)
                return false;
            result.bytes = buffers + used_bytes;
            used_bytes += unsigned(number);
            memcpy(result.bytes, block.next, number);
            result.content.next = result.bytes;
        }
        return true;
    case 0x12: {
        if (!stream.skip(1) || !stream.block(block) || !block.read(1, number) ||
            number > sizeof(values) / sizeof(*values) - used_values)
            return false;
        auto* entries = values + used_values;
        used_values += unsigned(number);
        result = {Type::Package, number, {}, find(scope), entries};
        for (unsigned i = 0; i < number; ++i) {
            entries[i] = {};
            if (block.left && !evaluate(block, scope, frame, entries[i], depth + 1))
                return false;
        }
        return !block.left;
    }
    case 0x70: // Store
        return stream.skip(1) && evaluate(stream, scope, frame, result, depth + 1) &&
               store(stream, scope, frame, result, depth + 1);
    case 0x75: { // Increment
        if (!stream.skip(1) || stream.peek() < 0x60 || stream.peek() > 0x67)
            return false;
        auto target = stream;
        if (!evaluate(stream, scope, frame, result, depth + 1) || result.type != Type::Integer)
            return false;
        result.number = (result.number + 1) & integer_mask;
        return store(target, scope, frame, result, depth + 1);
    }
    case 0x83: // DerefOf
        if (!stream.skip(1) || !evaluate(stream, scope, frame, result, depth + 1) ||
            result.type != Type::Reference || result.entries->type == Type::Reference)
            return false;
        result = *result.entries;
        return result.type != Type::None;
    case 0x88: { // Index
        Value package{}, index{};
        if (!stream.skip(1) || !evaluate(stream, scope, frame, package, depth + 1) ||
            !evaluate(stream, scope, frame, index, depth + 1) || package.type != Type::Package ||
            index.type != Type::Integer || index.number >= package.number)
            return false;
        result = {Type::Reference, 0, {}, nullptr, package.entries + index.number};
        return store(stream, scope, frame, result, depth + 1);
    }
    case 0x72:   // Add
    case 0x79:   // ShiftLeft
    case 0x7a:   // ShiftRight
    case 0x7b:   // And
    case 0x7d:   // Or
    case 0x92:   // LNot
    case 0x93:   // LEqual
    case 0x94:   // LGreater
    case 0x95: { // LLess
        stream.skip(1);
        Value left{}, right{};
        if (!evaluate(stream, scope, frame, left, depth + 1) ||
            (opcode != 0x92 && !evaluate(stream, scope, frame, right, depth + 1)))
            return false;
        if (opcode == 0x93 && left.type == Type::Buffer && right.type == Type::Buffer) {
            const bool equal = left.content.left == right.content.left &&
                               !memcmp(left.content.next, right.content.next, left.content.left);
            result = {Type::Integer, equal ? integer_mask : 0, {}, nullptr};
            return true;
        }
        if (left.type != Type::Integer || (opcode != 0x92 && right.type != Type::Integer) ||
            !integer_result(opcode, left.number, right.number, number))
            return false;
        if (opcode >= 0x92) {
            result = {Type::Integer, number ? integer_mask : 0, {}, nullptr};
            return true;
        }
        result = {Type::Integer, number & integer_mask, {}, nullptr};
        return store(stream, scope, frame, result, depth + 1);
    }
    }
    Name name;
    if (!read_name(stream, name) || !name.path.count)
        return false;
    if (auto local = frame ? frame->find(name) : nullptr) {
        if (local->type == Type::BufferField) {
            Cursor bytes{local->bytes, size_t(local->number)};
            if (!bytes.read(unsigned(local->number), number))
                return false;
            result = {Type::Integer, number, {}, nullptr};
        } else {
            result = *local;
        }
        return true;
    }
    const auto* object = lookup(scope, name);
    if (!object)
        return false;
    if (object->kind != Kind::Method)
        return value(*object, result, depth + 1);
    Value arguments[7]{};
    for (unsigned i = 0; i < object->arguments; ++i)
        if (!evaluate(stream, scope, frame, arguments[i], depth + 1))
            return false;
    return method(*object, arguments, object->arguments, result, depth + 1);
}

bool Namespace::execute(Cursor stream, const Path& scope, Frame& frame, Value& result,
                        unsigned depth) {
    if (depth >= max_depth)
        return false;
    while (stream.left && result.type == Type::None) {
        if (!steps)
            return false;
        --steps;
        Cursor term = stream;
        auto opcode = stream.peek();
        stream.skip(1);
        switch (opcode) {
        case 0x08: { // Method-local Name
            Name name;
            Value initial{};
            if (!read_name(stream, name) || !evaluate(stream, scope, &frame, initial, depth + 1) ||
                !frame.add(name, initial))
                return false;
            break;
        }
        case 0x8a: { // CreateDWordField
            Value buffer{}, offset{};
            Name name;
            if (!evaluate(stream, scope, &frame, buffer, depth + 1) ||
                !evaluate(stream, scope, &frame, offset, depth + 1) || !read_name(stream, name) ||
                buffer.type != Type::Buffer || !buffer.bytes || offset.type != Type::Integer ||
                buffer.content.left < 4 || offset.number > buffer.content.left - 4 ||
                !frame.add(
                    name,
                    {Type::BufferField, 4, {}, nullptr, nullptr, buffer.bytes + offset.number}))
                return false;
            break;
        }
        case 0xa0: { // If and optional Else
            Cursor yes, no;
            Value test{};
            if (!stream.block(yes) || !evaluate(yes, scope, &frame, test, depth + 1) ||
                test.type != Type::Integer)
                return false;
            if (stream.peek() == 0xa1 && (!stream.skip(1) || !stream.block(no)))
                return false;
            if (!execute(test.number ? yes : no, scope, frame, result, depth + 1))
                return false;
            break;
        }
        case 0xa2: { // While
            Cursor loop;
            if (!stream.block(loop))
                return false;
            while (result.type == Type::None) {
                Cursor body = loop;
                Value test{};
                if (!evaluate(body, scope, &frame, test, depth + 1) || test.type != Type::Integer)
                    return false;
                if (!test.number)
                    break;
                if (!execute(body, scope, frame, result, depth + 1))
                    return false;
            }
            break;
        }
        case 0xa3: // NoOp
            break;
        case 0xa4: // Return
            return evaluate(stream, scope, &frame, result, depth + 1) &&
                   result.type != Type::None && result.type != Type::Reference;
        case 0x70:   // Store
        case 0x72:   // Add
        case 0x75:   // Increment
        case 0x79:   // ShiftLeft
        case 0x7a:   // ShiftRight
        case 0x7b:   // And
        case 0x7d: { // Or
            Value ignored{};
            if (!evaluate(term, scope, &frame, ignored, depth + 1))
                return false;
            stream = term;
            break;
        }
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

bool i2c_connection(Cursor resources, I2cHidDevice& device) {
    const Cursor original = resources;
    bool found = false;
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
            !speed || !bus.read(2, address) || address > (mode ? 0x3ffu : 0x7fu) || item.left < 2 ||
            item.left > sizeof(device.controller) || item.next[item.left - 1])
            return false;
        Name resource_source{};
        if (!string_name({item.next, item.left - 1}, resource_source))
            return false;
        device.source_index = index;
        device.ten_bit = mode != 0;
        device.max_hz = speed;
        device.address = address;
        memcpy(device.controller, item.next, item.left);
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

bool i2c_hid_device(Namespace& space, const Object& object, I2cHidDevice& device) {
    Value id{}, compatible{}, status{}, resources{};
    if (!space.config(object.path, name_segment("_HID"), id) ||
        (!i2c_hid_id(id) && (!space.config(object.path, name_segment("_CID"), compatible) ||
                             !i2c_hid_compatible(compatible))) ||
        (space.child(object.path, name_segment("_STA")) &&
         (!space.config(object.path, name_segment("_STA"), status) ||
          status.type != Type::Integer || !(status.number & 1))) ||
        !space.config(object.path, name_segment("_CRS"), resources) ||
        resources.type != Type::Buffer || !i2c_connection(resources.content, device))
        return false;
    if (id.type == Type::String && id.content.left < sizeof(device.hardware_id))
        memcpy(device.hardware_id, id.content.next, id.content.left);
    else
        memcpy(device.hardware_id, "PNP0C50", 7);

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

bool pci_root_id(Value id) {
    // EISA IDs PNP0A03 (PCI) and PNP0A08 (PCI Express).
    if (id.type == Type::Integer)
        return id.number == 0x030ad041 || id.number == 0x080ad041;
    return id.type == Type::String && id.content.left == 7 &&
           (!memcmp(id.content.next, "PNP0A03", 7) || !memcmp(id.content.next, "PNP0A08", 7));
}

bool Namespace::field_address(const Object& field, ConfigField& address, unsigned depth) {
    if (depth >= max_depth)
        return false;
    const auto* region = field.region;
    Cursor operands = region->content;
    operands.skip(1);
    uint64_t base, length;
    unsigned width = field.arguments;
    if (!integer(operands, base) || !integer(operands, length) || operands.left || base >= 4096 ||
        length > 4096 - base || field.integer > length || width > length - field.integer ||
        ((base + field.integer) & (width - 1)))
        return false;

    // Resolve namespace device addresses from the operation region to its PCI root.
    uint32_t addresses[max_depth];
    unsigned used = 0;
    Path root = parent(region->path);
    for (;;) {
        const auto* device = find(root);
        if (!device || device->kind != Kind::Device)
            return false;
        Value hid{}, adr{};
        if (config(root, name_segment("_HID"), hid, depth + 1) && pci_root_id(hid))
            break;
        if (!config(root, name_segment("_ADR"), adr, depth + 1) || adr.type != Type::Integer ||
            (adr.number >> 16) >= 32 || (adr.number & 0xffff) >= 8 || used == max_depth)
            return false;
        addresses[used++] = adr.number;
        root = parent(root);
    }
    if (!used)
        return false;
    Value segment{Type::Integer, 0, {}, nullptr}, bus = segment;
    if ((child(root, name_segment("_SEG")) &&
         !config(root, name_segment("_SEG"), segment, depth + 1)) ||
        (child(root, name_segment("_BBN")) &&
         !config(root, name_segment("_BBN"), bus, depth + 1)) ||
        segment.type != Type::Integer || segment.number > UINT16_MAX || bus.type != Type::Integer ||
        bus.number > UINT8_MAX)
        return false;
    uint8_t subordinate = UINT8_MAX;
    while (used > 1) {
        uint32_t address = addresses[--used];
        const PciBridge* next = nullptr;
        if (!bridges || bridges->overflow)
            return false;
        for (unsigned i = 0; i < bridges->count; ++i) {
            const auto& bridge = bridges->entries[i];
            if (bridge.segment != segment.number || bridge.primary != bus.number ||
                bridge.slot != (address >> 16) || bridge.function != (address & 7))
                continue;
            if (next || bridge.subordinate > subordinate ||
                parent_bridge(*bridges, bridge.segment, bridge.secondary).bridge != &bridge)
                return false;
            next = &bridge;
        }
        if (!next)
            return false;
        bus.number = next->secondary;
        subordinate = next->subordinate;
    }
    address = {uint16_t(segment.number), uint16_t(base + field.integer), uint8_t(bus.number),
               uint8_t(addresses[0] >> 16), uint8_t(addresses[0] & 7)};
    return true;
}

bool Namespace::read_field(const Object& field, Value& result, unsigned depth) {
    ConfigField address;
    if (!read_pci || !field_address(field, address, depth))
        return false;
    if (field.arguments == 1)
        for (unsigned i = 0; i < change_count; ++i)
            if (changes[i].field == address) {
                result = {Type::Integer, changes[i].next, {}, nullptr};
                return true;
            }
    uint32_t value;
    if (!read_pci(address.segment, address.bus, address.slot, address.function, address.offset,
                  field.arguments, value))
        return false;
    result = {Type::Integer, value, {}, nullptr};
    return true;
}

bool Namespace::stage_field(const Object& field, Value input, unsigned depth) {
    ConfigField address;
    if (!programming_gsi || change_emitted || field.arguments != 1 || !read_pci ||
        input.type != Type::Integer || input.number != programming_gsi ||
        !field_address(field, address, depth))
        return false;
    if (address.segment || address.bus || address.slot != 1 || address.function ||
        address.offset < 0x60 || address.offset > 0x63)
        return false;
    for (unsigned i = 0; i < change_count; ++i)
        if (changes[i].field == address)
            return false;
    uint32_t previous;
    if (!read_pci(address.segment, address.bus, address.slot, address.function, address.offset, 1,
                  previous) ||
        previous > UINT8_MAX || !(previous & 0x80))
        return false;
    changes[change_count++] = {address, uint8_t(previous), programming_gsi};
    change_emitted = true;
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

bool accept_root_window(unsigned tag, Cursor item, uint16_t segment, uint8_t bus,
                        PciRootWindows& windows) {
    unsigned width;
    switch (tag) {
    case 0x87:
        width = 4;
        break; // DWord Address Space
    case 0x88:
        width = 2;
        break; // Word Address Space
    case 0x8a:
    case 0x8b:
        width = 8;
        break; // QWord and Extended Address Space
    default:
        return true;
    }
    const bool extended = tag == 0x8b;
    uint64_t type, general, flags;
    if (!item.read(1, type) || !item.read(1, general) || !item.read(1, flags))
        return false;
    if (extended) {
        uint64_t revision;
        if (!item.read(2, revision) || revision != 1)
            return false;
    }
    uint64_t granularity, minimum, maximum, translation, length, attributes = 0;
    if (!item.read(width, granularity) || !item.read(width, minimum) ||
        !item.read(width, maximum) || !item.read(width, translation) || !item.read(width, length) ||
        (extended && (!item.read(8, attributes) || item.left)))
        return false;
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

Namespace* load_namespace(const DefinitionBlocks& blocks, PciBridges* bridges,
                          PciConfigRead read_pci, PciLinkProgram program) {
    if (blocks.ssdt_count > max_root_entries)
        return nullptr;
    auto* space = static_cast<Namespace*>(alloc(sizeof(Namespace)));
    if (!space)
        return nullptr;
    space->count = 0;
    space->steps = 32768;
    space->used_values = 0;
    space->used_bytes = 0;
    space->integer_mask = blocks.dsdt.table && blocks.dsdt.length >= 36 && blocks.dsdt.table[8] >= 2
                              ? UINT64_MAX
                              : UINT32_MAX;
    space->bridges = bridges;
    space->read_pci = read_pci;
    space->link_program = program;
    space->change_count = 0;
    space->programming_gsi = 0;
    space->change_emitted = false;
    space->link_evaluation = false;
    auto load = [&](const DefinitionBlock& block) {
        return block.table && block.length >= 36 &&
               space->load({block.table + 36, block.length - 36}, {}, 0);
    };
    bool ok = load(blocks.dsdt);
    for (size_t i = 0; ok && i < blocks.ssdt_count; ++i)
        ok = load(blocks.ssdt[i]);
    if (!ok) {
        release(space);
        return nullptr;
    }
    return space;
}
} // namespace

bool decode_pci_root_windows(const DefinitionBlocks& blocks, PciRootWindows& result) {
    result.count = 0;
    auto* space = load_namespace(blocks, nullptr, nullptr, {});
    if (!space)
        return false;
    const bool ok = pci_root_windows(*space, result);
    release(space);
    if (!ok)
        result.count = 0;
    return ok;
}

bool decode_i2c_hid_devices(const DefinitionBlocks& blocks, I2cHidDevices& result) {
    result.count = 0;
    auto* space = load_namespace(blocks, nullptr, nullptr, {});
    if (!space)
        return false;
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
