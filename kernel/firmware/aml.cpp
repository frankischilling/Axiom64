// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml.cpp
 * @brief   Loads and evaluates a bounded ACPI AML namespace.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Supports the operations used by the firmware probes.
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

unsigned buffer_field_width(unsigned opcode) {
    switch (opcode) {
    case 0x8a:
        return 32; // CreateDWordField
    case 0x8b:
        return 16; // CreateWordField
    case 0x8c:
        return 8; // CreateByteField
    case 0x8d:
        return 1; // CreateBitField
    case 0x8f:
        return 64; // CreateQWordField
    default:
        return 0;
    }
}

bool buffer_field_offset(Cursor buffer, uint64_t index, unsigned width, uint64_t& offset) {
    const unsigned scale = width == 1 ? 1 : 8;
    if (index > UINT64_MAX / scale || buffer.left > UINT64_MAX / 8)
        return false;
    offset = index * scale;
    const uint64_t bits = buffer.left * 8;
    return offset <= bits && width <= bits - offset;
}

uint64_t read_buffer_bits(const uint8_t* data, uint64_t offset, unsigned length) {
    uint64_t result = 0;
    for (unsigned i = 0; i < length; ++i) {
        const auto bit = offset + i;
        result |= uint64_t((data[bit / 8] >> (bit % 8)) & 1) << i;
    }
    return result;
}

void write_buffer_bits(uint8_t* data, uint64_t offset, unsigned length, uint64_t value) {
    for (unsigned i = 0; i < length; ++i) {
        const auto bit = offset + i;
        const uint8_t mask = 1u << (bit % 8);
        auto& byte = data[bit / 8];
        byte = (byte & ~mask) | ((value >> i) & 1 ? mask : 0);
    }
}

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
        case 0xa0: { // Evaluate supported predicates before loading the selected declarations.
            if (!stream.block(block))
                return false;
            auto literal = block;
            uint64_t condition;
            if (integer(literal, condition)) {
                block = literal;
                condition &= integer_mask;
            } else {
                const unsigned values_before = used_values, bytes_before = used_bytes;
                Value result{};
                if (!read_system_memory || !evaluate(block, scope, nullptr, result, depth + 1) ||
                    result.type != Type::Integer)
                    return false;
                condition = result.number;
                used_values = values_before;
                used_bytes = bytes_before;
            }
            if (condition && !load(block, scope, depth + 1))
                return false;
            if (stream.peek() == 0xa1) {
                Cursor alternative;
                if (!stream.skip(1) || !stream.block(alternative) ||
                    (!condition && !load(alternative, scope, depth + 1)))
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
        case 0x8a: // CreateDWordField
        case 0x8b: // CreateWordField
        case 0x8c: // CreateByteField
        case 0x8d: // CreateBitField
        case 0x8f: // CreateQWordField
            if (!read_system_memory || !declare_buffer_field(stream, scope, opcode, depth + 1))
                return false;
            break;
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
                objects[count - 1].integer = info;
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
            if (!read_name(stream, other) || !other.path.count || !read_name(stream, name) ||
                !append(scope, name, path) || !add(path, Kind::Opaque))
                return false;
            break;
        case 0x5b01: // Mutex
        case 0x5b02: // Event
            if (!read_name(stream, name) || !append(scope, name, path))
                return false;
            if (opcode == 0x5b01) {
                if (!stream.read(1, info) || info > 15 || !add(path, Kind::Mutex, {}, info))
                    return false;
            } else if (!add(path, Kind::Event)) {
                return false;
            }
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
    if (!region || region->kind != Kind::Region)
        return true;
    const unsigned space = region->content.peek();
    const bool system_memory = space == 0 && read_system_memory;
    const bool diagnostic_pci = space == 2 && read_system_memory;
    if (!system_memory && space != 2)
        return true;
    const unsigned flags = field.peek();
    unsigned access = flags & 15;
    field.skip(1);
    uint64_t offset = 0;
    const uint64_t limit = system_memory ? UINT64_MAX : 4096 * 8;
    const unsigned integer_bits = integer_mask == UINT32_MAX ? 32 : 64;
    while (field.left) {
        auto term = field.peek();
        if (term == 1) { // AccessField
            uint64_t operands;
            if (!field.skip(1) || !field.read(2, operands))
                return false;
            access = (system_memory || diagnostic_pci) && operands >> 8 ? 15 : operands & 15;
            continue;
        }
        if (term == 2 || term == 3)
            return true; // Connections and extended accesses are outside this provider.
        unsigned bits, bytes;
        uint64_t segment = 0;
        if (!(term ? field.read(4, segment) : field.skip(1)) || !field.length(bits, bytes) ||
            bits > limit - offset)
            return false;
        const unsigned access_bits = access && access <= 3 ? 8u << (access - 1) : bits;
        const bool supported =
            system_memory    ? bits && bits <= integer_bits && access <= 1 && !(flags & 0x80)
            : diagnostic_pci ? bits && bits <= 32 && access <= 3 && !(flags & 0x90)
                             : !(offset & 7) && (bits == 8 || bits == 16 || bits == 32) &&
                                   (!access || (access <= 3 && access_bits == bits));
        if (term && supported) {
            Path path = scope;
            if (path.count == max_depth)
                return false;
            for (unsigned i = 0; i < 4; ++i)
                if (!name_character(uint8_t(segment >> (8 * i)), !i))
                    return false;
            path.segments[path.count++] = segment;
            const auto kind = system_memory    ? Kind::MemoryField
                              : diagnostic_pci ? Kind::DiagnosticPciField
                                               : Kind::PciField;
            const bool bit_field = kind != Kind::PciField;
            if (!add(path, kind, {}, bit_field ? bits : bits / 8))
                return false;
            auto& entry = objects[count - 1];
            entry.integer = bit_field ? offset : offset / 8;
            entry.region = region;
            entry.firmware_lock = system_memory && (flags & 0x10);
            entry.preserves_field_neighbors = system_memory && !(flags & 0x60);
            entry.access_bytes = system_memory || (diagnostic_pci && !access) ? 1 : access_bits / 8;
        }
        offset += bits;
    }
    return true;
}

bool Namespace::declare_buffer_field(Cursor& stream, const Path& scope, unsigned opcode,
                                     unsigned depth) {
    const unsigned values_before = used_values, bytes_before = used_bytes;
    Name source, name;
    Path path;
    Value index_value{}, buffer{};
    if (!read_name(stream, source) || !source.path.count ||
        !evaluate(stream, scope, nullptr, index_value, depth + 1) ||
        index_value.type != Type::Integer || !read_name(stream, name) || !name.path.count ||
        !append(scope, name, path))
        return false;
    auto* backing = lookup(scope, source);
    if (!backing || backing->kind != Kind::Data || !value(*backing, buffer, depth + 1) ||
        buffer.type != Type::Buffer)
        return false;
    const unsigned width = buffer_field_width(opcode);
    uint64_t offset;
    if (!buffer_field_offset(buffer.content, index_value.number, width, offset))
        return false;
    if (!retain_buffer(*backing, buffer) || !add(path, Kind::BufferField, {}, width))
        return false;
    auto& field = objects[count - 1];
    field.integer = offset;
    field.region = backing;
    used_values = values_before;
    used_bytes = bytes_before;
    return true;
}

bool Namespace::retain_buffer(Object& object, Value& buffer) {
    if (object.assigned == Type::Buffer)
        return true;
    if (buffer.content.left > sizeof(buffers) - used_bytes - persistent_bytes)
        return false;
    persistent_bytes += unsigned(buffer.content.left);
    auto* copy = buffers + sizeof(buffers) - persistent_bytes;
    memcpy(copy, buffer.content.next, buffer.content.left);
    object.content = {copy, buffer.content.left};
    object.assigned = Type::Buffer;
    buffer.content = object.content;
    buffer.bytes = copy;
    return true;
}

uint8_t* Namespace::scratch_buffer(size_t size) {
    if (size > sizeof(buffers) - used_bytes - persistent_bytes)
        return nullptr;
    auto* result = buffers + used_bytes;
    used_bytes += unsigned(size);
    return result;
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
            reference.type != Type::Reference || input.is_reference())
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
            write_buffer_bits(local->bytes, local->bit_shift, local->number, input.number);
        } else if (local->type == Type::LocalMemoryField) {
            Value current{};
            return replay_initialization && input.type == Type::Integer &&
                   read_local_memory(*local, current) &&
                   stage_memory_bits(local->number + local->bit_shift / 8, local->bit_shift % 8,
                                     local->content.left, input.number);
        } else if (local->type == Type::LocalRegion) {
            return false;
        } else {
            *local = input;
        }
        return true;
    }
    auto* object = lookup(scope, name);
    if (object && object->kind == Kind::PciField)
        return stage_field(*object, input, depth + 1);
    if (object && object->kind == Kind::MemoryField && replay_initialization)
        return stage_memory_field(*object, input, depth + 1);
    if (object && object->kind == Kind::BufferField && !link_evaluation &&
        input.type == Type::Integer) {
        auto* bytes = const_cast<uint8_t*>(object->region->content.next);
        write_buffer_bits(bytes, object->integer, object->arguments, input.number);
        return true;
    }
    Value old{};
    if (link_evaluation || !object || object->kind != Kind::Data ||
        (input.type != Type::Integer && !(replay_initialization && input.type == Type::String)) ||
        !value(*object, old, depth + 1) || old.type != input.type)
        return false;
    if (input.type == Type::String) {
        if (input.content.left > sizeof(buffers) - used_bytes - persistent_bytes)
            return false;
        persistent_bytes += unsigned(input.content.left);
        auto* bytes = buffers + sizeof(buffers) - persistent_bytes;
        memmove(bytes, input.content.next, input.content.left);
        object->content = {bytes, input.content.left};
    } else {
        object->integer = input.number;
    }
    object->assigned = input.type;
    return true;
}

bool integer_result(unsigned opcode, uint64_t left, uint64_t right, uint64_t& result) {
    switch (opcode) {
    case 0x72:
        result = left + right;
        break;
    case 0x74:
        result = left - right;
        break;
    case 0x77:
        result = left * right;
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
    case 0x90:
        result = left && right;
        break;
    case 0x91:
        result = left || right;
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

uint64_t explicit_integer(Cursor string, uint64_t maximum) {
    while (string.peek() == ' ' || (string.peek() >= '\t' && string.peek() <= '\r'))
        string.skip(1);
    unsigned radix = 10;
    if (string.left >= 2 && string.next[0] == '0' &&
        (string.next[1] == 'x' || string.next[1] == 'X')) {
        radix = 16;
        string.skip(2);
    }
    uint64_t result = 0;
    while (string.left) {
        const unsigned character = string.peek();
        unsigned digit = radix;
        if (character >= '0' && character <= '9')
            digit = character - '0';
        else if ((character | 32) >= 'a' && (character | 32) <= 'f')
            digit = (character | 32) - 'a' + 10;
        if (digit >= radix || result > (maximum - digit) / radix)
            break;
        result = result * radix + digit;
        string.skip(1);
    }
    return result;
}

static bool integer_match(unsigned op, uint64_t element, uint64_t operand) {
    switch (op) {
    case 0:
        return true; // MTR
    case 1:
        return element == operand;
    case 2:
        return element <= operand;
    case 3:
        return element < operand;
    case 4:
        return element >= operand;
    case 5:
        return element > operand;
    }
    return false;
}

bool Namespace::synchronize(unsigned opcode, Cursor& stream, const Path& scope, Frame& frame,
                            Value& result, unsigned depth) {
    Name name;
    if (!replay_initialization || !read_name(stream, name) || !name.path.count || frame.find(name))
        return false;
    auto* object = lookup(scope, name);
    const bool mutex = opcode == 0x23 || opcode == 0x27;
    if (!object || object->kind != (mutex ? Kind::Mutex : Kind::Event))
        return false;

    switch (opcode) {
    case 0x23: { // Acquire: the timeout is a literal WordData.
        uint64_t timeout;
        if (!stream.read(2, timeout) || object->arguments < sync_level())
            return false;
        if (!object->integer) {
            if (held_mutex_count == sizeof(held_mutexes) / sizeof(*held_mutexes))
                return false;
            held_mutexes[held_mutex_count++] = object;
        }
        ++object->integer;
        result = {Type::Integer, 0, {}, nullptr};
        return true;
    }
    case 0x24: // Signal
        ++object->integer;
        return true;
    case 0x25: { // Wait
        Value timeout{};
        if (!evaluate(stream, scope, &frame, timeout, depth + 1) || timeout.type != Type::Integer)
            return false;
        // No other AML thread can signal a private event while replay is running.
        if (!object->integer && timeout.number)
            return false;
        result = {Type::Integer, object->integer ? 0 : integer_mask, {}, nullptr};
        if (object->integer)
            --object->integer;
        return true;
    }
    case 0x26: // Reset
        object->integer = 0;
        return true;
    case 0x27: // Release
        if (!object->integer || object->arguments != sync_level())
            return false;
        if (!--object->integer) {
            unsigned slot = held_mutex_count - 1;
            while (held_mutexes[slot] != object)
                --slot;
            // Remaining acquisitions above this one have the same level.
            held_mutexes[slot] = held_mutexes[--held_mutex_count];
        }
        return true;
    }
    return false;
}

bool Namespace::evaluate(Cursor& stream, const Path& scope, Frame* frame, Value& result,
                         unsigned depth) {
    if (depth >= max_evaluation_depth || !steps)
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
    case 0x5b: {
        uint64_t extended;
        if (!stream.skip(1) || !stream.read(1, extended))
            return false;
        if (extended >= 0x23 && extended <= 0x27)
            return frame && synchronize(extended, stream, scope, *frame, result, depth);
        // CondRefOf
        Name source;
        if (extended != 0x12 || !read_name(stream, source) || !source.path.count)
            return false;
        auto* local = frame ? frame->find(source) : nullptr;
        const auto* object = local ? nullptr : lookup(scope, source);
        const bool present = local || object;
        if (present) {
            const Value reference = local ? Value{Type::Reference, 0, {}, nullptr, local}
                                          : Value{Type::ObjectReference, 0, {}, object};
            if (!store(stream, scope, frame, reference, depth + 1))
                return false;
        } else if (frame && stream.peek() >= 0x60 && stream.peek() <= 0x67) {
            stream.skip(1);
        } else {
            Name target;
            if (!read_name(stream, target) ||
                (!target.path.count && (target.absolute || target.parents)))
                return false;
        }
        result = {Type::Integer, present ? integer_mask : 0, {}, nullptr};
        return true;
    }
    case 0x0d: {
        stream.skip(1);
        Cursor text = stream;
        while (stream.left && stream.peek())
            stream.skip(1);
        result = {Type::String, 0, {text.next, text.left - stream.left}, nullptr};
        return stream.skip(1);
    }
    case 0x11: { // Buffer
        Value length{};
        if (!stream.skip(1) || !stream.block(block) ||
            !evaluate(block, scope, frame, length, depth + 1) || length.type != Type::Integer)
            return false;
        number = max(length.number, uint64_t(block.left));
        result = {Type::Buffer, 0, block, nullptr};
        if (frame || number != block.left) {
            result.bytes = scratch_buffer(number);
            if (!result.bytes)
                return false;
            memcpy(result.bytes, block.next, block.left);
            memset(result.bytes + block.left, 0, number - block.left);
            result.content = {result.bytes, size_t(number)};
        }
        return true;
    }
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
    case 0x75:   // Increment
    case 0x76: { // Decrement
        if (!stream.skip(1) || stream.peek() < 0x60 || stream.peek() > 0x67)
            return false;
        auto target = stream;
        if (!evaluate(stream, scope, frame, result, depth + 1) || result.type != Type::Integer)
            return false;
        result.number = (opcode == 0x75 ? result.number + 1 : result.number - 1) & integer_mask;
        return store(target, scope, frame, result, depth + 1);
    }
    case 0x80: { // Bitwise Not
        if (!stream.skip(1) || !evaluate(stream, scope, frame, result, depth + 1) ||
            result.type != Type::Integer)
            return false;
        result.number = ~result.number & integer_mask;
        return store(stream, scope, frame, result, depth + 1);
    }
    case 0x83: // DerefOf
        if (!stream.skip(1) || !evaluate(stream, scope, frame, result, depth + 1))
            return false;
        if (result.type == Type::ObjectReference)
            return value(*result.object, result, depth + 1);
        if (result.type != Type::Reference || result.entries->is_reference())
            return false;
        result = *result.entries;
        return result.type != Type::None;
    case 0x84: { // ConcatenateResTemplate
        Value first{}, second{};
        size_t left, right;
        if (!stream.skip(1) || !evaluate(stream, scope, frame, first, depth + 1) ||
            !evaluate(stream, scope, frame, second, depth + 1) || first.type != Type::Buffer ||
            second.type != Type::Buffer || !resource_payload(first.content, left) ||
            !resource_payload(second.content, right) || left > sizeof(buffers) ||
            right > sizeof(buffers))
            return false;
        const size_t length = left + right + 2;
        auto* bytes = scratch_buffer(length);
        if (!bytes)
            return false;
        if (left)
            memcpy(bytes, first.content.next, left);
        if (right)
            memcpy(bytes + left, second.content.next, right);
        bytes[length - 2] = 0x79;
        uint8_t sum = 0;
        for (size_t i = 0; i < length - 1; ++i)
            sum += bytes[i];
        bytes[length - 1] = uint8_t(0 - sum);
        result = {Type::Buffer, 0, {bytes, length}, nullptr, nullptr, bytes};
        return store(stream, scope, frame, result, depth + 1);
    }
    case 0x88: { // Index
        Value package{}, index{};
        if (!stream.skip(1) || !evaluate(stream, scope, frame, package, depth + 1) ||
            !evaluate(stream, scope, frame, index, depth + 1) || package.type != Type::Package ||
            index.type != Type::Integer || index.number >= package.number)
            return false;
        result = {Type::Reference, 0, {}, nullptr, package.entries + index.number};
        return store(stream, scope, frame, result, depth + 1);
    }
    case 0x89: { // Match
        Value package{}, operands[2]{}, start{};
        uint64_t operators[2]{};
        if (!stream.skip(1) || !evaluate(stream, scope, frame, package, depth + 1) ||
            package.type != Type::Package)
            return false;
        for (unsigned i = 0; i < 2; ++i)
            if (!stream.read(1, operators[i]) || operators[i] > 5 ||
                !evaluate(stream, scope, frame, operands[i], depth + 1) ||
                operands[i].type != Type::Integer)
                return false;
        if (!evaluate(stream, scope, frame, start, depth + 1) || start.type != Type::Integer ||
            start.number >= package.number)
            return false;
        result = {Type::Integer, integer_mask, {}, nullptr};
        for (auto index = start.number; index < package.number; ++index) {
            const auto& element = package.entries[index];
            if (element.type == Type::None)
                continue;
            // The firmware resource evaluator supports integer package matching.
            if (element.type != Type::Integer)
                return false;
            if (integer_match(operators[0], element.number, operands[0].number) &&
                integer_match(operators[1], element.number, operands[1].number)) {
                result.number = index;
                break;
            }
        }
        return true;
    }
    case 0x99: { // ToInteger
        Value input{};
        if (!stream.skip(1) || !evaluate(stream, scope, frame, input, depth + 1))
            return false;
        if (input.type == Type::Integer)
            number = input.number;
        else if (input.type == Type::String)
            number = explicit_integer(input.content, integer_mask);
        else if (input.type == Type::Buffer && input.content.left) {
            const unsigned width = integer_mask == UINT32_MAX ? 4 : 8;
            if (!input.content.read(min(size_t(width), input.content.left), number))
                return false;
        } else
            return false;
        result = {Type::Integer, number & integer_mask, {}, nullptr};
        return store(stream, scope, frame, result, depth + 1);
    }
    case 0x72:   // Add
    case 0x74:   // Subtract
    case 0x77:   // Multiply
    case 0x79:   // ShiftLeft
    case 0x7a:   // ShiftRight
    case 0x7b:   // And
    case 0x7d:   // Or
    case 0x90:   // LAnd
    case 0x91:   // LOr
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
        if (opcode >= 0x90) {
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
        if (local->type == Type::LocalMemoryField)
            return read_local_memory(*local, result);
        if (local->type == Type::LocalRegion)
            return false;
        if (local->type == Type::BufferField) {
            number = read_buffer_bits(local->bytes, local->bit_shift, local->number);
            result = {Type::Integer, number & integer_mask, {}, nullptr};
        } else {
            result = *local;
        }
        return true;
    }
    const auto* object = lookup(scope, name);
    if (!object)
        return false;
    if (object->kind != Kind::Method && object->kind != Kind::InterfaceQuery)
        return value(*object, result, depth + 1);
    Value arguments[7]{};
    for (unsigned i = 0; i < object->arguments; ++i)
        if (!evaluate(stream, scope, frame, arguments[i], depth + 1))
            return false;
    return method(*object, arguments, object->arguments, result, depth + 1);
}

bool Namespace::declare_local_region(Cursor& stream, const Path& scope, Frame& frame,
                                     unsigned depth) {
    Name name;
    uint64_t space;
    Value address{}, length{};
    if (!read_name(stream, name) || !stream.read(1, space) || space != 0 ||
        !evaluate(stream, scope, &frame, address, depth + 1) || address.type != Type::Integer ||
        !evaluate(stream, scope, &frame, length, depth + 1) || length.type != Type::Integer ||
        !length.number || length.number > UINT64_MAX - address.number)
        return false;
    return frame.add(name, {Type::LocalRegion, address.number, {nullptr, length.number}, nullptr});
}

bool Namespace::declare_local_fields(Cursor& stream, Frame& frame) {
    Cursor field;
    Name name;
    uint64_t flags;
    if (!stream.block(field) || !read_name(field, name) || !field.read(1, flags))
        return false;
    const bool bar_pair = flags == 3 && !replay_initialization && read_pci_bars;
    const bool ecam = (flags == 2 || flags == 3) && replay_initialization && read_pci_ecam;
    if (!bar_pair && !ecam && (!replay_initialization || (flags != 0 && flags != 1)))
        return false;
    const auto* region = frame.find(name);
    if (!region || region->type != Type::LocalRegion)
        return false;
    const unsigned unit = bar_pair || ecam ? 1u << (flags - 1) : 1;
    const unsigned unit_bits = 8 * unit;

    uint64_t offset = 0;
    while (field.left) {
        const unsigned term = field.peek();
        unsigned bits, encoded_bytes;
        Name field_name{};
        if ((term == 0 ? !field.skip(1) : !read_name(field, field_name)) ||
            !field.length(bits, encoded_bytes))
            return false;
        const uint64_t end = offset + bits;
        if (end < offset || end / 8 + (end % 8 != 0) > region->content.left)
            return false;
        const unsigned shift = offset % unit_bits;
        if (term &&
            (!bits || bits > (integer_mask == UINT32_MAX ? 32u : 64u) || region->number % unit ||
             (bar_pair && (shift || bits % 32)) ||
             (ecam && (end / unit_bits + (end % unit_bits != 0)) > region->content.left / unit) ||
             !frame.add(field_name, {Type::LocalMemoryField,
                                     region->number + (offset - shift) / 8,
                                     {nullptr, bits},
                                     nullptr,
                                     nullptr,
                                     nullptr,
                                     uint8_t(shift),
                                     uint8_t(unit == 1 ? 0 : unit)})))
            return false;
        offset = end;
    }
    return true;
}

bool Namespace::execute(Cursor stream, const Path& scope, Frame& frame, Value& result,
                        unsigned depth) {
    if (depth >= max_evaluation_depth)
        return false;
    while (stream.left && result.type == Type::None &&
           frame.loop_control == Frame::LoopControl::none) {
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
        case 0x8a:   // CreateDWordField
        case 0x8b:   // CreateWordField
        case 0x8c:   // CreateByteField
        case 0x8d:   // CreateBitField
        case 0x8f: { // CreateQWordField
            Value buffer{}, offset{};
            Name name;
            const unsigned width = buffer_field_width(opcode);
            uint64_t bit;
            Cursor source = stream;
            if (!evaluate(stream, scope, &frame, buffer, depth + 1) || buffer.type != Type::Buffer)
                return false;
            Name backing_name;
            if (read_system_memory && !link_evaluation && read_name(source, backing_name) &&
                backing_name.path.count && source.next == stream.next &&
                !frame.find(backing_name)) {
                auto* backing = lookup(scope, backing_name);
                if (backing && backing->kind == Kind::Data && !retain_buffer(*backing, buffer))
                    return false;
            }
            if (!buffer.bytes || !evaluate(stream, scope, &frame, offset, depth + 1) ||
                !read_name(stream, name) || offset.type != Type::Integer ||
                !buffer_field_offset(buffer.content, offset.number, width, bit) ||
                !frame.add(name, {Type::BufferField,
                                  width,
                                  {},
                                  nullptr,
                                  nullptr,
                                  buffer.bytes + bit / 8,
                                  uint8_t(bit % 8)}))
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
            ++frame.loops;
            while (result.type == Type::None) {
                Cursor body = loop;
                Value test{};
                if (!evaluate(body, scope, &frame, test, depth + 1) || test.type != Type::Integer)
                    return false;
                if (!test.number)
                    break;
                if (!execute(body, scope, frame, result, depth + 1))
                    return false;
                const auto control = frame.loop_control;
                frame.loop_control = Frame::LoopControl::none;
                if (control == Frame::LoopControl::stop)
                    break;
            }
            --frame.loops;
            break;
        }
        case 0x9f: // Continue
        case 0xa5: // Break
            if (!frame.loops)
                return false;
            frame.loop_control =
                opcode == 0x9f ? Frame::LoopControl::next : Frame::LoopControl::stop;
            break;
        case 0xa3: // NoOp
            break;
        case 0x86: { // Notify
            Name target;
            Value event{};
            if (!replay_initialization || !read_name(stream, target) ||
                !(target.absolute || target.parents || target.path.count))
                return false;
            const auto* device = lookup(scope, target);
            if (!device || device->kind != Kind::Device ||
                !evaluate(stream, scope, &frame, event, depth + 1) || event.type != Type::Integer ||
                (event.number != 0 && event.number != 2))
                return false;
            // Bus Check and Device Wake have no recipient in this private replay.
            break;
        }
        case 0xa4: // Return
            return evaluate(stream, scope, &frame, result, depth + 1) &&
                   result.type != Type::None && !result.is_reference();
        case 0x5b: // Extended opcode
            if ((replay_initialization || read_pci_bars) &&
                (stream.peek() == 0x80 || stream.peek() == 0x81)) {
                const unsigned extended = stream.peek();
                stream.skip(1);
                const bool declared = extended == 0x80
                                          ? declare_local_region(stream, scope, frame, depth)
                                          : declare_local_fields(stream, frame);
                if (!declared)
                    return false;
                break;
            }
            [[fallthrough]]; // Other supported operations are evaluated as expressions.
        case 0x70:           // Store
        case 0x84:           // ConcatenateResTemplate
        case 0x99:           // ToInteger
        case 0x72:           // Add
        case 0x74:           // Subtract
        case 0x77:           // Multiply
        case 0x75:           // Increment
        case 0x76:           // Decrement
        case 0x79:           // ShiftLeft
        case 0x7a:           // ShiftRight
        case 0x7b:           // And
        case 0x7d:           // Or
        case 0x80: {         // Bitwise Not
            Value ignored{};
            if (!evaluate(term, scope, &frame, ignored, depth + 1))
                return false;
            stream = term;
            break;
        }
        default: {
            Name name;
            Cursor encoded = term;
            if (!replay_initialization || !read_name(encoded, name) || !name.path.count ||
                frame.find(name))
                return false;
            const auto* object = lookup(scope, name);
            Value ignored{};
            if (!object || object->kind != Kind::Method ||
                !evaluate(term, scope, &frame, ignored, depth + 1))
                return false;
            stream = term;
            break;
        }
        }
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

struct ConfigSpan {
    uint64_t offset;
    unsigned bytes, shift;
};

ConfigSpan config_span(const Object& field) {
    if (field.kind == Kind::PciField)
        return {field.integer, field.arguments, 0};
    const unsigned unit = 8 * field.access_bytes;
    const unsigned shift = field.integer % unit;
    const unsigned units = (shift + field.arguments + unit - 1) / unit;
    return {field.integer / unit * field.access_bytes, units * field.access_bytes, shift};
}

bool Namespace::field_address(const Object& field, ConfigField& address, unsigned depth,
                              bool* absent) {
    if (depth >= max_evaluation_depth)
        return false;
    const auto* region = field.region;
    Cursor operands = region->content;
    operands.skip(1);
    uint64_t base, length;
    const auto span = config_span(field);
    if (!integer(operands, base) || !integer(operands, length) || operands.left || base >= 4096 ||
        length > 4096 - base || span.offset > length || span.bytes > length - span.offset ||
        ((base + span.offset) & (field.access_bytes - 1)))
        return false;

    if (!pci_address(parent(region->path), address, depth, absent))
        return false;
    address.offset = base + span.offset;
    return true;
}

bool Namespace::pci_branch_absent(ConfigField port) {
    if (!read_pci)
        return false;
    uint32_t vendor, class_code, header, buses;
    const auto read = [&](uint16_t offset, uint8_t width, uint32_t& value) {
        return read_pci(port.segment, port.bus, port.slot, port.function, offset, width, value);
    };
    if (!read(0, 2, vendor))
        return false;
    if (vendor == UINT16_MAX)
        return true;
    return read(0x0a, 2, class_code) && class_code == 0x0604 && read(0x0e, 1, header) &&
           (header & 0x7f) == 1 && read(0x18, 4, buses) && !(buses & 0x00ffff00) &&
           uint8_t(buses) == port.bus;
}

bool Namespace::pci_address(Path root, ConfigField& address, unsigned depth, bool* absent) {
    if (depth >= max_evaluation_depth)
        return false;
    uint32_t addresses[max_depth];
    unsigned used = 0;
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
    if (!used && !absent)
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
        if (!next) {
            // Diagnostic AML may describe a child of an unused root port. Confirm that no
            // secondary bus is reachable before returning the config-space absent value.
            const ConfigField port{uint16_t(segment.number), 0, uint8_t(bus.number),
                                   uint8_t(address >> 16), uint8_t(address & 7)};
            if (!absent || !pci_branch_absent(port))
                return false;
            *absent = true;
            return true;
        }
        bus.number = next->secondary;
        subordinate = next->subordinate;
    }
    const uint32_t endpoint = used ? addresses[0] : 0;
    address = {uint16_t(segment.number), 0, uint8_t(bus.number), uint8_t(endpoint >> 16),
               uint8_t(endpoint & 7)};
    return true;
}

bool Namespace::read_field(const Object& field, Value& result, unsigned depth) {
    ConfigField address{};
    bool absent = false;
    if (!read_pci || !field_address(field, address, depth,
                                    field.kind == Kind::DiagnosticPciField ? &absent : nullptr))
        return false;
    if (absent) {
        result = {Type::Integer, (1ull << field.arguments) - 1, {}, nullptr};
        return true;
    }
    if (field.kind == Kind::PciField && field.arguments == 1)
        for (unsigned i = 0; i < change_count; ++i)
            if (changes[i].field == address) {
                result = {Type::Integer, changes[i].next, {}, nullptr};
                return true;
            }
    uint64_t value = 0;
    const auto span = config_span(field);
    for (unsigned i = 0; i < span.bytes; i += field.access_bytes) {
        uint32_t part;
        if (!read_pci(address.segment, address.bus, address.slot, address.function,
                      address.offset + i, field.access_bytes, part))
            return false;
        const uint64_t mask = (1ull << (field.access_bytes * 8)) - 1;
        value |= (part & mask) << (i * 8);
    }
    if (field.kind == Kind::DiagnosticPciField)
        value = (value >> span.shift) & ((1ull << field.arguments) - 1);
    result = {Type::Integer, value, {}, nullptr};
    return true;
}

bool Namespace::memory_field_bytes(const Object& field, uint8_t* data, uint64_t& address,
                                   size_t& bytes, unsigned depth) {
    Cursor operands = field.region->content;
    operands.skip(1);
    const Path scope = parent(field.region->path);
    Value base{}, length{};
    if (!read_system_memory || !evaluate(operands, scope, nullptr, base, depth + 1) ||
        !evaluate(operands, scope, nullptr, length, depth + 1) || operands.left ||
        base.type != Type::Integer || length.type != Type::Integer ||
        length.number > UINT64_MAX - base.number)
        return false;
    const uint64_t offset = field.integer / 8;
    bytes = (field.integer % 8 + field.arguments + 7) / 8;
    if (offset >= length.number || bytes > length.number - offset)
        return false;
    address = base.number + offset;
    return read_memory_bytes(address, data, bytes, field.firmware_lock, false);
}

bool Namespace::read_memory_bytes(uint64_t address, uint8_t* data, size_t bytes, bool lock,
                                  bool local) {
    if ((!read_system_memory || !read_system_memory(address, data, bytes, lock)) &&
        (!local || lock || !read_registers ||
         !read_registers(register_context, address, data, bytes)))
        return false;
    apply_memory_overlay(address, data, bytes);
    return true;
}

void Namespace::apply_memory_overlay(uint64_t address, uint8_t* data, size_t bytes) const {
    for (unsigned i = 0; i < memory_overlay_count; ++i) {
        const auto& entry = memory_overlay[i];
        if (entry.address < address || entry.address - address >= bytes)
            continue;
        auto& byte = data[entry.address - address];
        byte = (byte & ~entry.mask) | entry.value;
    }
}

bool Namespace::read_memory_field(const Object& field, Value& result, unsigned depth) {
    uint64_t address;
    size_t bytes;
    uint8_t data[9]{};
    if (!memory_field_bytes(field, data, address, bytes, depth))
        return false;
    const uint64_t number = read_buffer_bits(data, field.integer % 8, field.arguments);
    result = {Type::Integer, number & integer_mask, {}, nullptr};
    return true;
}

bool Namespace::read_local_memory(const Value& field, Value& result) {
    const unsigned bits = field.content.left;
    if (field.access_bytes == 4 && !replay_initialization) {
        uint32_t values[2]{};
        if (!read_pci_bars(field.number, values, bits / 32))
            return false;
        result = {Type::Integer, values[0] | (uint64_t(values[1]) << 32), {}, nullptr};
        return true;
    }
    uint8_t data[12]{}; // A 64-bit field can span three aligned dwords.
    if (const unsigned unit = field.access_bytes) {
        const unsigned unit_bits = 8 * unit;
        const unsigned bytes = (field.bit_shift + bits + unit_bits - 1) / unit_bits * unit;
        // One field cannot straddle two PCI functions.
        if (bytes > 4096 - (field.number & 0xfff))
            return false;
        for (unsigned offset = 0; offset < bytes; offset += unit) {
            uint32_t value;
            if (!read_pci_ecam(field.number + offset, unit, value))
                return false;
            for (unsigned byte = 0; byte < unit; ++byte)
                data[offset + byte] = uint8_t(value >> (8 * byte));
        }
        apply_memory_overlay(field.number, data, bytes);
    } else if (!read_memory_bytes(field.number, data, (field.bit_shift + bits + 7) / 8, false,
                                  true)) {
        return false;
    }
    result = {Type::Integer, read_buffer_bits(data, field.bit_shift, bits), {}, nullptr};
    return true;
}

bool Namespace::stage_memory_field(const Object& field, Value input, unsigned depth) {
    uint64_t address;
    size_t bytes;
    uint8_t data[9]{};
    if (link_evaluation || input.type != Type::Integer || !field.preserves_field_neighbors ||
        !memory_field_bytes(field, data, address, bytes, depth))
        return false;
    return stage_memory_bits(address, field.integer % 8, field.arguments, input.number);
}

bool Namespace::stage_memory_bits(uint64_t address, unsigned shift, unsigned bits,
                                  uint64_t number) {
    uint8_t data[9]{}, mask[9]{};
    const unsigned bytes = (shift + bits + 7) / 8;
    write_buffer_bits(data, shift, bits, number);
    write_buffer_bits(mask, shift, bits, integer_mask);

    // Store only the written bits so overlapping fields see the latest value.
    for (size_t byte = 0; byte < bytes; ++byte) {
        unsigned i = 0;
        while (i < memory_overlay_count && memory_overlay[i].address != address + byte)
            ++i;
        if (i == memory_overlay_count) {
            if (i == sizeof(memory_overlay) / sizeof(*memory_overlay))
                return false;
            memory_overlay[memory_overlay_count++] = {address + byte, 0, 0};
        }
        auto& entry = memory_overlay[i];
        entry.value = (entry.value & ~mask[byte]) | (data[byte] & mask[byte]);
        entry.mask |= mask[byte];
    }
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

Namespace* load_namespace(const DefinitionBlocks& blocks, const PciBridges* bridges,
                          PciConfigRead read_pci, PciLinkProgram program,
                          SystemMemoryRead read_system_memory) {
    if (blocks.ssdt_count > max_root_entries)
        return nullptr;
    const unsigned capacity = read_system_memory ? 8192 : 768;
    const unsigned slots = read_system_memory ? 16384 : 2048;
    auto* space = static_cast<Namespace*>(
        alloc(sizeof(Namespace) + capacity * sizeof(Object) + slots * sizeof(uint16_t)));
    if (!space)
        return nullptr;
    space->objects = reinterpret_cast<Object*>(space + 1);
    space->index = reinterpret_cast<uint16_t*>(space->objects + capacity);
    space->capacity = capacity;
    space->index_mask = slots - 1;
    memset(space->index, 0, slots * sizeof(*space->index));
    space->count = 0;
    space->steps = 32768;
    space->used_values = 0;
    space->used_bytes = 0;
    space->used_method_names = 0;
    space->persistent_bytes = 0;
    space->integer_mask = blocks.dsdt.table && blocks.dsdt.length >= 36 && blocks.dsdt.table[8] >= 2
                              ? UINT64_MAX
                              : UINT32_MAX;
    space->bridges = bridges;
    space->read_pci = read_pci;
    space->read_system_memory = read_system_memory;
    space->read_registers = nullptr;
    space->read_pci_bars = nullptr;
    space->read_pci_ecam = nullptr;
    space->register_context = nullptr;
    space->query_osi = nullptr;
    space->link_program = program;
    space->change_count = 0;
    space->programming_gsi = 0;
    space->change_emitted = false;
    space->link_evaluation = false;
    space->replay_initialization = false;
    space->held_mutex_count = 0;
    space->active_methods = 0;
    space->method_sync_level = 0;
    space->memory_overlay_count = 0;
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
} // namespace ax::Acpi::Aml
