// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml_internal.hpp
 * @brief   Shares the bounded AML namespace and evaluator types.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Internal state used by the interpreter and ACPI resource discovery.
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
#include "firmware/aml.hpp"
#include "core/base.hpp"

namespace ax::Acpi::Aml {

constexpr unsigned max_depth = 16;
constexpr unsigned max_evaluation_depth = 48;
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

struct Path {
    uint32_t segments[max_depth];
    unsigned count;
};

struct Name {
    Path path;
    unsigned parents;
    bool absolute;
};

bool name_character(uint8_t byte, bool first);
bool read_name(Cursor&, Name&);
Path parent(Path);
bool append(const Path&, const Name&, Path&);
bool match(const Path&, const Path&);
uint64_t read_buffer_bits(const uint8_t*, uint64_t offset, unsigned length);
bool resource_payload(Cursor, size_t&);

enum class Kind : uint8_t {
    Scope,
    Device,
    Data,
    Method,
    Opaque,
    Mutex,
    Event,
    Region,
    PciField,
    DiagnosticPciField,
    InterfaceQuery,
    MemoryField,
    BufferField
};
enum class Type : uint8_t {
    None,
    Integer,
    Buffer,
    Package,
    Device,
    String,
    Reference,
    ObjectReference,
    LocalRegion,
    LocalMemoryField,
    BufferField
};

struct Object {
    Path path;
    Cursor content;
    uint64_t integer;
    Kind kind;
    unsigned arguments;
    Type assigned;
    const Object* region = nullptr;
    bool firmware_lock = false;
    uint8_t access_bytes = 0;
    bool preserves_field_neighbors = false;
};

struct Value {
    Type type;
    uint64_t number;
    Cursor content;
    const Object* object;
    Value* entries = nullptr;
    uint8_t* bytes = nullptr;
    uint8_t bit_shift = 0;
    uint8_t access_bytes = 0;

    bool is_reference() const {
        return type == Type::Reference || type == Type::ObjectReference;
    }
};

struct Frame {
    enum class LoopControl { none, stop, next };
    static constexpr unsigned max_names = 128;

    struct Named {
        uint32_t name;
        Value value;
    };

    const Value* arguments;
    unsigned count;
    Named (&names)[max_names];
    unsigned& used_names;
    unsigned first_name;
    Value locals[8]{};
    unsigned loops = 0;
    LoopControl loop_control = LoopControl::none;

    Value* find(const Name& name) {
        if (name.absolute || name.parents || name.path.count != 1)
            return nullptr;
        for (unsigned i = first_name; i < used_names; ++i)
            if (names[i].name == name.path.segments[0])
                return &names[i].value;
        return nullptr;
    }

    bool add(const Name& name, Value value) {
        if (name.absolute || name.parents || name.path.count != 1 || used_names == max_names ||
            find(name))
            return false;
        names[used_names++] = {name.path.segments[0], value};
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

struct MemoryOverlayByte {
    uint64_t address;
    uint8_t value, mask;
};

struct Namespace {
    Object* objects;
    uint16_t* index;
    unsigned capacity, index_mask;
    Value values[4096];
    uint8_t buffers[8192];
    // Active methods share this arena. Each nested method releases its own tail on return.
    Frame::Named method_names[Frame::max_names];
    unsigned used_method_names;
    unsigned count;
    unsigned steps;
    unsigned used_values;
    unsigned used_bytes;
    unsigned persistent_bytes;
    uint64_t integer_mask;
    const PciBridges* bridges;
    PciConfigRead read_pci;
    SystemMemoryRead read_system_memory;
    RegisterRead read_registers;
    PciBarRead read_pci_bars;
    PciEcamRead read_pci_ecam;
    void* register_context;
    OsiQuery query_osi;
    PciLinkProgram link_program;
    LinkChange changes[4];
    unsigned change_count;
    uint8_t programming_gsi;
    bool change_emitted;
    bool link_evaluation;
    bool replay_initialization;
    uint64_t replay_time_100ns;
    // The replay runs one AML thread in a private namespace.
    Object* held_mutexes[32];
    unsigned held_mutex_count = 0;
    unsigned active_methods = 0;
    unsigned method_sync_level = 0;
    unsigned memory_overlay_count;
    MemoryOverlayByte memory_overlay[128];

    uint16_t& index_slot(const Path& path) {
        uint64_t hash = 14695981039346656037ull;
        for (unsigned i = 0; i < path.count; ++i)
            hash = (hash ^ path.segments[i]) * 1099511628211ull;
        unsigned slot = unsigned(hash ^ (hash >> 32)) & index_mask;
        // The index has at least two slots per object.
        while (index[slot] && !match(objects[index[slot] - 1].path, path))
            slot = (slot + 1) & index_mask;
        return index[slot];
    }

    Object* find(const Path& path) {
        const unsigned entry = index_slot(path);
        return entry ? &objects[entry - 1] : nullptr;
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
        if (!path.count || count == capacity)
            return false;
        auto& entry = index_slot(path);
        if (entry)
            return false;
        objects[count++] = {path, content, 0, kind, arguments, Type::None};
        entry = uint16_t(count);
        return true;
    }

    bool load(Cursor stream, const Path& scope, unsigned depth);
    bool load_fields(Cursor, const Path&);
    bool declare_buffer_field(Cursor&, const Path&, unsigned opcode, unsigned depth);
    bool retain_buffer(Object&, Value&);
    uint8_t* scratch_buffer(size_t);
    bool field_address(const Object&, ConfigField&, unsigned depth, bool* absent = nullptr);
    bool pci_address(Path, ConfigField&, unsigned depth = 0, bool* absent = nullptr);
    bool pci_branch_absent(ConfigField);
    bool read_field(const Object&, Value&, unsigned depth);
    bool memory_field_bytes(const Object&, uint8_t*, uint64_t& address, size_t& length,
                            unsigned depth);
    bool read_memory_field(const Object&, Value&, unsigned depth);
    bool read_memory_bytes(uint64_t address, uint8_t*, size_t, bool lock, bool local);
    bool read_local_memory(const Value& field, Value& result);
    void apply_memory_overlay(uint64_t address, uint8_t* data, size_t bytes) const;
    bool stage_memory_bits(uint64_t address, unsigned shift, unsigned bits, uint64_t number);
    bool declare_local_region(Cursor&, const Path&, Frame&, unsigned depth);
    bool declare_local_fields(Cursor&, Frame&);
    bool stage_memory_field(const Object&, Value, unsigned depth);
    bool stage_field(const Object&, Value, unsigned depth);

    unsigned sync_level() const {
        return held_mutex_count
                   ? max(method_sync_level, held_mutexes[held_mutex_count - 1]->arguments)
                   : method_sync_level;
    }

    bool synchronize(unsigned opcode, Cursor&, const Path&, Frame&, Value&, unsigned depth);
    bool evaluate(Cursor&, const Path&, Frame*, Value&, unsigned depth);
    bool execute(Cursor, const Path&, Frame&, Value&, unsigned depth);
    bool store(Cursor&, const Path&, Frame*, Value, unsigned depth);

    bool value(const Object& object, Value& result, unsigned depth) {
        if (object.kind == Kind::Device) {
            result = {Type::Device, 0, {}, &object};
            return true;
        }
        if (object.kind == Kind::PciField || object.kind == Kind::DiagnosticPciField)
            return read_field(object, result, depth);
        if (object.kind == Kind::MemoryField)
            return read_memory_field(object, result, depth);
        if (object.kind == Kind::BufferField) {
            const auto number =
                read_buffer_bits(object.region->content.next, object.integer, object.arguments);
            result = {Type::Integer, number & integer_mask, {}, nullptr};
            return true;
        }
        if (object.kind != Kind::Data)
            return false;
        if (object.assigned == Type::Integer) {
            result = {Type::Integer, object.integer, {}, nullptr};
            return true;
        }
        if (object.assigned == Type::String) {
            result = {Type::String, 0, object.content, nullptr};
            return true;
        }
        if (object.assigned == Type::Buffer) {
            result = {Type::Buffer, 0,       object.content,
                      nullptr,      nullptr, const_cast<uint8_t*>(object.content.next)};
            return true;
        }
        Cursor stream = object.content;
        return evaluate(stream, parent(object.path), nullptr, result, depth) && !stream.left;
    }

    bool method(const Object& object, const Value* args, unsigned count, Value& result,
                unsigned depth = 0) {
        if (count != object.arguments)
            return false;
        if (object.kind == Kind::InterfaceQuery) {
            if (!query_osi || count != 1 || args[0].type != Type::String)
                return false;
            const auto text = args[0].content;
            result = {
                Type::Integer, query_osi(text.next, text.left) ? integer_mask : 0, {}, nullptr};
            return true;
        }
        if (object.kind != Kind::Method)
            return false;
        const unsigned previous_level = method_sync_level;
        if (replay_initialization && (object.integer & 8)) {
            const unsigned level = object.integer >> 4;
            if (level < sync_level())
                return false;
            method_sync_level = level;
        }
        ++active_methods;
        const unsigned first = used_method_names;
        Frame frame{args, count, method_names, used_method_names, first};
        bool ok = execute(object.content, object.path, frame, result, depth);
        used_method_names = first;
        method_sync_level = previous_level;
        if (!--active_methods && held_mutex_count) {
            // Reject a leaked acquisition and clear it before the next invocation.
            while (held_mutex_count)
                held_mutexes[--held_mutex_count]->integer = 0;
            ok = false;
        }
        return ok;
    }

    bool config(const Path& scope, uint32_t segment, Value& result, unsigned depth = 0) {
        const auto* object = child(scope, segment);
        return object && (object->kind == Kind::Method ? method(*object, nullptr, 0, result, depth)
                                                       : value(*object, result, depth));
    }
};

bool pci_root_id(Value);
Namespace* load_namespace(const DefinitionBlocks&, const PciBridges*, PciConfigRead, PciLinkProgram,
                          SystemMemoryRead = nullptr);
} // namespace ax::Acpi::Aml
