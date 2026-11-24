// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/aml_objects.cpp
 * @brief   Resolve AML objects and retain named package contents.
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
#include "aml_internal.hpp"

namespace ax::Acpi::Aml {
Value* Namespace::reserve_package_values(size_t count) {
    constexpr size_t capacity = sizeof(values) / sizeof(*values);
    if (count > capacity - used_values - persistent_values)
        return nullptr;
    persistent_values += unsigned(count);
    return values + capacity - persistent_values;
}

bool Namespace::retain_value(Value& result, const Value& input, unsigned depth) {
    if (depth >= max_depth)
        return false;
    result = input;
    switch (input.type) {
    case Type::None:
    case Type::Integer:
    case Type::Device:
    case Type::ObjectReference:
        return true;
    case Type::Package:
        result.entries = reserve_package_values(input.number);
        if (!result.entries)
            return false;
        for (unsigned i = 0; i < input.number; ++i)
            if (!retain_value(result.entries[i], input.entries[i], depth + 1))
                return false;
        return true;
    case Type::Buffer:
    case Type::String: {
        const auto length = input.content.left;
        if (length > sizeof(buffers) - used_bytes - persistent_bytes)
            return false;
        persistent_bytes += unsigned(length);
        auto* begin = buffers + sizeof(buffers) - persistent_bytes;
        if (length)
            memmove(begin, input.content.next, length);
        result.content = {begin, length};
        result.bytes = input.type == Type::Buffer ? begin : nullptr;
        return true;
    }
    default:
        return false;
    }
}

bool Namespace::replace_package_element(Value& target, const Value& input) {
    constexpr size_t capacity = sizeof(values) / sizeof(*values);
    const auto address = reinterpret_cast<uintptr_t>(&target);
    if (address < reinterpret_cast<uintptr_t>(values + capacity - persistent_values) ||
        address >= reinterpret_cast<uintptr_t>(values + capacity)) {
        target = input;
        return true;
    }

    const unsigned saved_values = persistent_values, saved_bytes = persistent_bytes;
    Value replacement{};
    if (!retain_value(replacement, input)) {
        persistent_values = saved_values;
        persistent_bytes = saved_bytes;
        return false;
    }
    target = replacement;
    return true;
}

bool Namespace::value(const Object& object, Value& result, unsigned depth) {
    switch (object.kind) {
    case Kind::Device:
        result = {Type::Device, 0, {}, &object};
        return true;
    case Kind::PciField:
    case Kind::DiagnosticPciField:
        return read_field(object, result, depth);
    case Kind::MemoryField:
        return read_memory_field(object, result, depth);
    case Kind::EmbeddedControllerField:
    case Kind::CmosField:
        return read_power_field(object, result, depth);
    case Kind::BufferField: {
        const auto number =
            read_buffer_bits(object.region->content.next, object.integer, object.arguments);
        result = {Type::Integer, number & integer_mask, {}, nullptr};
        return true;
    }
    case Kind::Data:
        break;
    default:
        return false;
    }
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
    if (object.package) {
        result = *object.package;
        return true;
    }
    Cursor stream = object.content;
    if (stream.peek() != 0x12)
        return evaluate(stream, parent(object.path), nullptr, result, depth) && !stream.left;

    const unsigned scratch_values = used_values, scratch_bytes = used_bytes;
    Value temporary{};
    if (!evaluate(stream, parent(object.path), nullptr, temporary, depth) || stream.left) {
        used_values = scratch_values;
        used_bytes = scratch_bytes;
        return false;
    }
    const unsigned saved_values = persistent_values, saved_bytes = persistent_bytes;
    auto* package = reserve_package_values(1);
    const bool ok = package && retain_value(*package, temporary);
    used_values = scratch_values;
    used_bytes = scratch_bytes;
    if (!ok) {
        persistent_values = saved_values;
        persistent_bytes = saved_bytes;
        return false;
    }

    // Index references must survive repeated reads of the named package.
    object.package = package;
    result = *package;
    return true;
}
} // namespace ax::Acpi::Aml
