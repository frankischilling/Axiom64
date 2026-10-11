// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/xattr.hpp"
#include "core/base.hpp"

namespace ax {
int xattr_name(const char* name, XattrName& result) {
    size_t length = strlen(name);
    if (!length || length > 255)
        return -34;
    constexpr unsigned indexes[] = {1, 4, 6};
    for (unsigned index : indexes) {
        auto prefix = xattr_prefix(index);
        size_t prefix_length = strlen(prefix);
        if (length >= prefix_length && !memcmp(name, prefix, prefix_length)) {
            if (length == prefix_length)
                return -22;
            result = {index, name + prefix_length};
            return 0;
        }
    }
    return -95;
}

const char* xattr_prefix(unsigned index) {
    switch (index) {
    case 1:
        return "user.";
    case 4:
        return "trusted.";
    case 6:
        return "security.";
    default:
        return nullptr;
    }
}

namespace {
bool matches(const Xattr& attribute, const XattrName& name) {
    return attribute.index == name.index && !strcmp(attribute.name, name.suffix);
}

void destroy(Xattr* attribute) {
    release(attribute->value);
    release(attribute);
}
} // namespace

int64_t xattr_store_get(const Xattr* attributes, const XattrName& name, void* buffer,
                        size_t capacity) {
    for (auto attribute = attributes; attribute; attribute = attribute->next)
        if (matches(*attribute, name)) {
            if (!capacity)
                return attribute->size;
            if (capacity < attribute->size)
                return -34;
            if (attribute->size)
                memcpy(buffer, attribute->value, attribute->size);
            return attribute->size;
        }
    return -61;
}

int64_t xattr_store_list(const Xattr* attributes, void* buffer, size_t capacity, bool trusted) {
    size_t needed = 0;
    for (auto attribute = attributes; attribute; attribute = attribute->next) {
        auto prefix = xattr_prefix(attribute->index);
        if (!prefix || (attribute->index == 4 && !trusted))
            continue;
        size_t bytes = strlen(prefix) + strlen(attribute->name) + 1;
        if (bytes > xattr_list_max - needed)
            return -7;
        needed += bytes;
    }
    if (!capacity)
        return needed;
    if (capacity < needed)
        return -34;
    auto output = static_cast<char*>(buffer);
    for (auto attribute = attributes; attribute; attribute = attribute->next) {
        auto prefix = xattr_prefix(attribute->index);
        if (!prefix || (attribute->index == 4 && !trusted))
            continue;
        size_t length = strlen(prefix);
        memcpy(output, prefix, length);
        output += length;
        length = strlen(attribute->name) + 1;
        memcpy(output, attribute->name, length);
        output += length;
    }
    return needed;
}

int xattr_store_set(Xattr*& attributes, const XattrName& name, const void* value, size_t size,
                    unsigned flags) {
    if (flags & ~3u)
        return -22;
    if (size > xattr_value_max)
        return -7;
    if (!name.suffix[0] || strlen(name.suffix) > 255)
        return -22;
    auto slot = &attributes;
    while (*slot && !matches(**slot, name))
        slot = &(*slot)->next;
    if (!*slot && (flags & 2))
        return -61;
    if (*slot && (flags & 1))
        return -17;
    auto replacement = static_cast<Xattr*>(alloc(sizeof(Xattr)));
    if (!replacement)
        return -12;
    *replacement = {};
    if (size) {
        replacement->value = static_cast<uint8_t*>(alloc(size));
        if (!replacement->value) {
            release(replacement);
            return -12;
        }
        memcpy(replacement->value, value, size);
    }
    replacement->size = size;
    replacement->index = name.index;
    memcpy(replacement->name, name.suffix, strlen(name.suffix) + 1);
    auto previous = *slot;
    replacement->next = previous ? previous->next : nullptr;
    *slot = replacement;
    if (previous)
        destroy(previous);
    return 0;
}

int xattr_store_remove(Xattr*& attributes, const XattrName& name) {
    auto slot = &attributes;
    while (*slot && !matches(**slot, name))
        slot = &(*slot)->next;
    if (!*slot)
        return -61;
    auto previous = *slot;
    *slot = previous->next;
    destroy(previous);
    return 0;
}

void xattr_store_destroy(Xattr*& attributes) {
    while (attributes) {
        auto next = attributes->next;
        destroy(attributes);
        attributes = next;
    }
}
} // namespace ax
