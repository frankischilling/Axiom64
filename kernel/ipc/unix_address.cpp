// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_address.hpp"

namespace ax {
bool UnixAddressValue::same(const UnixAddressValue& other) const {
    return valid() && other.valid() && length == other.length && !memcmp(path, other.path, length);
}

bool UnixAddressValue::valid() const {
    if (length > sizeof(path))
        return false;
    if (!length)
        return true;
    if (!path[0])
        return length <= 108;
    for (size_t n = 0; n < length; n++)
        if (!path[n])
            return n + 1 == length;
    return false;
}

size_t UnixAddressValue::output(void* destination, size_t capacity) const {
    if (!valid())
        return 0;
    uint8_t bytes[111]{1, 0};
    memcpy(bytes + 2, path, length);
    size_t actual = 2 + length;
    if (capacity)
        memcpy(destination, bytes, min(capacity, actual));
    return actual;
}

int unix_address_decode(const void* data, size_t length, UnixAddressValue& result) {
    if (length < 2 || length > 110)
        return -22;
    uint16_t family;
    memcpy(&family, data, sizeof(family));
    if (family != 1)
        return -22;
    UnixAddressValue value;
    size_t count = length - 2;
    if (count) {
        auto path = static_cast<const uint8_t*>(data) + 2;
        if (*path) {
            size_t end = 0;
            while (end < count && path[end])
                end++;
            count = end + 1;
            memcpy(value.path, path, end);
        } else
            memcpy(value.path, path, count);
        value.length = count;
    }
    result = value;
    return 0;
}

UnixAddressName* UnixAddressName::create(const UnixAddressValue& value) {
    if (!value.length || !value.valid())
        return nullptr;
    auto name = static_cast<UnixAddressName*>(alloc(sizeof(UnixAddressName)));
    if (name) {
        *name = {};
        name->value = value;
    }
    return name;
}

void UnixAddressName::retain() {
    if (references == UINT32_MAX)
        panic("Unix address reference overflow");
    references++;
}

void UnixAddressName::drop() {
    if (!--references)
        release(this);
}
} // namespace ax
