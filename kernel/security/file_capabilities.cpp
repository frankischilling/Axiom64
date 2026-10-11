// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/file_capabilities.hpp"
#include "security/credentials.hpp"

namespace ax {
namespace {
uint32_t word(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) |
           (uint32_t(bytes[3]) << 24);
}
} // namespace

int file_capabilities_decode(const void* value, size_t size, FileCapabilities& result,
                             FileCapabilityUse use) {
    if (!value || size < 4)
        return -22;
    auto bytes = static_cast<const uint8_t*>(value);
    uint32_t magic = word(bytes), revision = magic >> 24;
    if ((revision != 1 && revision != 2 && revision != 3) || size != (revision == 1   ? 12u
                                                                      : revision == 2 ? 20u
                                                                                      : 24u))
        return -22;
    if (use != FileCapabilityUse::execute && (revision == 1 || (magic & 0x00fffffe)))
        return -22;
    FileCapabilities next;
    next.present = true;
    next.effective = magic & 1;
    next.permitted = word(bytes + 4);
    next.inheritable = word(bytes + 8);
    if (revision != 1) {
        next.permitted |= uint64_t(word(bytes + 12)) << 32;
        next.inheritable |= uint64_t(word(bytes + 16)) << 32;
    }
    if (revision == 3)
        next.root_id = word(bytes + 20);
    if (next.root_id == UINT32_MAX && use == FileCapabilityUse::read)
        return -75;
    next.permitted &= all_capabilities;
    next.inheritable &= all_capabilities;
    result = next;
    return 0;
}

int64_t file_capabilities_export(const void* value, size_t size, void* output, size_t capacity) {
    FileCapabilities caps;
    int error = file_capabilities_decode(value, size, caps, FileCapabilityUse::read);
    if (error)
        return error;
    size_t length = size == 24 && !caps.root_id ? 20 : size;
    if (!capacity)
        return length;
    if (capacity < length)
        return -34;
    auto source = static_cast<const uint8_t*>(value);
    auto destination = static_cast<uint8_t*>(output);
    for (size_t i = 0; i < length; i++)
        destination[i] = i == 3 && size != length ? 2 : source[i];
    return length;
}
} // namespace ax
