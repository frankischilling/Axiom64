// SPDX-License-Identifier: GPL-3.0-or-later
#include "firmware/acpi.hpp"

namespace ax::Acpi {
static uint64_t little(const uint8_t* bytes, size_t count) {
    uint64_t value = 0;
    for (size_t i = 0; i < count; i++)
        value |= uint64_t(bytes[i]) << (i * 8);
    return value;
}

static bool match(const uint8_t* bytes, const char* text, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (bytes[i] != uint8_t(text[i]))
            return false;
    return true;
}

static bool checksum(const uint8_t* bytes, size_t count) {
    uint8_t sum = 0;
    for (size_t i = 0; i < count; i++)
        sum += bytes[i];
    return !sum;
}

static const uint8_t* read(uint64_t address, size_t length, Read reader, void* context) {
    constexpr uint64_t limit = 1ull << 52;
    return !address || address >= limit || length > limit - address
               ? nullptr
               : reader(address, length, context);
}

static const uint8_t* table(uint64_t address, const char* signature, size_t minimum, Read reader,
                            void* context) {
    const uint8_t* header = read(address, 36, reader, context);
    if (!header || !match(header, signature, 4))
        return nullptr;
    size_t length = little(header + 4, 4);
    if (length < minimum || length > max_table_bytes)
        return nullptr;
    const uint8_t* complete = read(address, length, reader, context);
    return complete && little(complete + 4, 4) == length && match(complete, signature, 4) &&
                   checksum(complete, length)
               ? complete
               : nullptr;
}

static bool find(uint64_t address, bool extended, Read reader, void* context, Hpet& result) {
    const uint8_t* root = table(address, extended ? "XSDT" : "RSDT", 36, reader, context);
    if (!root)
        return false;
    size_t bytes = little(root + 4, 4) - 36, stride = extended ? 8 : 4;
    if (bytes % stride || bytes / stride > max_root_entries)
        return false;
    for (size_t offset = 36; offset < 36 + bytes; offset += stride) {
        const uint8_t* hpet = table(little(root + offset, stride), "HPET", 56, reader, context);
        if (!hpet || hpet[40] || (hpet[41] && hpet[41] != 64) || hpet[42] ||
            (hpet[43] && hpet[43] != 4))
            continue;
        uint64_t mmio = little(hpet + 44, 8);
        if (!mmio || (mmio & 1023) || mmio > (1ull << 52) - 1024)
            continue;
        result = {mmio, uint32_t(little(hpet + 36, 4))};
        return true;
    }
    return false;
}

bool find_hpet(uint64_t address, Read reader, void* context, Hpet& result) {
    if (!reader)
        return false;
    const uint8_t* first = read(address, 20, reader, context);
    if (!first || !match(first, "RSD PTR ", 8) || !checksum(first, 20) || first[15] == 1)
        return false;
    uint64_t rsdt = little(first + 16, 4);
    if (first[15] >= 2) {
        const uint8_t* header = read(address, 36, reader, context);
        if (!header)
            return false;
        size_t length = little(header + 20, 4);
        if (length < 36 || length > 4096)
            return false;
        const uint8_t* complete = read(address, length, reader, context);
        if (!complete || !match(complete, "RSD PTR ", 8) || little(complete + 20, 4) != length ||
            !checksum(complete, 20) || !checksum(complete, length))
            return false;
        if (find(little(complete + 24, 8), true, reader, context, result))
            return true;
    }
    return find(rsdt, false, reader, context, result);
}
} // namespace ax::Acpi
