// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/xattr.hpp"
#include "core/base.hpp"

namespace ax {
namespace {
constexpr uint32_t magic = 0xea020000;
constexpr size_t header_size = 32, entry_size = 16;

uint16_t half(const uint8_t* data) {
    return uint16_t(data[0]) | (uint16_t(data[1]) << 8);
}

uint32_t word(const uint8_t* data) {
    return uint32_t(half(data)) | (uint32_t(half(data + 2)) << 16);
}

void put(uint8_t* data, uint32_t value, unsigned bytes = 4) {
    for (unsigned i = 0; i < bytes; i++)
        data[i] = value >> (i * 8);
}

size_t padded(size_t size) {
    return (size + 3) & ~size_t(3);
}

size_t next(const uint8_t* entry) {
    return padded(entry_size + entry[0]);
}

int compare(unsigned index, const uint8_t* name, size_t length, const uint8_t* entry) {
    if (index != entry[1])
        return index < entry[1] ? -1 : 1;
    if (length != entry[0])
        return length < entry[0] ? -1 : 1;
    return memcmp(name, entry + entry_size, length);
}

uint32_t entry_hash(const uint8_t* entry, const uint8_t* block, bool signed_name = true) {
    uint32_t hash = 0;
    for (unsigned i = 0; i < entry[0]; i++) {
        uint8_t byte = entry[entry_size + i];
        uint32_t character = signed_name ? uint32_t(int32_t(int8_t(byte))) : byte;
        hash = (hash << 5) ^ (hash >> 27) ^ character;
    }
    uint32_t size = word(entry + 8);
    auto value = block + half(entry + 2);
    for (size_t i = 0; i < padded(size); i += 4)
        hash = (hash << 16) ^ (hash >> 16) ^ word(value + i);
    return hash;
}

uint32_t fold(uint32_t hash, uint32_t entry) {
    return (hash << 16) ^ (hash >> 16) ^ entry;
}

bool block_size(size_t size) {
    return size == 1024 || size == 2048 || size == 4096;
}
} // namespace

bool ext2_xattr_valid(const void* value, size_t size, uint32_t& references) {
    if (!value || !block_size(size))
        return false;
    auto block = static_cast<const uint8_t*>(value);
    uint32_t refcount = word(block + 4);
    if (word(block) != magic || !refcount || refcount > 1024 || word(block + 8) != 1)
        return false;
    for (size_t offset = 16; offset < header_size; offset += 4)
        if (word(block + offset))
            return false;
    size_t at = header_size, previous = 0;
    while (at <= size - 4 && word(block + at)) {
        auto entry = block + at;
        if (at > size - entry_size || next(entry) > size - at || !entry[1] || word(entry + 4))
            return false;
        for (unsigned i = 0; i < entry[0]; i++)
            if (!entry[entry_size + i])
                return false;
        if ((!entry[0] && xattr_prefix(entry[1])) ||
            (previous && compare(entry[1], entry + entry_size, entry[0], block + previous) <= 0))
            return false;
        previous = at;
        at += next(entry);
    }
    if (at > size - 4 || word(block + at))
        return false;
    size_t names_end = at + 4;
    uint32_t hash = 0;
    bool shareable = true;
    for (at = header_size; word(block + at); at += next(block + at)) {
        auto entry = block + at;
        size_t offset = half(entry + 2), length = word(entry + 8);
        if (offset > size || length > size - offset || padded(length) > size - offset ||
            (length && ((offset & 3) || offset < names_end)))
            return false;
        if (length)
            for (size_t earlier = header_size; earlier < at; earlier += next(block + earlier)) {
                auto other = block + earlier;
                size_t other_offset = half(other + 2), other_size = padded(word(other + 8));
                if (other_size && offset < other_offset + other_size &&
                    other_offset < offset + padded(length))
                    return false;
            }
        uint32_t actual = entry_hash(entry, block), stored = word(entry + 12);
        // The historical hash depended on the producer's signed-char convention.
        if (stored && stored != actual && stored != entry_hash(entry, block, false))
            return false;
        shareable &= stored != 0;
        hash = fold(hash, stored);
    }
    if (word(block + 12) && (!shareable || word(block + 12) != hash))
        return false;
    references = refcount;
    return true;
}

bool ext2_xattr_supported(const void* value, size_t size) {
    uint32_t references;
    if (!ext2_xattr_valid(value, size, references))
        return false;
    auto block = static_cast<const uint8_t*>(value);
    for (size_t at = header_size; word(block + at); at += next(block + at))
        if (block[at + 1] == 2 || block[at + 1] == 3)
            return false; // Stored ACLs require their permission policy before mounting.
    return true;
}

int64_t ext2_xattr_get(const void* value, size_t size, const XattrName& name, void* output,
                       size_t capacity) {
    uint32_t references;
    if (!ext2_xattr_valid(value, size, references))
        return -117;
    auto block = static_cast<const uint8_t*>(value);
    size_t length = strlen(name.suffix);
    for (size_t at = header_size; word(block + at); at += next(block + at)) {
        auto entry = block + at;
        if (!compare(name.index, reinterpret_cast<const uint8_t*>(name.suffix), length, entry)) {
            size_t bytes = word(entry + 8);
            if (!capacity)
                return bytes;
            if (capacity < bytes)
                return -34;
            if (bytes)
                memcpy(output, block + half(entry + 2), bytes);
            return bytes;
        }
    }
    return -61;
}

int64_t ext2_xattr_list(const void* value, size_t size, void* output, size_t capacity,
                        bool trusted) {
    uint32_t references;
    if (!ext2_xattr_valid(value, size, references))
        return -117;
    auto block = static_cast<const uint8_t*>(value);
    size_t required = 0;
    for (size_t at = header_size; word(block + at); at += next(block + at)) {
        auto prefix = xattr_prefix(block[at + 1]);
        if (prefix && (block[at + 1] != 4 || trusted))
            required += strlen(prefix) + block[at] + 1;
    }
    if (!capacity)
        return required;
    if (capacity < required)
        return -34;
    auto destination = static_cast<uint8_t*>(output);
    for (size_t at = header_size; word(block + at); at += next(block + at)) {
        auto entry = block + at;
        auto prefix = xattr_prefix(entry[1]);
        if (!prefix || (entry[1] == 4 && !trusted))
            continue;
        size_t length = strlen(prefix);
        memcpy(destination, prefix, length);
        destination += length;
        memcpy(destination, entry + entry_size, entry[0]);
        destination += entry[0];
        *destination++ = 0;
    }
    return required;
}

int ext2_xattr_change(const void* original, size_t size, const XattrName& name, const void* value,
                      size_t length, unsigned flags, bool remove, void* output, bool& empty) {
    if (!block_size(size) || original == output || (flags & ~3u) || !name.suffix[0] ||
        strlen(name.suffix) > 255 || name.index > 255 || !name.index)
        return -22;
    if (length > xattr_value_max)
        return -7;
    auto source = static_cast<const uint8_t*>(original);
    auto key = reinterpret_cast<const uint8_t*>(name.suffix);
    size_t key_length = strlen(name.suffix), names = header_size + 4, values = 0, entries = 0;
    bool found = false;
    if (source) {
        uint32_t references;
        if (!ext2_xattr_valid(source, size, references))
            return -117;
        for (size_t at = header_size; word(source + at); at += next(source + at)) {
            auto entry = source + at;
            if (!compare(name.index, key, key_length, entry))
                found = true;
            else {
                names += next(entry);
                values += padded(word(entry + 8));
                entries++;
            }
        }
    }
    if (!found && (remove || (flags & 2)))
        return -61;
    if (found && (flags & 1))
        return -17;
    if (!remove) {
        names += padded(entry_size + key_length);
        values += padded(length);
        entries++;
    }
    if (names > size || values > size - names)
        return -28;
    auto destination = static_cast<uint8_t*>(output);
    memset(destination, 0, size);
    put(destination, magic);
    put(destination + 4, 1);
    put(destination + 8, 1);
    size_t cursor = header_size, tail = size;
    uint32_t hash = 0;
    bool shareable = true, inserted = remove;
    auto emit = [&](unsigned index, const uint8_t* suffix, size_t suffix_length,
                    const uint8_t* bytes, size_t bytes_length) {
        auto entry = destination + cursor;
        entry[0] = suffix_length;
        entry[1] = index;
        tail -= padded(bytes_length);
        put(entry + 2, bytes_length ? tail : 0, 2);
        put(entry + 8, bytes_length);
        memcpy(entry + entry_size, suffix, suffix_length);
        if (bytes_length)
            memcpy(destination + tail, bytes, bytes_length);
        uint32_t digest = entry_hash(entry, destination);
        put(entry + 12, digest);
        hash = fold(hash, digest);
        shareable &= digest != 0;
        cursor += padded(entry_size + suffix_length);
    };
    if (source)
        for (size_t at = header_size; word(source + at); at += next(source + at)) {
            auto entry = source + at;
            int order = compare(name.index, key, key_length, entry);
            if (!inserted && order <= 0) {
                emit(name.index, key, key_length, static_cast<const uint8_t*>(value), length);
                inserted = true;
            }
            if (order)
                emit(entry[1], entry + entry_size, entry[0], source + half(entry + 2),
                     word(entry + 8));
        }
    if (!inserted)
        emit(name.index, key, key_length, static_cast<const uint8_t*>(value), length);
    put(destination + 12, shareable ? hash : 0);
    empty = !entries;
    return 0;
}
} // namespace ax
