// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/xattr.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace ax {
void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* pointer) {
    std::free(pointer);
}
} // namespace ax

using namespace ax;
static unsigned negatives;

static uint32_t word(const uint8_t* data) {
    return uint32_t(data[0]) | (uint32_t(data[1]) << 8) | (uint32_t(data[2]) << 16) |
           (uint32_t(data[3]) << 24);
}

static void put(uint8_t* data, uint32_t value, unsigned bytes = 4) {
    for (unsigned i = 0; i < bytes; i++)
        data[i] = value >> (i * 8);
}

static size_t next(const uint8_t* entry) {
    return (16 + entry[0] + 3) & ~size_t(3);
}

static void check(const char* path) {
    uint8_t original[4096], current[4096], replacement[4096], damaged[4096];
    auto file = fopen(path, "rb");
    assert(file);
    size_t size = fread(original, 1, sizeof(original), file);
    assert(!ferror(file) && fclose(file) == 0 && (size == 1024 || size == 2048 || size == 4096));
    uint32_t references;
    assert(ext2_xattr_valid(original, size, references) && references == 1);
    assert(ext2_xattr_supported(original, size));
    memcpy(current, original, size);
    XattrName alpha, binary, trusted, capability, unicode, added;
    assert(!xattr_name("user.alpha", alpha) && !xattr_name("user.binary", binary) &&
           !xattr_name("trusted.private", trusted) &&
           !xattr_name("security.capability", capability) && !xattr_name("user.é", unicode) &&
           !xattr_name("user.new", added));
    uint8_t bytes[4096];
    assert(ext2_xattr_get(original, size, alpha, bytes, sizeof(bytes)) == 3 &&
           !memcmp(bytes, "one", 3));
    const uint8_t expected_binary[] = {0, 0xff, 1, 2};
    assert(ext2_xattr_get(original, size, binary, bytes, sizeof(bytes)) == 4 &&
           !memcmp(bytes, expected_binary, 4));
    assert(ext2_xattr_get(original, size, unicode, bytes, sizeof(bytes)) == 4 &&
           !memcmp(bytes, "utf8", 4));
    assert(ext2_xattr_get(original, size, trusted, bytes, sizeof(bytes)) == 6 &&
           !memcmp(bytes, "secret", 6));
    assert(ext2_xattr_get(original, size, capability, bytes, sizeof(bytes)) == 20 &&
           word(bytes) == 0x02000001);
    assert(ext2_xattr_get(original, size, added, bytes, sizeof(bytes)) == -61);
    memset(bytes, 0x5a, sizeof(bytes));
    assert(ext2_xattr_get(original, size, alpha, bytes, 2) == -34 && bytes[0] == 0x5a);
    assert(ext2_xattr_list(original, size, nullptr, 0, false) + 16 ==
           ext2_xattr_list(original, size, nullptr, 0, true));
    assert(ext2_xattr_list(original, size, bytes, 1, true) == -34 && bytes[0] == 0x5a);
    bool empty = true;
    assert(ext2_xattr_change(original, size, alpha, "new", 3, 1, false, replacement, empty) == -17);
    assert(ext2_xattr_change(original, size, added, "new", 3, 3, false, replacement, empty) == -61);
    assert(ext2_xattr_change(original, size, alpha, "new", 3, 3, false, replacement, empty) == -17);
    assert(ext2_xattr_change(original, size, alpha, "new", 3, 4, false, replacement, empty) == -22);
    memset(replacement, 0x5a, size);
    assert(ext2_xattr_change(original, size, alpha, bytes, size, 2, false, replacement, empty) ==
           -28);
    assert(replacement[0] == 0x5a && empty);
    assert(!ext2_xattr_change(original, size, alpha, "changed", 7, 2, false, replacement, empty) &&
           !empty);
    memcpy(current, replacement, size);
    assert(
        !ext2_xattr_change(current, size, added, expected_binary, 4, 1, false, replacement, empty));
    memcpy(current, replacement, size);
    assert(!ext2_xattr_change(current, size, binary, nullptr, 0, 0, true, replacement, empty));
    memcpy(current, replacement, size);
    assert(ext2_xattr_valid(current, size, references) && references == 1);
    assert(ext2_xattr_get(current, size, alpha, bytes, sizeof(bytes)) == 7 &&
           !memcmp(bytes, "changed", 7));
    assert(ext2_xattr_get(current, size, binary, bytes, sizeof(bytes)) == -61);
    assert(ext2_xattr_get(current, size, trusted, bytes, sizeof(bytes)) == 6 &&
           !memcmp(bytes, "secret", 6));
    assert(ext2_xattr_get(current, size, capability, bytes, sizeof(bytes)) == 20 &&
           word(bytes) == 0x02000001);
    assert(ext2_xattr_get(current, size, unicode, bytes, sizeof(bytes)) == 4 &&
           !memcmp(bytes, "utf8", 4));
    char generated[1024];
    assert(snprintf(generated, sizeof(generated), "%s.generated", path) < int(sizeof(generated)));
    file = fopen(generated, "wb");
    assert(file && fwrite(current, 1, size, file) == size && fclose(file) == 0);
    // Copy-on-write produces a private reference while keeping a shared source intact.
    memcpy(damaged, original, size);
    put(damaged + 4, 2);
    assert(ext2_xattr_valid(damaged, size, references) && references == 2);
    assert(!ext2_xattr_change(damaged, size, alpha, "private", 7, 2, false, replacement, empty));
    assert(word(damaged + 4) == 2 && ext2_xattr_valid(replacement, size, references) &&
           references == 1);
    // Unknown namespaces stay byte-exact when a supported attribute changes.
    XattrName future{5, "future"};
    assert(!ext2_xattr_change(original, size, future, expected_binary, 4, 1, false, replacement,
                              empty));
    memcpy(damaged, replacement, size);
    assert(!ext2_xattr_change(damaged, size, alpha, "private", 7, 2, false, replacement, empty));
    assert(ext2_xattr_get(replacement, size, future, bytes, sizeof(bytes)) == 4 &&
           !memcmp(bytes, expected_binary, 4));
    // Remove every entry and exercise an empty value through an actual block.
    const XattrName names[] = {alpha, binary, trusted, capability, unicode};
    memcpy(damaged, original, size);
    for (auto name : names) {
        assert(!ext2_xattr_change(damaged, size, name, nullptr, 0, 0, true, replacement, empty));
        memcpy(damaged, replacement, size);
    }
    assert(empty && ext2_xattr_valid(damaged, size, references));
    assert(!ext2_xattr_change(nullptr, size, alpha, nullptr, 0, 0, false, replacement, empty) &&
           !empty);
    assert(ext2_xattr_get(replacement, size, alpha, bytes, sizeof(bytes)) == 0);
    // A structurally readable ACL must still be refused without ACL permission support.
    memset(damaged, 0, size);
    put(damaged, 0xea020000);
    put(damaged + 4, 1);
    put(damaged + 8, 1);
    damaged[33] = 2;
    assert(ext2_xattr_valid(damaged, size, references) && !ext2_xattr_supported(damaged, size));
    auto reject = [&](auto mutation) {
        memcpy(damaged, original, size);
        mutation();
        assert(!ext2_xattr_valid(damaged, size, references));
        assert(ext2_xattr_get(damaged, size, alpha, bytes, sizeof(bytes)) == -117);
        memset(replacement, 0x5a, size);
        assert(ext2_xattr_change(damaged, size, alpha, "bad", 3, 2, false, replacement, empty) ==
               -117);
        assert(replacement[0] == 0x5a);
        negatives++;
    };
    reject([&] { damaged[0] ^= 1; });
    reject([&] { put(damaged + 4, 0); });
    reject([&] { put(damaged + 4, 1025); });
    reject([&] { put(damaged + 8, 2); });
    reject([&] { damaged[16] = 1; });
    reject([&] { put(damaged + 32 + 4, 1); });
    reject([&] { put(damaged + 32 + 2, 32, 2); });
    reject([&] { put(damaged + 32 + 8, UINT32_MAX); });
    reject([&] { put(damaged + 32 + 2, size, 2); });
    reject([&] { put(damaged + 32 + 2, size - 1, 2); });
    reject([&] { damaged[32] = 255; });
    reject([&] { damaged[48] = 0; });
    reject([&] { put(damaged + 12, word(damaged + 12) ^ 1); });
    reject([&] { put(damaged + 44, word(damaged + 44) ^ 1); });
    reject([&] {
        size_t second = 32 + next(damaged + 32);
        put(damaged + second + 2, word(damaged + 34) & 0xffff, 2);
        put(damaged + second + 12, 0);
        put(damaged + 12, 0);
    });
    reject([&] {
        damaged[33] = 7;
        put(damaged + 12, 0);
    });
    assert(!ext2_xattr_valid(original, size - 1, references));
    negatives++;
    // Malformed records must remain bounded before any hash or value access.
    uint32_t random = 0x27182818;
    for (unsigned cycle = 0; cycle < 10000; cycle++) {
        memcpy(damaged, original, size);
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        damaged[random % size] ^= uint8_t((random >> 24) | 1);
        (void)ext2_xattr_valid(damaged, size, references);
    }
}

int main(int argc, char** argv) {
    assert(argc == 4);
    for (int i = 1; i < argc; i++)
        check(argv[i]);
    printf("EXT2_XATTR_CODEC_PASS actual_blocks=3 malformed_cases=%u bounds signed_names "
           "shared_source empty_values unknown_namespaces\n",
           negatives);
}
