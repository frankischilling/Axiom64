// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/xattr.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static unsigned allocations, calls, fail_call;

namespace ax {
void* alloc(size_t size) {
    if (++calls == fail_call)
        return nullptr;
    auto result = std::malloc(size);
    if (result)
        allocations++;
    return result;
}

void release(void* pointer) {
    if (pointer) {
        assert(allocations);
        allocations--;
        std::free(pointer);
    }
}
} // namespace ax

using namespace ax;

int main() {
    XattrName user, trusted, security;
    assert(xattr_name("user.alpha", user) == 0 && user.index == 1 && !strcmp(user.suffix, "alpha"));
    assert(xattr_name("trusted.private", trusted) == 0 && trusted.index == 4);
    assert(xattr_name("security.capability", security) == 0 && security.index == 6);
    assert(xattr_name("user.", security) == -22);
    assert(xattr_name("", security) == -34);
    assert(xattr_name("system.posix_acl_access", security) == -95);
    assert(xattr_name("unsupported.attribute", security) == -95);
    char long_name[257];
    memset(long_name, 'a', sizeof(long_name));
    memcpy(long_name, "user.", 5);
    long_name[255] = 0;
    assert(xattr_name(long_name, security) == 0);
    long_name[255] = 'a';
    long_name[256] = 0;
    assert(xattr_name(long_name, security) == -34);
    Xattr* attributes = nullptr;
    char output[64];
    assert(xattr_store_get(attributes, user, output, sizeof(output)) == -61);
    assert(xattr_store_remove(attributes, user) == -61);
    assert(xattr_store_set(attributes, user, "one", 3, 3) == -61);
    assert(xattr_store_set(attributes, user, "one", 3, 2) == -61);
    assert(xattr_store_set(attributes, user, "one", 3, 4) == -22);
    assert(xattr_store_set(attributes, user, "one", xattr_value_max + 1, 0) == -7);
    assert(!attributes && !allocations);
    assert(xattr_store_set(attributes, user, "one", 3, 1) == 0 && allocations == 2);
    assert(xattr_store_set(attributes, user, "two", 3, 3) == -17);
    assert(xattr_store_set(attributes, user, "two", 3, 1) == -17);
    assert(xattr_store_get(attributes, user, nullptr, 0) == 3);
    memset(output, 'z', sizeof(output));
    assert(xattr_store_get(attributes, user, output, 2) == -34 && output[0] == 'z');
    assert(xattr_store_get(attributes, user, output, 3) == 3 && !memcmp(output, "one", 3) &&
           output[3] == 'z');
    // Every allocation failure retains the old attribute and its ownership.
    for (unsigned stage = 1; stage <= 2; stage++) {
        fail_call = calls + stage;
        assert(xattr_store_set(attributes, user, "replacement", 11, 2) == -12);
        fail_call = 0;
        assert(allocations == 2);
        assert(xattr_store_get(attributes, user, output, sizeof(output)) == 3 &&
               !memcmp(output, "one", 3));
    }
    assert(xattr_store_set(attributes, user, nullptr, 0, 2) == 0 && allocations == 1);
    assert(xattr_store_get(attributes, user, output, sizeof(output)) == 0);
    assert(xattr_store_set(attributes, trusted, "secret", 6, 0) == 0);
    assert(xattr_name("security.capability", security) == 0);
    assert(xattr_store_set(attributes, security, "metadata", 8, 0) == 0);
    assert(xattr_store_list(attributes, nullptr, 0, false) == 31);
    assert(xattr_store_list(attributes, nullptr, 0, true) == 47);
    memset(output, 'z', sizeof(output));
    assert(xattr_store_list(attributes, output, 30, false) == -34 && output[0] == 'z');
    assert(xattr_store_list(attributes, output, sizeof(output), false) == 31);
    assert(!strcmp(output, "user.alpha") && !strcmp(output + 11, "security.capability"));
    assert(xattr_store_remove(attributes, trusted) == 0);
    assert(xattr_store_get(attributes, security, output, sizeof(output)) == 8 &&
           !memcmp(output, "metadata", 8));
    xattr_store_destroy(attributes);
    assert(!attributes && !allocations);
    // Repeated replacements/removal and recreation leave no retired values.
    for (unsigned cycle = 0; cycle < 20000; cycle++) {
        assert(xattr_store_set(attributes, user, &cycle, sizeof(cycle), 0) == 0);
        if (cycle & 1)
            assert(xattr_store_remove(attributes, user) == 0);
    }
    xattr_store_destroy(attributes);
    assert(!allocations);
    puts("XATTR_STORE_PASS namespaces flags sizes empty_values allocation_failure "
         "atomic_replacement lifetime");
}
