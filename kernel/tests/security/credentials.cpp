// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/credentials.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static unsigned allocations;
static bool fail_allocation;

namespace ax {
void* alloc(size_t bytes) {
    if (fail_allocation)
        return nullptr;
    auto result = std::malloc(bytes);
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
constexpr auto res = IdentityChange::real_effective_saved;
constexpr auto re = IdentityChange::real_effective;
constexpr auto single = IdentityChange::single;

static void identities() {
    Credentials c;
    assert(credential_identity(c, false, single, UINT32_MAX) == -22);
    assert(credential_identity(c, true, res, 1001, 1002, 1003) == 0);
    assert(credential_identity(c, false, res, 1001, 0, 1003) == 0);
    assert(credential_identity(c, false, res, UINT32_MAX, 1002) == 0);
    assert(!c.effective && !c.permitted);
    assert(credential_identity(c, false, res, 9000) == -1 && c.user.real == 1001);
    assert(credential_identity(c, false, single, 1002) == -1);
    assert(credential_identity(c, false, single, 1003) == 0 && c.user.filesystem == 1003);
    assert(credential_identity(c, false, re, 1003, 1001) == 0 && c.user.saved == 1001);
    assert(credential_identity(c, false, res, 1003, 1003, 1003) == 0 && !c.permitted);
    assert(credential_identity(c, false, single, 0) == -1 && c.user.effective == 1003);
    Credentials temporary;
    assert(credential_identity(temporary, false, re, UINT32_MAX, 1001) == 0);
    assert(!temporary.effective && temporary.permitted == all_capabilities);
    assert(credential_identity(temporary, false, re, UINT32_MAX, 0) == 0);
    assert(temporary.effective == all_capabilities);
    assert(credential_filesystem(temporary, false, 1002) == 0);
    assert(temporary.user.filesystem == 1002 && !capable(temporary, Capability::dac_override));
    assert(credential_filesystem(temporary, false, UINT32_MAX) == 1002);
    assert(credential_filesystem(temporary, false, 0) == 1002);
    assert(capable(temporary, Capability::dac_override));
    assert(credential_identity(temporary, false, single, 1001) == 0);
    assert(credential_filesystem(temporary, false, 0) == 1001 && temporary.user.filesystem == 1001);
    assert(credential_identity(temporary, true, re, UINT32_MAX, 0) == 0);
    assert(credential_identity(temporary, true, res, 1001, 1002, 1003) == -1);
}

static GroupList* list(unsigned count) {
    auto result = groups_allocate(count);
    assert(result);
    for (unsigned at = 0; at < count; at++)
        result->ids[at] = count - at;
    return result;
}

static void groups() {
    Credentials parent, child;
    auto original = list(maximum_groups);
    assert(credential_groups(parent, original) == 0);
    groups_release(original);
    assert(parent.groups->ids[0] == 1 && parent.groups->ids[maximum_groups - 1] == maximum_groups);
    assert(credential_group(parent, 8000) && !credential_group(parent, 80000));
    credential_inherit(child, parent);
    credential_inherit(child, child);
    assert(child.groups == parent.groups && child.groups->references == 2);
    auto replacement = list(5);
    replacement->ids[0] = 3;
    assert(credential_groups(child, replacement) == 0);
    groups_release(replacement);
    assert(parent.groups->count == maximum_groups && child.groups->count == 5);
    for (unsigned at = 1; at < child.groups->count; at++)
        assert(child.groups->ids[at - 1] <= child.groups->ids[at]);
    auto invalid = list(1);
    invalid->ids[0] = UINT32_MAX;
    assert(credential_groups(child, invalid) == -22 && child.groups->count == 5);
    groups_release(invalid);
    fail_allocation = true;
    assert(!groups_allocate(1) && parent.groups->count == maximum_groups);
    fail_allocation = false;
    assert(credential_identity(child, false, single, 1001) == 0);
    auto denied = list(0);
    assert(credential_groups(child, denied) == -1 && child.groups->count == 5);
    groups_release(denied);
    credential_release(parent);
    assert(credential_group(child, 3));
    credential_release(child);
    assert(!allocations);
}

static void privileges() {
    Credentials c;
    assert(credential_control(c, 8, 1, 0, 0, 0) == 0);
    assert(credential_identity(c, false, single, 1001) == 0);
    assert(c.permitted == all_capabilities && !c.effective);
    uint64_t bit = 1ull << unsigned(Capability::net_raw);
    assert(credential_capabilities(c, bit, bit, bit) == 0);
    assert(credential_control(c, 47, 2, unsigned(Capability::net_raw), 0, 0) == 0);
    assert(c.ambient == bit);
    auto executed = credential_exec(c, 0, 0, 0100755, false);
    assert(executed.permitted == bit && executed.effective == bit && !executed.securebits);
    assert(credential_capabilities(c, bit | 1, bit | 1, bit) == -1);
    assert(credential_capabilities(c, 0, 0, bit) == 0 && !c.ambient);
    Credentials unprivileged;
    assert(credential_identity(unprivileged, false, single, 1001) == 0);
    auto setid = credential_exec(unprivileged, 0, 99, 0106755, false);
    assert(setid.user.real == 1001 && !setid.user.effective && !setid.user.saved);
    assert(setid.group.effective == 99 && setid.group.saved == 99);
    assert(setid.effective == all_capabilities);
    assert(credential_control(unprivileged, 38, 1, 0, 0, 0) == 0);
    auto suppressed = credential_exec(unprivileged, 0, 99, 0106755, false);
    assert(suppressed.user.effective == 1001 && !suppressed.effective);
    assert(credential_control(unprivileged, 38, 0, 0, 0, 0) == -22);
    Credentials locked;
    assert(credential_control(locked, 28, 3, 0, 0, 0) == 0);
    assert(credential_control(locked, 28, 0, 0, 0, 0) == -1);
    assert(!credential_exec(locked, 0, 0, 0100755, false).effective);
    Credentials bounded;
    assert(credential_control(bounded, 24, 13, 0, 0, 0) == 0);
    assert(!(credential_exec(bounded, 0, 0, 0100755, false).permitted & bit));
}

static void permissions() {
    Credentials root, user;
    assert(credential_identity(user, true, single, 1001) == 0);
    assert(credential_identity(user, false, single, 1001) == 0);
    assert(credential_access(root, 0, 0, 0100000, 1) == -13);
    assert(credential_access(root, 1001, 1001, 0040000, 7) == 0);
    assert(credential_access(user, 1001, 1001, 0100600, 6) == 0);
    assert(credential_access(user, 1002, 1001, 0100640, 4) == 0);
    assert(credential_access(user, 1002, 1002, 0100640, 4) == -13);
    assert(credential_access(user, 1001, 1001, 0100640, 8) == -22);
    Credentials access_ids;
    assert(credential_identity(access_ids, false, res, 1001, 0, 0) == 0);
    assert(credential_access(access_ids, 0, 0, 0100600, 4) == 0);
    assert(credential_access(access_ids, 0, 0, 0100600, 4, true) == -13);
    assert(credential_signal(root, user, false, 0));
    assert(!credential_signal(user, root, false, 0));
    assert(credential_signal(user, root, true, 18));
    assert(!credential_signal(user, root, true, 15));
    assert(credential_signal(user, user, false, 15));
}

int main() {
    identities();
    groups();
    privileges();
    permissions();
    assert(!allocations);
    puts("CREDENTIAL_POLICY_PASS identities groups lifetime allocation capabilities permissions");
}
