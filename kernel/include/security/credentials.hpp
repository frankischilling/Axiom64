// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax {
enum class Capability : unsigned {
    chown = 0,
    dac_override = 1,
    dac_read_search = 2,
    fowner = 3,
    fsetid = 4,
    kill = 5,
    setgid = 6,
    setuid = 7,
    setpcap = 8,
    net_bind_service = 10,
    net_admin = 12,
    net_raw = 13,
    ipc_owner = 15,
    sys_ptrace = 19,
    sys_admin = 21,
    sys_boot = 22,
    sys_chroot = 18
};
constexpr uint64_t all_capabilities = (1ull << 41) - 1;
constexpr unsigned maximum_groups = 65536;

struct Identity {
    uint32_t real = 0, effective = 0, saved = 0, filesystem = 0;
};

// Lists are immutable after installation; cloned tasks retain the same list.
struct GroupList {
    unsigned references, count;
    uint32_t ids[1];
};

struct Credentials {
    Identity user{}, group{};
    GroupList* groups = nullptr;
    uint64_t permitted = all_capabilities, effective = all_capabilities;
    uint64_t inheritable = 0, bounding = all_capabilities, ambient = 0;
    uint32_t securebits = 0;
    bool no_new_privileges = false;
};

enum class IdentityChange { single, real_effective, real_effective_saved };

bool capable(const Credentials&, Capability);
bool credential_group(const Credentials&, uint32_t, bool real = false);
void credential_inherit(Credentials&, const Credentials&);
void credential_release(Credentials&);
GroupList* groups_allocate(unsigned);
void groups_release(GroupList*);
int credential_groups(Credentials&, GroupList*);
int credential_identity(Credentials&, bool group, IdentityChange, uint32_t, uint32_t = UINT32_MAX,
                        uint32_t = UINT32_MAX);
uint32_t credential_filesystem(Credentials&, bool group, uint32_t);
int credential_capabilities(Credentials&, uint64_t effective, uint64_t permitted,
                            uint64_t inheritable);
int64_t credential_control(Credentials&, unsigned option, uint64_t, uint64_t, uint64_t, uint64_t);
Credentials credential_exec(const Credentials&, uint32_t uid, uint32_t gid, uint32_t mode,
                            bool nosuid);
// DAC masks use Linux R_OK/W_OK/X_OK bits. The caller supplies inode identity.
int credential_access(const Credentials&, uint32_t uid, uint32_t gid, uint32_t mode, unsigned mask,
                      bool real = false);
bool credential_signal(const Credentials&, const Credentials&, bool same_session, unsigned signal);
} // namespace ax
