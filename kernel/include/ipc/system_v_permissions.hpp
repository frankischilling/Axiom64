// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "security/credentials.hpp"

namespace ax {
struct SystemVPermission {
    int32_t key;
    uint32_t uid, gid, creator_uid, creator_gid, mode;
    uint16_t sequence, pad;
    uint32_t alignment;
    uint64_t reserved[2];

    bool allows(const Credentials& credentials, unsigned requested) const {
        unsigned allowed = mode;
        if (credentials.user.effective == uid || credentials.user.effective == creator_uid)
            allowed >>= 6;
        else if (credential_group(credentials, gid) || credential_group(credentials, creator_gid))
            allowed >>= 3;
        return !(requested & ~allowed & 7) || capable(credentials, Capability::ipc_owner);
    }

    bool controls(const Credentials& credentials) const {
        return credentials.user.effective == uid || credentials.user.effective == creator_uid ||
               capable(credentials, Capability::sys_admin);
    }
};

static_assert(sizeof(SystemVPermission) == 48);
} // namespace ax
