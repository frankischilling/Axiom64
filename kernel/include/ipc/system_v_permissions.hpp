// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/system_v_permissions.hpp
 * @brief   System V IPC permission interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines shared ownership data and declares permission and control checks for
 * IPC objects.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
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
