// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/busy.h
 * @brief   Account use checks.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the checks that determine whether an account is currently in use.
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
#ifndef AXIOM64_ACCOUNTS_BUSY_H
#define AXIOM64_ACCOUNTS_BUSY_H
#include <sys/types.h>

// One means a process/thread retains any requested real/effective/saved/fs ID
// or supplementary GID. UINT32_MAX skips that identity dimension. Zero means
// the complete live procfs scan found none; failures never mean safe to reuse.
int account_process_busy(uid_t, gid_t);

#endif
