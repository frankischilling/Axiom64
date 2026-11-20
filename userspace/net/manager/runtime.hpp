// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/manager/runtime.hpp
 * @brief   Network manager runtime interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the runtime dependencies and entry points used by the network
 * manager.
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
#include <signal.h>

namespace ax::net {
struct ManagerPaths {
    const char* runtime = "/run/network-manager";
    const char* saved = "/etc/network";
    const char* resolver_runtime = "/run/network-resolver";
    const char* resolver_target = "/etc/resolv.conf";
};

// Foreground singleton manager. Recovers owned state, runs at most eight clients
// fairly, and withdraws only its recorded configuration on signal or failure.
// Paths select separate private runtime/saved and public resolver directories.
// Returns positive errno; synchronous filesystem operations may extend teardown.
int run_manager(const ManagerPaths&, const volatile sig_atomic_t& stopping);
} // namespace ax::net
