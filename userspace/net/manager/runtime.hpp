// SPDX-License-Identifier: GPL-3.0-or-later
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
