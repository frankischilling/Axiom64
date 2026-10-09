// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
// Return false for options owned by the socket family's dispatcher.
bool socket_timeout_syscall(Task&, const Frame&, Handle*, int64_t& result);
} // namespace ax
