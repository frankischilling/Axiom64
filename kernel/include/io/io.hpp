// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t io_syscall(Task&, const Frame&);

bool io_resume(Task&);

void io_discard(Task&);
// A finite socket timeout or completed stream bytes prevent automatic restart.
bool io_restartable(const Task&);

// Read before discarding a retained request; interruption preserves completed bytes.
int64_t io_interrupted_result(const Task&);
} // namespace ax
