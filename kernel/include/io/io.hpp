// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t io_syscall(Task&, const Frame&);

bool io_resume(Task&);

void io_discard(Task&);
// A finite socket timeout prevents automatic restart after signal interruption.
bool io_restartable(const Task&);
} // namespace ax
