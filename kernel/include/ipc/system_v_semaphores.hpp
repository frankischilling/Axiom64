// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t semaphore_syscall(Frame*);
bool semaphore_share_undo(Task& child, Task& parent);
void semaphore_discard(Task&);
void semaphore_exit(Task&);
bool semaphore_timeout(Task&);
} // namespace ax
