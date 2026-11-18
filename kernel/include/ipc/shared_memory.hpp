// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t shared_memory_syscall(Frame*);
bool shared_memory_fork(Task& child, const Task& parent);
void shared_memory_release(Task&);
int shared_memory_unmap(Task&, uint64_t base, size_t length);
int shared_memory_protect(Task&, uint64_t base, size_t length, int protection);
} // namespace ax
