// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t futex_syscall(Frame*);

int futex_wake(Task*, uint64_t address, int count, bool private_key, uint32_t bitset = UINT32_MAX);

void futex_discard(Task&);

bool futex_ready(Task&);
} // namespace ax
