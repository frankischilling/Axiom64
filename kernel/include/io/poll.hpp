// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax {
struct Frame;
struct Task;

int64_t poll_syscall(Task&, const Frame&);
bool poll_resume(Task&);
bool poll_interrupt(Task&);
void poll_stop(Task&);
void poll_discard(Task&);
} // namespace ax
