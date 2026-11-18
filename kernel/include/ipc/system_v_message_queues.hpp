// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int64_t message_queue_syscall(Frame*);
void message_queue_discard(Task&);
void message_queue_resume(Task&);
} // namespace ax
