// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax {
struct Frame;
struct Task;

int64_t descriptor_wait_syscall(Task&, const Frame&);
bool descriptor_wait_resume(Task&);
bool descriptor_wait_interrupt(Task&);
void descriptor_wait_stop(Task&);
void descriptor_wait_discard(Task&);
void descriptor_wait_notify(const void* source, uint32_t events);
} // namespace ax
