// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "task.hpp"
namespace ax {
constexpr uint64_t signal_trampoline = 0x7fffffffe000;
void queue_signal(Task*, int, int sender = 0, int code = 0, int status = 0, uint64_t address = 0);
void queue_process_signal(Process*, int, int sender = 0, int code = 0, int status = 0,
                          uint64_t address = 0);
bool signal_wakes(const Task&);
void signal_interrupt(Task&);
bool signal_deliver(Task&);
void signal_tick();
int64_t signal_syscall(Frame*);
} // namespace ax
