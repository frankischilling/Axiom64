// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
constexpr uint64_t signal_trampoline = 0x7fffffffe000;
constexpr uint64_t unmaskable_signals = (1ull << 8) | (1ull << 18);

int queue_signal(Task*, int, int sender = 0, int code = 0, int status = 0, uint64_t address = 0);

int queue_process_signal(Process*, int, int sender = 0, int code = 0, int status = 0,
                         uint64_t address = 0, const Process* child = nullptr);
int queue_message_signal(Process*, int, const Task& sender, uint64_t value);

bool signal_wakes(const Task&);

void signal_interrupt(Task&);

bool signal_deliver(Task&);

void signal_tick();

void signal_discard_ignored(Task&, int number);

int64_t signal_syscall(Frame*);

int64_t signal_wait_enter(Frame*);

bool signal_wait_resume(Task&);
bool signal_pending_for(const Task&, uint64_t mask);
int next_pending_signal(const Task&, uint64_t mask);
int take_pending_signal(Task&, uint64_t mask, SignalData&);
void format_signal_info(uint8_t (&bytes)[128], int number, const SignalData&);
} // namespace ax
