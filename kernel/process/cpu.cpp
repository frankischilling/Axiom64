// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/cpu.hpp"
#include "process/signals.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
Task* owner;
uint64_t started;
bool user;

uint64_t add(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}
} // namespace

void cpu_account(Task* next, bool userspace) {
    clock_refresh();
    if (owner) {
        uint64_t elapsed = ticks - started;
        auto& process = *owner->process;
        auto& task_time = user ? owner->cpu_user_ticks : owner->cpu_system_ticks;
        auto& process_time = user ? process.cpu_user_ticks : process.cpu_system_ticks;
        task_time = add(task_time, elapsed);
        process_time = add(process_time, elapsed);
        int signal =
            process.limits.cpu_signal(add(process.cpu_user_ticks, process.cpu_system_ticks));
        if (signal)
            queue_process_signal(&process, signal, 0, 128);
    }
    owner = next;
    user = userspace;
    started = ticks;
}

void cpu_refresh() {
    cpu_account(owner, user);
}

void cpu_depart(Task& task) {
    if (owner == &task)
        cpu_account();
}

uint64_t cpu_ticks(const Task& task, bool thread) {
    cpu_refresh();
    return thread ? add(task.cpu_user_ticks, task.cpu_system_ticks)
                  : add(task.process->cpu_user_ticks, task.process->cpu_system_ticks);
}
} // namespace ax
