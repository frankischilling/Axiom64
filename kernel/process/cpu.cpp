// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/cpu.cpp
 * @brief   Task CPU-time accounting.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Tracks execution time charged to tasks and processes.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "process/cpu.hpp"
#include "process/signals.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
Task* owner;
uint64_t started;
bool user;
bool accounting_started;
CpuTotals totals;

constexpr uint64_t load_period = 501; // Five seconds plus one 100 Hz tick.
constexpr uint64_t load_scale = 1 << 11;
uint64_t load_tick;
LoadAverages load_average;

uint64_t decay_for_periods(uint64_t decay, uint64_t periods) {
    uint64_t result = load_scale;
    while (periods) {
        if (periods & 1)
            result = (result * decay + load_scale / 2) / load_scale;
        decay = (decay * decay + load_scale / 2) / load_scale;
        periods >>= 1;
    }
    return result;
}

uint64_t smooth_load(uint64_t previous, uint64_t target, uint64_t decay, uint64_t periods) {
    const uint64_t weight = decay_for_periods(decay, periods);
    if (previous <= target)
        return target - (target - previous) * weight / load_scale;
    return target + (previous - target) * weight / load_scale;
}

uint64_t add(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}
} // namespace

void cpu_sample_load() {
    const uint64_t periods = (ticks - load_tick) / load_period;
    if (!periods)
        return;
    load_tick += periods * load_period;
    uint64_t runnable = 0;
    for (const auto& task : tasks)
        if (task.state == State::runnable)
            runnable++;
    const uint64_t target = runnable * load_scale;
    load_average.one = smooth_load(load_average.one, target, 1884, periods);
    load_average.five = smooth_load(load_average.five, target, 2014, periods);
    load_average.fifteen = smooth_load(load_average.fifteen, target, 2037, periods);
}

LoadAverages cpu_load_averages() {
    // Linux's userspace representation has 16 fractional bits.
    return {load_average.one << 5, load_average.five << 5, load_average.fifteen << 5};
}

void cpu_account(Task* next, bool userspace) {
    clock_refresh();
    uint64_t elapsed = ticks - started;
    if (owner) {
        auto& process = *owner->process;
        auto& task_time = user ? owner->cpu_user_ticks : owner->cpu_system_ticks;
        auto& process_time = user ? process.cpu_user_ticks : process.cpu_system_ticks;
        auto& system_time = user ? totals.user_ticks : totals.system_ticks;
        task_time = add(task_time, elapsed);
        process_time = add(process_time, elapsed);
        system_time = add(system_time, elapsed);
        int signal =
            process.limits.cpu_signal(add(process.cpu_user_ticks, process.cpu_system_ticks));
        if (signal)
            queue_process_signal(&process, signal, 0, 128);
    } else if (accounting_started)
        totals.idle_ticks = add(totals.idle_ticks, elapsed);
    else
        totals.system_ticks = elapsed;
    accounting_started = true;
    owner = next;
    user = userspace;
    started = ticks;
}

void cpu_refresh() {
    cpu_account(owner, user);
}

CpuTotals cpu_totals() {
    cpu_refresh();
    return totals;
}

void cpu_depart(Task& task) {
    if (owner == &task)
        cpu_account();
}

CpuUsage cpu_usage(const Task& task, bool thread) {
    cpu_refresh();
    if (thread)
        return {task.cpu_user_ticks, task.cpu_system_ticks};
    return {task.process->cpu_user_ticks, task.process->cpu_system_ticks};
}

CpuUsage cpu_waited_usage(const Process& process) {
    return {add(process.cpu_user_ticks, process.children_user_ticks),
            add(process.cpu_system_ticks, process.children_system_ticks)};
}

void cpu_reap_child(Process& parent, const Process& child) {
    auto usage = cpu_waited_usage(child);
    parent.children_user_ticks = add(parent.children_user_ticks, usage.user_ticks);
    parent.children_system_ticks = add(parent.children_system_ticks, usage.system_ticks);
}

uint64_t cpu_ticks(const Task& task, bool thread) {
    auto usage = cpu_usage(task, thread);
    return add(usage.user_ticks, usage.system_ticks);
}
} // namespace ax
