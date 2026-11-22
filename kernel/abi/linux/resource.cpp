// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/resource.cpp
 * @brief   Linux resource limits, usage, and system information.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Translates Linux resource IDs and copies process usage and system accounting
 * to the Linux x86-64 userspace layouts.
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
#include "abi/linux/resource.hpp"
#include "core/time.hpp"
#include "drivers/block/block.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
struct SystemInformation {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    uint16_t procs, pad;
    uint32_t alignment;
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit, tail;
};

static_assert(sizeof(SystemInformation) == 112 && offsetof(SystemInformation, procs) == 80 &&
              offsetof(SystemInformation, totalhigh) == 88 &&
              offsetof(SystemInformation, mem_unit) == 104);

bool permitted(const Task& target) {
    if (&target == current_task() || capable(current_task()->credentials, Capability::sys_resource))
        return true;
    const auto& from = current_task()->credentials;
    const auto& to = target.credentials;
    return from.user.real == to.user.real && from.user.real == to.user.effective &&
           from.user.real == to.user.saved && from.group.real == to.group.real &&
           from.group.real == to.group.effective && from.group.real == to.group.saved;
}
} // namespace

ResourceUsage linux_resource_usage(CpuUsage cpu) {
    return {{int64_t(cpu.user_ticks / 100), int64_t(cpu.user_ticks % 100 * 10000)},
            {int64_t(cpu.system_ticks / 100), int64_t(cpu.system_ticks % 100 * 10000)},
            {}};
}

int64_t resource_usage_syscall(int who, uint64_t output) {
    CpuUsage time;
    switch (who) {
    case 0:
    case 1:
        time = cpu_usage(*current_task(), who == 1);
        break;
    case -1:
        time = {current_task()->process->children_user_ticks,
                current_task()->process->children_system_ticks};
        break;
    default:
        return -22;
    }
    auto usage = linux_resource_usage(time);
    return current_task()->memory->space.copy_out(output, &usage, sizeof(usage)) ? 0 : -14;
}

int64_t system_information_syscall(uint64_t output) {
    clock_refresh();
    const auto ram = physical_memory_stats();
    const auto load = cpu_load_averages();
    SystemInformation info{};
    info.uptime = ticks / 100 + (ticks % 100 != 0);
    info.loads[0] = load.one;
    info.loads[1] = load.five;
    info.loads[2] = load.fifteen;
    info.totalram = ram.total;
    info.freeram = ram.free;
    info.sharedram = ram.shared;
    info.bufferram = block_buffer_bytes();
    for (const auto& task : tasks)
        if (task.state != State::empty)
            info.procs++;
    info.mem_unit = 1;
    return current_task()->memory->space.copy_out(output, &info, sizeof(info)) ? 0 : -14;
}

int64_t resource_syscall(Frame* frame) {
    auto& space = current_task()->memory->space;
    Task* target = current_task();
    unsigned resource = uint32_t(frame->rdi);
    uint64_t input = frame->rax == 160 ? frame->rsi : 0;
    uint64_t output = frame->rax == 97 ? frame->rsi : 0;
    if (frame->rax == 302) {
        resource = uint32_t(frame->rsi);
        input = frame->rdx;
        output = frame->r10;
    }
    ResourceLimit replacement{}, previous{};
    if (input && !space.copy_in(&replacement, input, sizeof(replacement)))
        return -14;
    if (frame->rax == 160 && !input)
        return -14;
    if (frame->rax == 302 && int32_t(frame->rdi)) {
        target = nullptr;
        for (auto& task : tasks)
            if (task.state != State::empty && task.pid == int32_t(frame->rdi))
                target = &task;
        if (!target)
            return -3;
        if (!permitted(*target))
            return -1;
    }
    int error = target->process->limits.exchange(
        resource, input ? &replacement : nullptr, &previous,
        capable(current_task()->credentials, Capability::sys_resource));
    if (error)
        return error;
    if (frame->rax == 97 && !output)
        return -14;
    return output && !space.copy_out(output, &previous, sizeof(previous)) ? -14 : 0;
}
} // namespace ax
