// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/resource.cpp
 * @brief   Linux resource-limit syscalls.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Translates Linux resource IDs and copies limit values for getrlimit,
 * setrlimit, and prlimit.
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
#include "process/task.hpp"

namespace ax {
namespace {
bool permitted(const Task& target) {
    if (&target == current || capable(current->credentials, Capability::sys_resource))
        return true;
    const auto& from = current->credentials;
    const auto& to = target.credentials;
    return from.user.real == to.user.real && from.user.real == to.user.effective &&
           from.user.real == to.user.saved && from.group.real == to.group.real &&
           from.group.real == to.group.effective && from.group.real == to.group.saved;
}
} // namespace

int64_t resource_syscall(Frame* frame) {
    auto& space = current->memory->space;
    Task* target = current;
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
    int error =
        target->process->limits.exchange(resource, input ? &replacement : nullptr, &previous,
                                         capable(current->credentials, Capability::sys_resource));
    if (error)
        return error;
    if (frame->rax == 97 && !output)
        return -14;
    return output && !space.copy_out(output, &previous, sizeof(previous)) ? -14 : 0;
}
} // namespace ax
