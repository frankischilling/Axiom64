// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/security/seccomp.cpp
 * @brief   Task-local Linux seccomp policy and filter lifetime.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#include "security/seccomp.hpp"
#include "core/classic_filter.hpp"
#include "core/time.hpp"
#include "process/signals.hpp"

namespace ax {
struct SeccompFilter {
    SeccompFilter* parent;
    unsigned references, length, path_length;

    FilterInstruction* instructions() {
        return reinterpret_cast<FilterInstruction*>(this + 1);
    }
};

namespace {
constexpr unsigned strict_mode = 1, filter_mode = 2;
constexpr uint32_t thread_sync = 1, sync_error = 1 << 4;
constexpr unsigned max_path_length = 32768;
constexpr uint32_t audit_x86_64 = 0xc000003e;
constexpr uint32_t action_mask = 0xffff0000, data_mask = 0xffff;
constexpr uint32_t kill_process = 0x80000000, kill_thread = 0, trap = 0x00030000;
constexpr uint32_t return_errno = 0x00050000, notify = 0x7fc00000, trace = 0x7ff00000;
constexpr uint32_t log_call = 0x7ffc0000, allow = 0x7fff0000;
constexpr int sigsys = 31;
uint64_t next_log_time;

struct FilterProgram {
    uint16_t length;
    uint64_t instructions;
};

struct SyscallData {
    int32_t number;
    uint32_t architecture;
    uint64_t instruction_pointer;
    uint64_t arguments[6];
};

static_assert(sizeof(FilterProgram) == 16 && offsetof(FilterProgram, instructions) == 8);
static_assert(sizeof(SyscallData) == 64 && offsetof(SyscallData, arguments) == 16);

void retain_filter(SeccompFilter* filter) {
    if (filter)
        ++filter->references;
}

void release_filter(SeccompFilter* filter) {
    while (filter && --filter->references == 0) {
        auto parent = filter->parent;
        release(filter);
        filter = parent;
    }
}

void assign_filter(Task& task, SeccompFilter* filter, unsigned count) {
    retain_filter(filter);
    release_filter(task.seccomp_filter);
    task.seccomp_filter = filter;
    task.seccomp_filter_count = count;
    task.seccomp_mode = filter_mode;
}

bool other_live_thread(const Task& other, const Task& caller) {
    return &other != &caller && other.process == caller.process && other.state != State::empty &&
           other.state != State::zombie;
}

bool can_sync(const Task& other, const Task& caller) {
    if (!other.seccomp_mode)
        return true;
    if (other.seccomp_mode != filter_mode)
        return false;
    for (auto filter = caller.seccomp_filter; filter; filter = filter->parent)
        if (filter == other.seccomp_filter)
            return true;
    return false;
}

int64_t attach_filter(Task& task, uint32_t flags, uint64_t argument) {
    if (flags & ~(thread_sync | sync_error))
        return -22;
    FilterProgram program;
    auto& memory = task.memory->space;
    if (!memory.copy_in(&program, argument, sizeof(program)))
        return -14;
    const unsigned length = program.length;
    if (!length || length > max_classic_filter_instructions)
        return -22;
    if (!task.credentials.no_new_privileges && !capable(task.credentials, Capability::sys_admin))
        return -13;
    if (!program.instructions)
        return -22;

    auto filter = static_cast<SeccompFilter*>(
        alloc(sizeof(SeccompFilter) + length * sizeof(FilterInstruction)));
    auto masks = static_cast<uint16_t*>(alloc(length * sizeof(uint16_t)));
    int64_t error = 0;
    if (!filter || !masks)
        error = -12;
    else if (!memory.copy_in(filter->instructions(), program.instructions,
                             length * sizeof(FilterInstruction)))
        error = -14;
    else if (!validate_classic_filter(filter->instructions(), length, masks, FilterContext::syscall,
                                      sizeof(SyscallData)))
        error = -22;
    release(masks);

    const auto parent = task.seccomp_filter;
    const unsigned path_length = length + (parent ? parent->path_length + 4 : 0);
    if (!error && path_length > max_path_length)
        error = -12;
    if (!error && (flags & thread_sync))
        for (const auto& other : tasks)
            if (other_live_thread(other, task) && !can_sync(other, task)) {
                error = flags & sync_error ? -3 : other.pid;
                break;
            }
    if (error) {
        release(filter);
        return error;
    }

    // Syscall entry holds the kernel lock across both the check and publication.
    *filter = {parent, 1, length, path_length};
    retain_filter(parent);
    const unsigned count = task.seccomp_filter_count + 1;
    assign_filter(task, filter, count);
    if (flags & thread_sync)
        for (auto& other : tasks)
            if (other_live_thread(other, task)) {
                if (task.credentials.no_new_privileges)
                    other.credentials.no_new_privileges = true;
                assign_filter(other, filter, count);
            }
    release_filter(filter);
    return 0;
}

int64_t action_available(Task& task, uint32_t flags, uint64_t argument) {
    if (flags)
        return -22;
    uint32_t action;
    if (!task.memory->space.copy_in(&action, argument, sizeof(action)))
        return -14;
    switch (action) {
    case allow:
    case return_errno:
    case log_call:
    case trap:
    case kill_thread:
    case kill_process:
        return 0;
    default:
        return -95;
    }
}
} // namespace

void seccomp_inherit(Task& child, const Task& parent) {
    child.seccomp_filter = parent.seccomp_filter;
    child.seccomp_mode = parent.seccomp_mode;
    child.seccomp_filter_count = parent.seccomp_filter_count;
    retain_filter(child.seccomp_filter);
}

void seccomp_release(Task& task) {
    release_filter(task.seccomp_filter);
    task.seccomp_filter = nullptr;
}

int64_t seccomp_syscall(Task& task, uint32_t operation, uint32_t flags, uint64_t argument) {
    switch (operation) {
    case 0: // SECCOMP_SET_MODE_STRICT
        if (flags || argument || task.seccomp_mode)
            return -22;
        task.seccomp_mode = strict_mode;
        return 0;
    case 1: // SECCOMP_SET_MODE_FILTER
        return task.seccomp_mode == strict_mode ? -22 : attach_filter(task, flags, argument);
    case 2: // SECCOMP_GET_ACTION_AVAIL
        return action_available(task, flags, argument);
    default:
        return -22;
    }
}

int64_t seccomp_set_mode(Task& task, uint64_t mode, uint64_t program) {
    if (mode == strict_mode)
        return seccomp_syscall(task, 0, 0, 0);
    if (mode == filter_mode)
        return seccomp_syscall(task, 1, 0, program);
    return -22;
}

bool seccomp_may_dispatch(Task& task, const Frame& frame, int64_t& result) {
    if (task.seccomp_mode == strict_mode) {
        if (frame.rax == 0 || frame.rax == 1 || frame.rax == 15 || frame.rax == 60)
            return true;
        exit_thread(&task, 9);
        return false;
    }
    if (!task.seccomp_filter)
        return true;
    const SyscallData data{int32_t(frame.rax),
                           audit_x86_64,
                           frame.rip,
                           {frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9}};
    const FilterInput input{reinterpret_cast<const uint8_t*>(&data), sizeof(data)};
    uint32_t decision = allow;
    for (auto filter = task.seccomp_filter; filter; filter = filter->parent) {
        const uint32_t value = run_classic_filter(filter->instructions(), filter->length, input,
                                                  FilterContext::syscall);
        // Signed action order gives KILL_PROCESS precedence. The newest filter wins ties.
        if (int32_t(value & action_mask) < int32_t(decision & action_mask))
            decision = value;
    }
    switch (decision & action_mask) {
    case allow:
        return true;
    case log_call: {
        const auto now = clock_monotonic_ns();
        if (now >= next_log_time) {
            log("seccomp: tid=%u syscall=%d\n", uint64_t(task.pid), int64_t(data.number));
            next_log_time = now + 100'000'000;
        }
        return true;
    }
    case return_errno:
        result = -int64_t(min(decision & data_mask, 4095u));
        break;
    case trap:
        result = int64_t(frame.rax);
        signal_seccomp_trap(task, data.number, data.architecture, data.instruction_pointer,
                            int(decision & data_mask));
        break;
    case notify:
    case trace:
        result = -38;
        break;
    case kill_thread:
        exit_thread(&task, sigsys);
        break;
    default:
        exit_task(&task, sigsys);
        break;
    }
    return false;
}
} // namespace ax
