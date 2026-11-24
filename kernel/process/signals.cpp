// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/signals.cpp
 * @brief   Linux signal delivery.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages dispositions, masks, user signal frames, and signal return.
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
#include "process/signals.hpp"
#include "fs/pipe.hpp"
#include "ipc/system_v_semaphores.hpp"
#include "ipc/system_v_message_queues.hpp"
#include "ipc/posix_message_queues.hpp"
#include "process/clock_sleep.hpp"
#include "process/futex.hpp"
#include "io/io.hpp"
#include "io/descriptor_wait.hpp"
#include "ipc/ipc.hpp"

namespace ax {
static bool default_ignore(int signal) {
    return signal == 17 || signal == 18 || signal == 23 || signal == 28;
}

void signal_discard_ignored(Task& task, int number) {
    auto handler = task.handlers->signal_actions[number - 1][0];
    if (handler != 1 && (handler || !default_ignore(number)))
        return;
    uint64_t mask = 1ull << (number - 1);
    task.process->pending_signals.discard(mask);
    for (auto& member : tasks)
        if (member.state != State::empty && member.state != State::zombie &&
            member.process == task.process)
            member.pending_signals.discard(mask);
}

static void notify_parent(Process* process, int code, int status) {
    for (auto& parent : tasks)
        if (parent.state != State::empty && parent.process->leader == &parent &&
            parent.process->pid == process->parent)
            queue_process_signal(parent.process, 17, process->pid, code, status, 0, process);
}

static void control_signal(Process* process, int signal) {
    constexpr uint64_t stops = (1ull << 18) | (1ull << 19) | (1ull << 20) | (1ull << 21);
    bool resumed = false;
    if (signal == 18)
        process->pending_signals.discard(stops);
    if (signal >= 19 && signal <= 22)
        process->pending_signals.discard((1ull << 17));
    for (auto& task : tasks)
        if (task.state != State::empty && task.state != State::zombie && task.process == process) {
            if (signal == 18)
                task.pending_signals.discard(stops);
            if (signal >= 19 && signal <= 22)
                task.pending_signals.discard((1ull << 17));
            if ((signal == 18 || signal == 9) && task.state == State::stopped) {
                task.state = task.wait == Wait::none ? State::runnable : State::blocked;
                resumed = true;
            }
        }
    if (signal == 18) {
        if (resumed) {
            process->continued = true;
            process->stop_reported = false;
            process->stopped = false;
            notify_parent(process, 6, 18);
        }
    }
}

static uint32_t sender_uid(int sender) {
    if (!sender)
        return 0;
    if (current_task() && current_task()->process->pid == sender)
        return current_task()->credentials.user.real;
    for (const auto& task : tasks)
        if (task.state != State::empty && task.process->pid == sender &&
            task.process->leader == &task)
            return task.credentials.user.real;
    return 0;
}

static int post_signal(Task& task, PendingSignals& queue, int signal, const SignalData& data) {
    control_signal(task.process, signal);
    if (task.handlers->signal_actions[signal - 1][0] == 1 && signal != 9 && signal != 19 &&
        !(task.signal_mask & (1ull << (signal - 1))))
        return 0;
    if (signal < 32 && (queue.mask() & (1ull << (signal - 1))))
        return 0;
    int error = queue.push(signal, data, task.credentials.user.real,
                           task.process->limits.soft(Resource::pending_signals));
    if (!error)
        epoll_signal_notify(*task.handlers);
    return error;
}

int queue_signal(Task* task, int signal, int sender, int code, int status, uint64_t address) {
    if (signal < 1 || signal > 64 || task->state == State::empty || task->state == State::zombie)
        return 0;
    return post_signal(*task, task->pending_signals, signal,
                       {sender, code, status, address, sender_uid(sender)});
}

void signal_seccomp_trap(Task& task, int number, uint32_t architecture, uint64_t instruction,
                         int reason) {
    constexpr int sigsys = 31;
    constexpr uint64_t bit = 1ull << (sigsys - 1);
    auto& handler = task.handlers->signal_actions[sigsys - 1][0];
    if ((task.signal_mask & bit) || handler == 1) {
        handler = 0;
        task.signal_mask &= ~bit;
    }
    task.pending_signals.discard(bit);
    SignalData data{};
    data.code = 1; // SYS_SECCOMP
    data.error = reason;
    data.address = instruction;
    data.syscall_number = number;
    data.syscall_architecture = architecture;
    if (post_signal(task, task.pending_signals, sigsys, data))
        exit_task(&task, sigsys);
}

static int post_process_signal(Process* process, int signal, const SignalData& data) {
    for (auto& task : tasks)
        if (task.state != State::empty && task.state != State::zombie && task.process == process)
            return post_signal(task, process->pending_signals, signal, data);
    return 0;
}

int queue_process_signal(Process* process, int signal, int sender, int code, int status,
                         uint64_t address, const Process* child) {
    if (!process->live_threads || signal < 1 || signal > 64)
        return 0;
    SignalData data{sender, code, status, address, sender_uid(sender)};
    if (child) {
        data.child_user_ticks = child->cpu_user_ticks;
        data.child_system_ticks = child->cpu_system_ticks;
    }
    return post_process_signal(process, signal, data);
}

int queue_message_signal(Process* process, int signal, const Task& sender, uint64_t value) {
    if (!process->live_threads || signal < 1 || signal > 64)
        return 0;
    SignalData data{sender.process->pid, -3, 0, 0, sender.credentials.user.real};
    data.value = value;
    return post_process_signal(process, signal, data);
}

static int actionable(const Task& task) {
    uint64_t mask = ~task.signal_mask;
    for (int number = next_pending_signal(task, mask); number;
         number = next_pending_signal(task, mask)) {
        auto handler = task.handlers->signal_actions[number - 1][0];
        if (handler != 1 && (handler || !default_ignore(number)))
            return number;
        mask &= ~(1ull << (number - 1));
    }
    return 0;
}

bool signal_wakes(const Task& task) {
    return (task.wait != Wait::vfork || signal_pending_for(task, 1ull << 8)) && actionable(task);
}

void signal_interrupt(Task& task) {
    int signal = actionable(task);
    if (!signal)
        return;
    if (task.wait == Wait::signal_queue) {
        task.signal_wait = {};
        task.frame.rip += 2;
        task.frame.rax = uint64_t(-4);
        task.wait = Wait::none;
        task.state = State::runnable;
        return;
    }
    uint64_t flags = task.handlers->signal_actions[signal - 1][1];
    if (task.handlers->signal_actions[signal - 1][0] <= 1) {
        task.state = State::runnable;
        return; // Default delivery chooses group stop or termination.
    }
    if (descriptor_wait_interrupt(task))
        return;
    bool futex = task.wait == Wait::futex;
    bool restartable =
        futex ? !task.futex.deadline
              : io_restartable(task) && (task.wait == Wait::read || task.wait == Wait::write ||
                                         task.wait == Wait::child || task.wait == Wait::file_lock ||
                                         task.wait == Wait::random);
    bool fifo_open = task.wait == Wait::fifo_open;
    bool restart =
        (flags & 0x10000000) && (restartable || task.wait == Wait::posix_queue || fifo_open);
    // A caught signal ends this attempt. A restarted call imports its inputs again.
    int64_t interrupted_result = io_interrupted_result(task);
    restart = restart && interrupted_result == -4;
    io_discard(task);
    epoll_discard_wait(task);
    if (futex)
        futex_discard(task);
    if (task.wait == Wait::posix_queue)
        posix_queue_discard(task);
    if (fifo_open)
        discard_fifo_open(task);
    if (!restart) {
        if (task.wait == Wait::semaphore)
            semaphore_discard(task);
        if (task.wait == Wait::message_queue)
            message_queue_discard(task);
        if (task.wait == Wait::sleep)
            interrupted_result = clock_sleep_interrupt(task);
        task.frame.rip += 2;
        task.frame.rax = uint64_t(interrupted_result);
        task.deadline = 0;
    }
    task.wait = Wait::none;
    task.state = State::runnable;
}

struct UserStack {
    uint64_t pointer;
    int32_t flags;
    uint32_t padding;
    uint64_t size;
};

struct Context {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip,
        rflags;
    uint16_t cs, gs, fs, ss;
    uint64_t error, trap, oldmask, address, fpstate, reserved[8];
};

struct Ucontext {
    uint64_t flags, link;
    UserStack stack;
    Context context;
    uint64_t mask;
};

struct SignalFrame {
    uint64_t restorer;
    Ucontext uc;
    uint8_t info[128];
};

static_assert(sizeof(Context) == 256 && sizeof(Ucontext) == 304 && sizeof(SignalFrame) == 440);

bool signal_deliver(Task& task) {
    message_queue_resume(task);
    posix_queue_resume(task);
    SignalData data;
    while (int signal = take_pending_signal(task, ~task.signal_mask, data)) {
        auto action = task.handlers->signal_actions[signal - 1];
        uint64_t handler = action[0], flags = action[1];
        if (handler == 1 || (!handler && default_ignore(signal)))
            continue;
        if (!handler || signal == 9 || signal == 19) {
            if (signal == 19 || signal == 20 || signal == 21 || signal == 22) {
                task.process->stopped = true;
                for (auto& member : tasks)
                    if (member.state != State::empty && member.state != State::zombie &&
                        member.process == task.process) {
                        if (member.io) {
                            if (!io_restartable(member)) {
                                member.frame.rip += 2;
                                member.frame.rax = uint64_t(io_interrupted_result(member));
                            }
                            io_discard(member);
                            member.wait = Wait::none;
                        }
                        if (member.fifo_open.handle && !resume_fifo_open(member)) {
                            discard_fifo_open(member);
                            member.wait = Wait::none;
                        }
                        epoll_stop_wait(member);
                        descriptor_wait_stop(member);
                        member.state = State::stopped;
                    }
                task.process->stop_signal = signal;
                task.process->stop_reported = false;
                notify_parent(task.process, 5, signal);
            } else
                exit_task(&task, signal);
            return false;
        }
        auto& f = task.frame;
        bool on_alt = task.altstack_size && f.rsp >= task.altstack_base &&
                      f.rsp - task.altstack_base < task.altstack_size;
        uint64_t top = ((flags & 0x08000000) && task.altstack_size && !on_alt)
                           ? task.altstack_base + task.altstack_size
                           : f.rsp;
        if (top < 128 + sizeof(SignalFrame) + 512 + 32) {
            exit_task(&task, 11);
            return false;
        }
        uint64_t frame = ((top - 128 - sizeof(SignalFrame) - 512 - 32) & ~15ull) - 8;
        uint64_t fp = (frame + sizeof(SignalFrame) + 15) & ~15ull;
        SignalFrame saved{};
        saved.restorer = action[2] ? action[2] : signal_trampoline;
        saved.uc.flags = 6;
        saved.uc.mask = task.suspend_mask ? task.suspend_saved_mask : task.signal_mask;
        task.suspend_mask = false;
        saved.uc.stack = {task.altstack_base,
                          on_alt               ? 1
                          : task.altstack_size ? 0
                                               : 2,
                          0, task.altstack_size};
        saved.uc.context = {f.r8,
                            f.r9,
                            f.r10,
                            f.r11,
                            f.r12,
                            f.r13,
                            f.r14,
                            f.r15,
                            f.rdi,
                            f.rsi,
                            f.rbp,
                            f.rbx,
                            f.rdx,
                            f.rax,
                            f.rcx,
                            f.rsp,
                            f.rip,
                            f.rflags,
                            0x23,
                            0,
                            0,
                            0x1b,
                            f.error,
                            f.vector,
                            task.signal_mask,
                            data.address,
                            fp,
                            {}};
        format_signal_info(saved.info, signal, data);
        if (!task.memory->space.copy_out(frame, &saved, sizeof(saved)) ||
            !task.memory->space.copy_out(fp, task.fpu, 512) ||
            !task.memory->space.valid(handler, 1)) {
            exit_task(&task, 11);
            return false;
        }
        f.rip = handler;
        f.rsp = frame;
        f.rdi = signal;
        f.rsi = frame + offsetof(SignalFrame, info);
        f.rdx = frame + offsetof(SignalFrame, uc);
        f.rax = 0;
        f.rflags &= ~uint64_t(0x10500);
        task.signal_mask |= action[3];
        if (!(flags & 0x40000000))
            task.signal_mask |= 1ull << (signal - 1);
        task.signal_mask &= ~((1ull << 8) | (1ull << 18));
        if (flags & 0x80000000)
            memset(action, 0, 32);
        break;
    }
    return task.state == State::runnable;
}

void signal_tick() {
    for (auto& task : tasks)
        if (task.state != State::empty && task.process->leader == &task &&
            task.process->live_threads && task.process->alarm_deadline &&
            ticks >= task.process->alarm_deadline) {
            task.process->alarm_deadline =
                task.process->alarm_interval ? ticks + task.process->alarm_interval : 0;
            queue_process_signal(task.process, 14);
        }
}

static int64_t restore_signal(Frame* f) {
    SignalFrame saved;
    if (f->rsp < 8 || !current_task()->memory->space.copy_in(&saved, f->rsp - 8, sizeof(saved))) {
        exit_task(current_task(), 11);
        return 0;
    }
    auto& c = saved.uc.context;
    if (c.cs != 0x23 || c.ss != 0x1b || c.rip >= user_limit || c.rsp >= user_limit ||
        !current_task()->memory->space.valid(c.rip, 1)) {
        exit_task(current_task(), 11);
        return 0;
    }
    if (c.fpstate && !current_task()->memory->space.copy_in(current_task()->fpu, c.fpstate, 512)) {
        exit_task(current_task(), 11);
        return 0;
    }
    // Invalid MXCSR reserved bits must not fault inside the kernel.
    *reinterpret_cast<uint32_t*>(current_task()->fpu + 24) &= 0xffff;
    asm volatile("fxrstor64 %0" ::"m"(current_task()->fpu));
    *f = {c.r15,  c.r14,   c.r13, c.r12, c.r11,
          c.r10,  c.r9,    c.r8,  c.rsi, c.rdi,
          c.rbp,  c.rdx,   c.rcx, c.rbx, c.rax,
          c.trap, c.error, c.rip, 0x23,  (c.rflags & 0x254dd5) | 0x202,
          c.rsp,  0x1b};
    current_task()->signal_mask = saved.uc.mask & ~((1ull << 8) | (1ull << 18));
    return 0;
}

static int queue_from_user(const Frame& frame) {
    bool thread = frame.rax == 297;
    int group = int(frame.rdi);
    int target = thread ? int(frame.rsi) : group;
    int signal = thread ? int(frame.rdx) : int(frame.rsi);
    uint64_t pointer = thread ? frame.r10 : frame.rdx;
    uint8_t bytes[48];
    if (!current_task()->memory->space.copy_in(bytes, pointer, sizeof(bytes)))
        return -14;
    if (thread && (group <= 0 || target <= 0))
        return -22;
    SignalData data;
    memcpy(&data.error, bytes + 4, 4);
    memcpy(&data.code, bytes + 8, 4);
    if ((data.code >= 0 || data.code == -6) && target != current_task()->pid)
        return -1;
    if (signal < 0 || signal > 64)
        return -22;
    memcpy(&data.sender, bytes + 16, 4);
    memcpy(&data.uid, bytes + 20, 4);
    memcpy(&data.value, bytes + 24, 8);
    if (data.code > 0) {
        memcpy(&data.address, bytes + 16, 8);
        memcpy(&data.status, bytes + 24, 4);
        memcpy(&data.child_user_ticks, bytes + 32, 8);
        memcpy(&data.child_system_ticks, bytes + 40, 8);
    }
    for (auto& task : tasks) {
        if (task.state == State::empty || task.pid != target ||
            (thread && (task.state == State::zombie || task.process->pid != group)))
            continue;
        if (task.process != current_task()->process &&
            !credential_signal(current_task()->credentials, task.credentials,
                               task.process->sid == current_task()->process->sid, signal))
            return -1;
        if (!signal)
            return 0;
        return thread ? post_signal(task, task.pending_signals, signal, data)
                      : post_process_signal(task.process, signal, data);
    }
    return -3;
}

int64_t signal_syscall(Frame* f) {
    uint64_t a = f->rdi, b = f->rsi, c = f->rdx;
    if (f->rax == 15)
        return restore_signal(f);
    if (f->rax == 129 || f->rax == 297)
        return queue_from_user(*f);
    if (f->rax == 128)
        return signal_wait_enter(f);
    if (f->rax == 34 || f->rax == 130) {
        if (f->rax == 130) {
            if (b != 8)
                return -22;
            uint64_t mask;
            if (!current_task()->memory->space.copy_in(&mask, a, 8))
                return -14;
            current_task()->suspend_saved_mask = current_task()->signal_mask;
            current_task()->suspend_mask = true;
            current_task()->signal_mask = mask & ~((1ull << 8) | (1ull << 18));
        }
        current_task()->state = State::blocked;
        current_task()->wait = Wait::signal;
        return would_block;
    }
    if (f->rax == 36 || f->rax == 38) {
        if (a != 0)
            return -22; // ITIMER_REAL; virtual/profiling clocks are not implemented.

        struct Timeval {
            int64_t sec, usec;
        };

        struct Timer {
            Timeval interval, value;
        };

        uint64_t left = current_task()->process->alarm_deadline > ticks
                            ? current_task()->process->alarm_deadline - ticks
                            : 0;
        Timer old{{int64_t(current_task()->process->alarm_interval / 100),
                   int64_t(current_task()->process->alarm_interval % 100) * 10000},
                  {int64_t(left / 100), int64_t(left % 100) * 10000}};
        uint64_t out = f->rax == 36 ? b : c;
        if (out && !current_task()->memory->space.copy_out(out, &old, sizeof(old)))
            return -14;
        if (f->rax == 38 && b) {
            Timer timer;
            if (!current_task()->memory->space.copy_in(&timer, b, sizeof(timer)))
                return -14;
            auto valid = [](Timeval t) {
                return t.sec >= 0 && t.sec <= 0x7fffffff && t.usec >= 0 && t.usec < 1000000;
            };
            if (!valid(timer.interval) || !valid(timer.value))
                return -22;
            current_task()->process->alarm_interval =
                timer.interval.sec * 100 + (timer.interval.usec + 9999) / 10000;
            uint64_t delay = timer.value.sec * 100 + (timer.value.usec + 9999) / 10000;
            current_task()->process->alarm_deadline = delay ? ticks + delay : 0;
        }
        return 0;
    }
    if (f->rax == 37) {
        uint64_t left = current_task()->process->alarm_deadline > ticks
                            ? current_task()->process->alarm_deadline - ticks
                            : 0;
        current_task()->process->alarm_interval = 0;
        current_task()->process->alarm_deadline =
            uint32_t(a) ? ticks + uint64_t(uint32_t(a)) * 100 : 0;
        return (left + 99) / 100;
    }
    if (f->rax == 131) {
        bool on_stack = current_task()->altstack_size && f->rsp >= current_task()->altstack_base &&
                        f->rsp - current_task()->altstack_base < current_task()->altstack_size;
        UserStack old{current_task()->altstack_base,
                      on_stack                        ? 1
                      : current_task()->altstack_size ? 0
                                                      : 2,
                      0, current_task()->altstack_size};
        if (b && !current_task()->memory->space.copy_out(b, &old, sizeof(old)))
            return -14;
        if (a) {
            if (on_stack)
                return -1;
            UserStack stack;
            if (!current_task()->memory->space.copy_in(&stack, a, sizeof(stack)))
                return -14;
            if (stack.flags & ~2)
                return -22;
            if (!(stack.flags & 2) && (stack.size < 2048 || !current_task()->memory->space.valid(
                                                                stack.pointer, stack.size, true)))
                return -12;
            current_task()->altstack_base = (stack.flags & 2) ? 0 : stack.pointer;
            current_task()->altstack_size = (stack.flags & 2) ? 0 : stack.size;
        }
        return 0;
    }
    if (f->rax == 127) {
        if (b != 8)
            return -22;
        uint64_t pending = (current_task()->pending_signals.mask() |
                            current_task()->process->pending_signals.mask()) &
                           current_task()->signal_mask;
        return current_task()->memory->space.copy_out(a, &pending, 8) ? 0 : -14;
    }
    int signal = f->rax == 234 ? int(c) : int(b);
    if (signal < 0 || signal > 64)
        return -22;
    bool found = false, permitted = false;
    for (auto& task : tasks)
        if (task.state != State::empty &&
            (f->rax == 234
                 ? task.state != State::zombie && int(a) == task.process->pid && int(b) == task.pid
             : f->rax == 200
                 ? int(a) == task.pid
                 : task.process->leader == &task &&
                       (int(a) == task.process->pid || int(a) == -1 ||
                        (int(a) == 0 && task.process->pgid == current_task()->process->pgid) ||
                        (int(a) < -1 && task.process->pgid == -int(a))))) {
            found = true;
            if (task.process != current_task()->process &&
                !credential_signal(current_task()->credentials, task.credentials,
                                   task.process->sid == current_task()->process->sid, signal))
                continue;
            permitted = true;
            if (signal) {
                if (f->rax == 234 || f->rax == 200)
                    return queue_signal(&task, signal, current_task()->process->pid, -6);
                else
                    queue_process_signal(task.process, signal, current_task()->process->pid);
            }
        }
    return permitted ? 0 : found ? -1 : -3;
}
} // namespace ax
