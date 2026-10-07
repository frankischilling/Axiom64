// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/signals.hpp"
#include "process/futex.hpp"
#include "io/io.hpp"

namespace ax {
static bool default_ignore(int signal) {
    return signal == 17 || signal == 18 || signal == 23 || signal == 28;
}
static void notify_parent(Process* process, int code, int status) {
    for (auto& parent : tasks)
        if (parent.state != State::empty && parent.process->leader == &parent &&
            parent.process->pid == process->parent)
            queue_process_signal(parent.process, 17, process->pid, code, status);
}
static void control_signal(Process* process, int signal) {
    constexpr uint64_t stops = (1ull << 18) | (1ull << 19) | (1ull << 20) | (1ull << 21);
    bool resumed = false;
    if (signal == 18)
        process->pending_signals &= ~stops;
    if (signal >= 19 && signal <= 22)
        process->pending_signals &= ~(1ull << 17);
    for (auto& task : tasks)
        if (task.state != State::empty && task.state != State::zombie && task.process == process) {
            if (signal == 18)
                task.pending_signals &= ~stops;
            if (signal >= 19 && signal <= 22)
                task.pending_signals &= ~(1ull << 17);
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
void queue_signal(Task* task, int signal, int sender, int code, int status, uint64_t address) {
    if (signal < 1 || signal > 64 || task->state == State::empty || task->state == State::zombie)
        return;
    control_signal(task->process, signal);
    if (task->handlers->signal_actions[signal - 1][0] == 1 && signal != 9 && signal != 19)
        return;
    task->pending_signals |= 1ull << (signal - 1);
    task->signal_data[signal - 1] = {sender, code, status, address};
}
void queue_process_signal(Process* process, int signal, int sender, int code, int status,
                          uint64_t address) {
    if (!process->live_threads || signal < 1 || signal > 64)
        return;
    control_signal(process, signal);
    for (auto& task : tasks)
        if (task.state != State::empty && task.state != State::zombie && task.process == process) {
            if (task.handlers->signal_actions[signal - 1][0] == 1 && signal != 9 && signal != 19)
                return;
            process->pending_signals |= 1ull << (signal - 1);
            process->signal_data[signal - 1] = {sender, code, status, address};
            return;
        }
}
static int actionable(const Task& task) {
    uint64_t pending = (task.pending_signals | task.process->pending_signals) & ~task.signal_mask;
    for (int s = 1; s <= 64; s++)
        if (pending & (1ull << (s - 1))) {
            auto handler = task.handlers->signal_actions[s - 1][0];
            if (handler == 1 || (!handler && default_ignore(s)))
                continue;
            return s;
        }
    return 0;
}
bool signal_wakes(const Task& task) {
    return (task.wait != Wait::vfork ||
            ((task.pending_signals | task.process->pending_signals) & (1ull << 8))) && actionable(task);
}
void signal_interrupt(Task& task) {
    int signal = actionable(task);
    if (!signal)
        return;
    uint64_t flags = task.handlers->signal_actions[signal - 1][1];
    if (task.handlers->signal_actions[signal - 1][0] <= 1) {
        task.state = State::runnable;
        return; // Default delivery chooses group stop or termination.
    }
    bool restart = (flags & 0x10000000) &&
                   (task.wait == Wait::read || task.wait == Wait::write || task.wait == Wait::child);
    // A caught signal ends this attempt. SA_RESTART re-enters with a fresh fd lookup.
    io_discard(task);
    if (task.handlers->signal_actions[signal - 1][0] > 1 && !restart) {
        if (task.wait == Wait::futex)
            futex_discard(task);
        if (task.wait == Wait::sleep && task.frame.rsi && task.deadline > ticks) {
            uint64_t remaining = task.deadline - ticks,
                     time[] = {remaining / 100, (remaining % 100) * 10000000};
            task.memory->space.copy_out(task.frame.rsi, time, sizeof(time));
        }
        task.frame.rip += 2;
        task.frame.rax = uint64_t(-4);
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
    uint64_t pending = (task.pending_signals | task.process->pending_signals) & ~task.signal_mask;
    for (int signal = 1; signal <= 64; signal++)
        if (pending & (1ull << (signal - 1))) {
            if (task.pending_signals & (1ull << (signal - 1)))
                task.pending_signals &= ~(1ull << (signal - 1));
            else {
                task.process->pending_signals &= ~(1ull << (signal - 1));
                task.signal_data[signal - 1] = task.process->signal_data[signal - 1];
            }
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
                                io_discard(member);
                                member.wait = Wait::none;
                            }
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
                                task.signal_data[signal - 1].address,
                                fp,
                                {}};
            int32_t signum = signal;
            memcpy(saved.info, &signum, 4);
            memcpy(saved.info + 8, &task.signal_data[signal - 1].code, 4);
            if (signal == 11 || signal == 7 || signal == 4 || signal == 8)
                memcpy(saved.info + 16, &task.signal_data[signal - 1].address, 8);
            else {
                memcpy(saved.info + 16, &task.signal_data[signal - 1].sender, 4);
                memcpy(saved.info + 24, &task.signal_data[signal - 1].status, 4);
            }
            if (!task.memory->space.copy_out(frame, &saved, sizeof(saved)) ||
                !task.memory->space.copy_out(fp, task.fpu, 512) || !task.memory->space.valid(handler, 1)) {
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
    if (f->rsp < 8 || !current->memory->space.copy_in(&saved, f->rsp - 8, sizeof(saved))) {
        exit_task(current, 11);
        return 0;
    }
    auto& c = saved.uc.context;
    if (c.cs != 0x23 || c.ss != 0x1b || c.rip >= user_limit || c.rsp >= user_limit ||
        !current->memory->space.valid(c.rip, 1)) {
        exit_task(current, 11);
        return 0;
    }
    if (c.fpstate && !current->memory->space.copy_in(current->fpu, c.fpstate, 512)) {
        exit_task(current, 11);
        return 0;
    }
    // Invalid MXCSR reserved bits must not fault inside the kernel.
    *reinterpret_cast<uint32_t*>(current->fpu + 24) &= 0xffff;
    asm volatile("fxrstor64 %0" ::"m"(current->fpu));
    *f = {c.r15,  c.r14,   c.r13, c.r12, c.r11,
          c.r10,  c.r9,    c.r8,  c.rsi, c.rdi,
          c.rbp,  c.rdx,   c.rcx, c.rbx, c.rax,
          c.trap, c.error, c.rip, 0x23,  (c.rflags & 0x254dd5) | 0x202,
          c.rsp,  0x1b};
    current->signal_mask = saved.uc.mask & ~((1ull << 8) | (1ull << 18));
    return 0;
}
int64_t signal_syscall(Frame* f) {
    uint64_t a = f->rdi, b = f->rsi, c = f->rdx;
    if (f->rax == 15)
        return restore_signal(f);
    if (f->rax == 34 || f->rax == 130) {
        if (f->rax == 130) {
            if (b != 8)
                return -22;
            uint64_t mask;
            if (!current->memory->space.copy_in(&mask, a, 8))
                return -14;
            current->suspend_saved_mask = current->signal_mask;
            current->suspend_mask = true;
            current->signal_mask = mask & ~((1ull << 8) | (1ull << 18));
        }
        current->state = State::blocked;
        current->wait = Wait::signal;
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
        uint64_t left = current->process->alarm_deadline > ticks
                            ? current->process->alarm_deadline - ticks : 0;
        Timer old{{int64_t(current->process->alarm_interval / 100),
                   int64_t(current->process->alarm_interval % 100) * 10000},
                  {int64_t(left / 100), int64_t(left % 100) * 10000}};
        uint64_t out = f->rax == 36 ? b : c;
        if (out && !current->memory->space.copy_out(out, &old, sizeof(old)))
            return -14;
        if (f->rax == 38 && b) {
            Timer timer;
            if (!current->memory->space.copy_in(&timer, b, sizeof(timer)))
                return -14;
            auto valid = [](Timeval t) {
                return t.sec >= 0 && t.sec <= 0x7fffffff && t.usec >= 0 && t.usec < 1000000;
            };
            if (!valid(timer.interval) || !valid(timer.value))
                return -22;
            current->process->alarm_interval =
                timer.interval.sec * 100 + (timer.interval.usec + 9999) / 10000;
            uint64_t delay = timer.value.sec * 100 + (timer.value.usec + 9999) / 10000;
            current->process->alarm_deadline = delay ? ticks + delay : 0;
        }
        return 0;
    }
    if (f->rax == 37) {
        uint64_t left = current->process->alarm_deadline > ticks
                            ? current->process->alarm_deadline - ticks : 0;
        current->process->alarm_interval = 0;
        current->process->alarm_deadline = uint32_t(a) ? ticks + uint64_t(uint32_t(a)) * 100 : 0;
        return (left + 99) / 100;
    }
    if (f->rax == 131) {
        bool on_stack = current->altstack_size && f->rsp >= current->altstack_base &&
                        f->rsp - current->altstack_base < current->altstack_size;
        UserStack old{current->altstack_base,
                      on_stack                 ? 1
                      : current->altstack_size ? 0
                                               : 2,
                      0, current->altstack_size};
        if (b && !current->memory->space.copy_out(b, &old, sizeof(old)))
            return -14;
        if (a) {
            if (on_stack)
                return -1;
            UserStack stack;
            if (!current->memory->space.copy_in(&stack, a, sizeof(stack)))
                return -14;
            if (stack.flags & ~2)
                return -22;
            if (!(stack.flags & 2) &&
                (stack.size < 2048 || !current->memory->space.valid(stack.pointer, stack.size, true)))
                return -12;
            current->altstack_base = (stack.flags & 2) ? 0 : stack.pointer;
            current->altstack_size = (stack.flags & 2) ? 0 : stack.size;
        }
        return 0;
    }
    if (f->rax == 127) {
        if (b != 8)
            return -22;
        uint64_t pending = current->pending_signals | current->process->pending_signals;
        return current->memory->space.copy_out(a, &pending, 8) ? 0 : -14;
    }
    int signal = f->rax == 234 ? int(c) : int(b);
    if (signal < 0 || signal > 64)
        return -22;
    bool found = false;
    for (auto& task : tasks)
        if (task.state != State::empty &&
            (f->rax == 234   ? task.state != State::zombie &&
                              int(a) == task.process->pid && int(b) == task.pid
             : f->rax == 200 ? int(a) == task.pid
                             : task.process->leader == &task &&
                               (int(a) == task.process->pid || int(a) == -1 ||
                                   (int(a) == 0 && task.process->pgid == current->process->pgid) ||
                                   (int(a) < -1 && task.process->pgid == -int(a))))) {
            found = true;
            if (signal) {
                if (f->rax == 234 || f->rax == 200)
                    queue_signal(&task, signal, current->process->pid, f->rax == 234 ? -6 : 0);
                else
                    queue_process_signal(task.process, signal, current->process->pid);
            }
        }
    return found ? 0 : -3;
}
} // namespace ax
