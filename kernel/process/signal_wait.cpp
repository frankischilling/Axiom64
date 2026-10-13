// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/signals.hpp"

namespace ax {
namespace {
int64_t consume(Task& task, uint64_t mask, uint64_t information) {
    uint64_t pending = task.pending_signals & mask;
    bool thread = pending != 0;
    if (!pending)
        pending = task.process->pending_signals & mask;
    // Linux selects the thread queue before the shared queue, and synchronous
    // signals before other numbers within either queue.
    constexpr uint64_t synchronous =
        (1ull << 3) | (1ull << 4) | (1ull << 6) | (1ull << 7) | (1ull << 10) | (1ull << 30);
    if (pending & synchronous)
        pending &= synchronous;
    for (int signal = 1; signal <= 64; signal++) {
        uint64_t bit = 1ull << (signal - 1);
        if (!(pending & bit))
            continue;
        SignalData data;
        if (thread) {
            task.pending_signals &= ~bit;
            data = task.signal_data[signal - 1];
        } else {
            task.process->pending_signals &= ~bit;
            data = task.process->signal_data[signal - 1];
        }
        if (information) {
            uint8_t bytes[128]{};
            int32_t number = signal;
            memcpy(bytes, &number, 4);
            memcpy(bytes + 8, &data.code, 4);
            if (data.code > 0 && (signal == 11 || signal == 7 || signal == 4 || signal == 8))
                memcpy(bytes + 16, &data.address, 8);
            else {
                memcpy(bytes + 16, &data.sender, 4);
                memcpy(bytes + 20, &data.uid, 4);
                memcpy(bytes + 24, &data.status, 4);
            }
            // Linux dequeues before copying siginfo. A failed output copy still
            // consumes this signal and must not leave it pending for another waiter.
            if (!task.memory->space.copy_out(information, bytes, sizeof(bytes)))
                return -14;
        }
        return signal;
    }
    return 0;
}
} // namespace

int64_t signal_wait_enter(Frame* frame) {
    if (frame->r10 != 8)
        return -22;
    uint64_t mask;
    if (!current->memory->space.copy_in(&mask, frame->rdi, sizeof(mask)))
        return -14;
    mask &= ~((1ull << 8) | (1ull << 18));
    bool finite = frame->rdx != 0;
    uint64_t deadline = 0;
    if (finite) {
        struct {
            int64_t seconds, nanoseconds;
        } timeout;

        if (!current->memory->space.copy_in(&timeout, frame->rdx, sizeof(timeout)))
            return -14;
        if (timeout.seconds < 0 || timeout.nanoseconds < 0 || timeout.nanoseconds >= 1000000000)
            return -22;
        uint64_t fraction = (uint64_t(timeout.nanoseconds) + 9999999) / 10000000;
        uint64_t seconds = uint64_t(timeout.seconds);
        constexpr uint64_t maximum = uint64_t(INT64_MAX) / 10000000 + 1;
        uint64_t duration = seconds > maximum / 100 ? maximum : seconds * 100 + fraction;
        if (duration > maximum)
            duration = maximum;
        deadline = duration > UINT64_MAX - ticks ? UINT64_MAX : ticks + duration;
    }
    int64_t result = consume(*current, mask, frame->rsi);
    if (result)
        return result;
    if (finite && deadline <= ticks)
        return -11;
    current->signal_wait = {mask, frame->rsi, deadline, finite};
    current->wait = Wait::signal_queue;
    current->state = State::blocked;
    return would_block;
}

bool signal_wait_resume(Task& task) {
    int64_t result = consume(task, task.signal_wait.mask, task.signal_wait.information);
    if (!result && task.signal_wait.finite && ticks >= task.signal_wait.deadline)
        result = -11;
    if (!result)
        return false;
    task.signal_wait = {};
    task.frame.rip += 2;
    task.frame.rax = uint64_t(result);
    task.wait = Wait::none;
    task.state = State::runnable;
    return true;
}
} // namespace ax
