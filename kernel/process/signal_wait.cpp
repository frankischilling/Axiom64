// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/signal_wait.cpp
 * @brief   Synchronous signal waits.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Implements waits for selected pending signals with Linux timeout and
 * interruption semantics.
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

namespace ax {
bool signal_pending_for(const Task& task, uint64_t mask) {
    return ((task.pending_signals.mask() | task.process->pending_signals.mask()) & mask) != 0;
}

int next_pending_signal(const Task& task, uint64_t mask) {
    uint64_t pending = task.pending_signals.mask() & mask;
    if (!pending)
        pending = task.process->pending_signals.mask() & mask;
    if (!pending)
        return 0;
    // Linux selects the thread queue before the shared queue, and synchronous
    // signals before other numbers within either queue.
    constexpr uint64_t synchronous =
        (1ull << 3) | (1ull << 4) | (1ull << 6) | (1ull << 7) | (1ull << 10) | (1ull << 30);
    if (pending & synchronous)
        pending &= synchronous;
    return int(__builtin_ctzll(pending)) + 1;
}

int take_pending_signal(Task& task, uint64_t mask, SignalData& data) {
    int number = next_pending_signal(task, mask);
    if (number) {
        auto& queue = task.pending_signals.mask() & mask ? task.pending_signals
                                                         : task.process->pending_signals;
        data = queue.take(number);
    }
    return number;
}

void format_signal_info(uint8_t (&bytes)[128], int number, const SignalData& data) {
    memset(bytes, 0, sizeof(bytes));
    memcpy(bytes, &number, 4);
    memcpy(bytes + 4, &data.error, 4);
    memcpy(bytes + 8, &data.code, 4);
    if (data.code > 0 && (number == 11 || number == 7 || number == 5 || number == 4 || number == 8))
        memcpy(bytes + 16, &data.address, 8);
    else {
        memcpy(bytes + 16, &data.sender, 4);
        memcpy(bytes + 20, &data.uid, 4);
        if (data.code < 0 && data.code != -6)
            memcpy(bytes + 24, &data.value, 8);
        else if (number == 17 && data.code > 0) {
            memcpy(bytes + 24, &data.status, 4);
            memcpy(bytes + 32, &data.child_user_ticks, 8);
            memcpy(bytes + 40, &data.child_system_ticks, 8);
        }
    }
}

namespace {
int64_t consume(Task& task, uint64_t mask, uint64_t information) {
    SignalData data;
    int32_t number = take_pending_signal(task, mask, data);
    if (!number || !information)
        return number;
    uint8_t bytes[128];
    format_signal_info(bytes, number, data);
    // Linux dequeues before copying siginfo. A failed output copy still
    // consumes this signal and must not leave it pending for another waiter.
    return task.memory->space.copy_out(information, bytes, sizeof(bytes)) ? number : -14;
}
} // namespace

int64_t signal_wait_enter(Frame* frame) {
    if (frame->r10 != 8)
        return -22;
    uint64_t mask;
    if (!current->memory->space.copy_in(&mask, frame->rdi, sizeof(mask)))
        return -14;
    mask &= ~unmaskable_signals;
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
