// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/clock_sleep.cpp
 * @brief   Implement Linux relative and absolute clock sleeps.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Keeps the requested deadline and remaining-time address in the sleeping task.
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
#include "process/clock_sleep.hpp"
#include "core/time.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr int realtime = 0, monotonic = 1, boottime = 7;
constexpr int absolute_time = 1;
constexpr uint64_t ns_per_second = 1000000000, ns_per_tick = 10000000;

struct UserTime {
    int64_t seconds, nanoseconds;
};

uint64_t interval_ns(const UserTime& time) {
    const auto fraction = uint64_t(time.nanoseconds);
    const auto seconds = uint64_t(time.seconds);
    // Linux clamps the imported interval to its signed nanosecond range.
    if (seconds > (INT64_MAX - fraction) / ns_per_second)
        return INT64_MAX;
    return seconds * ns_per_second + fraction;
}
} // namespace

int64_t linux_clock_nanosleep(Task& task, int clock, int flags, uint64_t address,
                              uint64_t remaining) {
    switch (clock) {
    case realtime:
    case monotonic:
    case boottime:
        break;
    case 2:  // CLOCK_PROCESS_CPUTIME_ID
    case 4:  // CLOCK_MONOTONIC_RAW
    case 5:  // CLOCK_REALTIME_COARSE
    case 6:  // CLOCK_MONOTONIC_COARSE
    case 8:  // CLOCK_REALTIME_ALARM
    case 9:  // CLOCK_BOOTTIME_ALARM
    case 11: // CLOCK_TAI
        return -95;
    default:
        return -22;
    }

    UserTime request;
    if (!task.memory->space.copy_in(&request, address, sizeof(request)))
        return -14;
    if (request.seconds < 0 || request.nanoseconds < 0 ||
        uint64_t(request.nanoseconds) >= ns_per_second)
        return -22;

    const bool absolute = flags & absolute_time;
    const bool wall = absolute && clock == realtime;
    const auto duration = interval_ns(request);
    auto deadline = (duration + ns_per_tick - 1) / ns_per_tick;
    if (absolute) {
        if (deadline <= (wall ? clock_realtime_ticks() : ticks))
            return 0;
    } else {
        if (!deadline)
            return 0;
        // The current clock sample is truncated. Allow for its partial tick
        // so even a sub-tick relative request sleeps for at least its interval.
        deadline = ticks + min(deadline + 1, UINT64_MAX - ticks);
    }

    task.sleep = {deadline, absolute ? 0 : remaining, duration, wall};
    task.wait = Wait::sleep;
    task.state = State::blocked;
    return would_block;
}

bool clock_sleep_resume(Task& task) {
    const auto now = task.sleep.realtime ? clock_realtime_ticks() : ticks;
    if (now < task.sleep.deadline)
        return false;
    task.sleep = {};
    task.frame.rip += 2;
    task.frame.rax = 0;
    task.wait = Wait::none;
    task.state = State::runnable;
    return true;
}

int clock_sleep_interrupt(Task& task) {
    const auto sleep = task.sleep;
    task.sleep = {};
    if (sleep.remaining && ticks < sleep.deadline) {
        const auto bounded_ticks = min(sleep.deadline - ticks, uint64_t(INT64_MAX) / ns_per_tick);
        const auto ns = min(sleep.request_ns, bounded_ticks * ns_per_tick);
        const UserTime left{int64_t(ns / ns_per_second), int64_t(ns % ns_per_second)};
        if (!task.memory->space.copy_out(sleep.remaining, &left, sizeof(left)))
            return -14;
    }
    return -4;
}
} // namespace ax
