// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/wall_clock.cpp
 * @brief   Implement Linux wall-clock updates.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Validates the Linux time structures and checks permission to set the realtime clock.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "abi/linux/wall_clock.hpp"
#include "core/time.hpp"
#include "process/task.hpp"
#include "security/credentials.hpp"

namespace ax {
namespace {
struct CalendarTime {
    int64_t seconds, fraction;
};

constexpr int64_t second_ns = 1000000000;
constexpr int64_t maximum_seconds = INT64_MAX / second_ns - 30LL * 365 * 24 * 3600;

int set_wall_clock(const Task& task, const CalendarTime* time, const ClockTimezone* timezone) {
    if (time && (time->seconds < 0 || time->seconds >= maximum_seconds || time->fraction < 0 ||
                 time->fraction >= second_ns))
        return -22;
    if (!capable(task.credentials, Capability::sys_time))
        return -1;
    if (timezone && (timezone->minutes_west < -900 || timezone->minutes_west > 900))
        return -22;
    uint64_t requested = 0;
    if (time)
        requested = uint64_t(time->seconds) * 100 + uint64_t(time->fraction) / 10000000;
    return clock_update_realtime(time ? &requested : nullptr, timezone);
}
} // namespace

int linux_settimeofday(Task& task, uint64_t time_address, uint64_t timezone_address) {
    CalendarTime time{};
    ClockTimezone timezone{};
    auto& memory = task.memory->space;
    if (time_address) {
        if (!memory.copy_in(&time, time_address, sizeof(time)))
            return -14;
        if (time.fraction < 0 || time.fraction >= 1000000)
            return -22;
        time.fraction *= 1000;
    }
    if (timezone_address && !memory.copy_in(&timezone, timezone_address, sizeof(timezone)))
        return -14;
    return set_wall_clock(task, time_address ? &time : nullptr,
                          timezone_address ? &timezone : nullptr);
}

int linux_clock_settime(Task& task, int clock, uint64_t address) {
    if (clock != 0) // CLOCK_REALTIME
        return -22;
    CalendarTime time;
    if (!task.memory->space.copy_in(&time, address, sizeof(time)))
        return -14;
    return set_wall_clock(task, &time, nullptr);
}
} // namespace ax
