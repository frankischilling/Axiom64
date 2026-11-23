// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/rtc.cpp
 * @brief   PC CMOS clock access.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reads the date and time registers used to initialize the boot realtime clock.
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
#include "boot/boot.hpp"
#include "core/time.hpp"
#include "firmware/rtc.hpp"

namespace ax {
namespace {
uint64_t epoch_ticks, initial_ticks;
ClockTimezone timezone;
bool timezone_set;

uint8_t rtc_register(uint8_t reg, void*) {
    out8(0x70, reg);
    return in8(0x71);
}
} // namespace

void clock_realtime_init() {
    int64_t seconds = 0;
    if (Rtc::read(rtc_register, nullptr, seconds)) {
        epoch_ticks = uint64_t(seconds) * 100;
        initial_ticks = ticks;
        log("Clock: RTC UTC seconds=%u\n", uint64_t(seconds));
    } else
        log("Clock: RTC unavailable, calendar time unavailable\n");
}

uint64_t clock_realtime_ticks() {
    uint64_t elapsed = ticks >= initial_ticks ? ticks - initial_ticks : 0;
    return elapsed > UINT64_MAX - epoch_ticks ? UINT64_MAX : epoch_ticks + elapsed;
}

ClockTimezone clock_timezone() {
    return timezone;
}

int clock_update_realtime(const uint64_t* new_time, const ClockTimezone* new_timezone) {
    clock_refresh();
    if (new_time && *new_time < ticks)
        return -22;
    if (new_time) {
        epoch_ticks = *new_time;
        initial_ticks = ticks;
    }
    if (new_timezone) {
        // The legacy timezone-only request can convert a CMOS clock kept in
        // local time to UTC on the first call.
        if (!timezone_set && !new_time) {
            const auto now = clock_realtime_ticks();
            const auto delta = int64_t(new_timezone->minutes_west) * 60 * 100;
            if (delta >= 0 && uint64_t(delta) <= UINT64_MAX - now) {
                epoch_ticks = now + uint64_t(delta);
                initial_ticks = ticks;
            } else if (delta < 0 && uint64_t(-delta) <= now - min(now, ticks)) {
                epoch_ticks = now - uint64_t(-delta);
                initial_ticks = ticks;
            }
        }
        timezone = *new_timezone;
        timezone_set = true;
    }
    return 0;
}
} // namespace ax
