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
} // namespace ax
