// SPDX-License-Identifier: GPL-3.0-or-later
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
