// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Handle;
struct Timerfd;

enum class TimerClock { realtime = 0, monotonic = 1, boottime = 7 };

struct TimerfdSetting {
    uint64_t interval, value;
};

Handle* open_timerfd(TimerClock, bool nonblocking, int& error);
void close_timerfd(Timerfd*);
bool timerfd_ready(Timerfd&);
uint64_t timerfd_notification(const Timerfd&);
int64_t timerfd_read(Timerfd&, void*, size_t);
void timerfd_set_ticks(Timerfd&, uint64_t);
TimerfdSetting timerfd_get(Timerfd&);
TimerfdSetting timerfd_set(Timerfd&, TimerfdSetting, bool absolute);
} // namespace ax
