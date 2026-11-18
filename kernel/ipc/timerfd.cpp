// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/timerfd.hpp"
#include "core/time.hpp"
#include "fs/vfs.hpp"

namespace ax {
struct Timerfd {
    TimerClock clock;
    bool absolute_realtime;
    bool expired;
    uint64_t deadline, interval, pending, notification;

    uint64_t now() const {
        constexpr uint64_t tick_ns = 10000000;
        uint64_t current = absolute_realtime ? clock_realtime_ticks() : ticks;
        return current > INT64_MAX / tick_ns ? INT64_MAX : current * tick_ns;
    }

    void accrue(uint64_t current) {
        if (deadline && !expired && current >= deadline) {
            expired = true;
            pending += pending != UINT64_MAX;
            notification++;
        }
    }

    void advance(uint64_t current) {
        accrue(current);
        if (!expired)
            return;
        expired = false;
        if (!interval) {
            deadline = 0;
            return;
        }
        uint64_t elapsed = current - deadline;
        pending += min(elapsed / interval, UINT64_MAX - pending);
        uint64_t last = current - elapsed % interval;
        deadline = last + interval <= INT64_MAX ? last + interval : 0;
    }
};

Handle* open_timerfd(TimerClock clock, bool nonblocking, int& error) {
    error = -12;
    auto timer = static_cast<Timerfd*>(alloc(sizeof(Timerfd)));
    if (!timer)
        return nullptr;
    *timer = {};
    timer->clock = clock;
    auto handle = open_handle(nullptr, 2 | (nonblocking ? 04000 : 0), &error);
    if (!handle) {
        release(timer);
        return nullptr;
    }
    handle->timer = timer;
    return handle;
}

void close_timerfd(Timerfd* timer) {
    release(timer);
}

bool timerfd_ready(Timerfd& timer) {
    timer.accrue(timer.now());
    return timer.pending;
}

uint64_t timerfd_notification(const Timerfd& timer) {
    return timer.notification;
}

int64_t timerfd_read(Timerfd& timer, void* output, size_t length) {
    if (length < sizeof(uint64_t))
        return -22;
    timer.advance(timer.now());
    if (!timer.pending)
        return -11;
    memcpy(output, &timer.pending, sizeof(timer.pending));
    timer.pending = 0;
    return sizeof(uint64_t);
}

void timerfd_set_ticks(Timerfd& timer, uint64_t count) {
    timer.accrue(timer.now());
    timer.pending = count;
    timer.notification++;
}

TimerfdSetting timerfd_get(Timerfd& timer) {
    uint64_t current = timer.now();
    timer.advance(current);
    return {timer.interval, timer.deadline > current ? timer.deadline - current : 0};
}

TimerfdSetting timerfd_set(Timerfd& timer, TimerfdSetting next, bool absolute) {
    TimerfdSetting old = timerfd_get(timer);
    timer.absolute_realtime = absolute && timer.clock == TimerClock::realtime;
    timer.interval = next.interval;
    timer.pending = 0;
    timer.deadline = next.value;
    if (next.value && !absolute)
        timer.deadline = min(timer.now() + next.value, uint64_t(INT64_MAX));
    return old;
}
} // namespace ax
