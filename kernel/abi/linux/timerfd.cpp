// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/timerfd.hpp"
#include "fs/descriptor.hpp"
#include "ipc/timerfd.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr uint64_t nanoseconds_per_second = 1000000000;
constexpr uint32_t set_ticks_request = 0x40085400;

struct Timespec {
    int64_t seconds, nanoseconds;

    bool valid() const {
        return seconds >= 0 && nanoseconds >= 0 && nanoseconds < int64_t(nanoseconds_per_second);
    }

    uint64_t to_nanoseconds() const {
        uint64_t available = INT64_MAX - nanoseconds;
        return uint64_t(seconds) > available / nanoseconds_per_second
                   ? INT64_MAX
                   : uint64_t(seconds) * nanoseconds_per_second + nanoseconds;
    }

    static Timespec from_nanoseconds(uint64_t time) {
        return {int64_t(time / nanoseconds_per_second), int64_t(time % nanoseconds_per_second)};
    }
};

struct Itimerspec {
    Timespec interval, value;
};

int64_t create(TimerClock clock, uint32_t flags) {
    if (flags & ~uint32_t(04000 | 02000000))
        return -22;
    if (int(clock) == 8 || int(clock) == 9)
        return -1;
    if (clock != TimerClock::realtime && clock != TimerClock::monotonic &&
        clock != TimerClock::boottime)
        return -22;
    int fd = reserve_fd(*current, 0, flags & 02000000);
    if (fd < 0)
        return fd;
    int error;
    auto handle = open_timerfd(clock, flags & 04000, error);
    if (!handle) {
        discard_reserved_fd(*current->files, fd);
        return error;
    }
    install_reserved_fd(*current->files, fd, handle);
    return fd;
}

int copy_setting(uint64_t pointer, TimerfdSetting setting) {
    Itimerspec value{Timespec::from_nanoseconds(setting.interval),
                     Timespec::from_nanoseconds(setting.value)};
    return current->memory->space.copy_out(pointer, &value, sizeof(value)) ? 0 : -14;
}
} // namespace

int64_t timerfd_syscall(const Frame& frame) {
    if (frame.rax == 283)
        return create(TimerClock(int(frame.rdi)), uint32_t(frame.rsi));

    bool setting = frame.rax == 286;
    uint32_t flags = frame.rsi;
    Itimerspec input;
    if (setting) {
        if (!current->memory->space.copy_in(&input, frame.rdx, sizeof(input)))
            return -14;
        if (flags & ~uint32_t(3) || !input.interval.valid() || !input.value.valid())
            return -22;
    }

    unsigned fd = unsigned(frame.rdi);
    auto handle = fd < max_fds ? current->files->entries[fd].handle : nullptr;
    if (!handle)
        return -9;
    if (!handle->timer)
        return -22;
    auto& timer = *handle->timer;
    if (!setting)
        return copy_setting(frame.rsi, timerfd_get(timer));

    // The RTC-derived wall clock has a fixed offset. No supported syscall steps it.
    TimerfdSetting next{input.interval.to_nanoseconds(), input.value.to_nanoseconds()};
    TimerfdSetting old = timerfd_set(timer, next, flags & 1);
    return frame.r10 ? copy_setting(frame.r10, old) : 0;
}

int64_t timerfd_ioctl(Timerfd& timer, uint32_t request, uint64_t argument) {
    if (request != set_ticks_request)
        return -25;
    uint64_t count;
    if (!current->memory->space.copy_in(&count, argument, sizeof(count)))
        return -14;
    if (!count)
        return -22;
    timerfd_set_ticks(timer, count);
    return 0;
}
} // namespace ax
