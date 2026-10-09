// SPDX-License-Identifier: GPL-3.0-or-later
#include "io/socket_timeout.hpp"

namespace ax {
struct Timeval {
    int64_t seconds, microseconds;
};

static_assert(sizeof(Timeval) == 16);

bool socket_timeout_syscall(Task& task, const Frame& frame, Handle* handle, int64_t& result) {
    int option = int(frame.rdx);
    bool receive = option == 20 || option == 66;
    if ((frame.rax != 54 && frame.rax != 55) || int(frame.rsi) != 1 ||
        (!receive && option != 21 && option != 67))
        return false;
    if (!handle) {
        result = -9;
        return true;
    }
    if (!handle->socket && !handle->inet && !handle->packet && !handle->netlink) {
        result = -88;
        return true;
    }
    auto& timeout = receive ? handle->receive_timeout : handle->send_timeout;
    if (frame.rax == 54) {
        Timeval value;
        if (int32_t(frame.r8) < int32_t(sizeof(value)))
            result = -22;
        else if (!task.memory->space.copy_in(&value, frame.r10, sizeof(value)))
            result = -14;
        else if (value.microseconds < 0 || value.microseconds >= 1000000)
            result = -33;
        else {
            SocketTimeout next;
            if (value.seconds < 0)
                next.finite = true; // Accepted by Linux as an immediate timeout.
            else if (value.seconds < INT64_MAX / 100 - 1 && (value.seconds || value.microseconds)) {
                next.ticks =
                    uint64_t(value.seconds) * 100 + (uint64_t(value.microseconds) + 9999) / 10000;
                next.finite = true;
            }
            // Zero and durations beyond MAX_SCHEDULE_TIMEOUT select an infinite wait.
            timeout = next;
            result = 0;
        }
    } else {
        int32_t length;
        if (!task.memory->space.copy_in(&length, frame.r8, sizeof(length)))
            result = -14;
        else if (length < 0)
            result = -22;
        else {
            Timeval value{int64_t(timeout.ticks / 100), int64_t(timeout.ticks % 100 * 10000)};
            uint32_t actual = min(uint32_t(length), uint32_t(sizeof(value)));
            result = task.memory->space.copy_out(frame.r10, &value, actual) &&
                             task.memory->space.copy_out(frame.r8, &actual, sizeof(actual))
                         ? 0
                         : -14;
        }
    }
    return true;
}
} // namespace ax
