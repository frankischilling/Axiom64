// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/tcp/wire.hpp"

namespace ax::tcp {
// Compact completed sequence space. No application bytes or input pointers remain.
struct TimeWait {
    uint32_t send = 0, receive = 0;
    uint16_t window = 0;
    uint64_t deadline = 0;
};

enum class TimeWaitAction { ignore, acknowledge, remove };

// Input is checksum-validated. Only a duplicate FIN restarts this endpoint's deadline.
TimeWaitAction time_wait_input(TimeWait&, const Segment&, uint64_t now);
} // namespace ax::tcp
