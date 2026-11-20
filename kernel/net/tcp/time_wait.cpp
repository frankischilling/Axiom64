// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/tcp/time_wait.cpp
 * @brief   TCP TIME-WAIT ownership.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Keeps closed connection identity for the interval needed to handle delayed
 * segments.
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
#include "net/tcp/time_wait.hpp"

namespace ax::tcp {
TimeWaitAction time_wait_input(TimeWait& state, const Segment& segment, uint64_t now) {
    if (now >= state.deadline)
        return TimeWaitAction::remove;
    if (segment.length > maximum_segment_size || (segment.length && !segment.payload))
        return TimeWaitAction::ignore;
    if ((segment.flags & fin) && !(segment.flags & rst) &&
        segment.sequence + segment.length + 1 == state.receive) {
        state.deadline = now > UINT64_MAX - 120000 ? UINT64_MAX : now + 120000;
        return TimeWaitAction::acknowledge;
    }
    if (!acceptable(segment.sequence, sequence_length(segment), state.receive, state.window))
        return segment.flags & rst ? TimeWaitAction::ignore : TimeWaitAction::acknowledge;
    if (segment.flags & rst) {
        auto decision = reset(segment.sequence, state.receive, state.window);
        return decision == Reset::accept      ? TimeWaitAction::remove
               : decision == Reset::challenge ? TimeWaitAction::acknowledge
                                              : TimeWaitAction::ignore;
    }
    if (segment.flags & syn)
        return TimeWaitAction::acknowledge;
    if (!(segment.flags & ack))
        return TimeWaitAction::ignore;
    if (before(state.send, segment.acknowledgment) || segment.length || (segment.flags & fin))
        return TimeWaitAction::acknowledge;
    return TimeWaitAction::ignore;
}
} // namespace ax::tcp
