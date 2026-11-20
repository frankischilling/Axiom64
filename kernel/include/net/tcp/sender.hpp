// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/tcp/sender.hpp
 * @brief   TCP send state interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines send-queue, window, and retransmission state and declares operations
 * that advance it.
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
#pragma once
#include <cstdint>

namespace ax::tcp {
// Millisecond RTT/RTO policy, with a 10 ms clock granularity and Karn filtering.
class Retransmission {
  public:
    uint32_t interval() const {
        return timeout_ms;
    }

    void sample(uint32_t milliseconds, bool retransmitted);
    void backoff();
    void established(bool syn_retransmitted);

  private:
    uint64_t smoothed8 = 0, variation4 = 0;
    uint32_t timeout_ms = 1000;
    bool measured = false;
};

// Byte-based Reno policy. Call only after sequence/ACK/window validation.
class Congestion {
  public:
    explicit Congestion(uint32_t maximum_segment = 536);

    uint32_t window() const {
        return congestion_window;
    }

    uint32_t threshold() const {
        return slow_start_threshold;
    }

    bool recovery() const {
        return recovering;
    }

    void acknowledged(uint32_t bytes);
    bool duplicate(uint32_t flight); // True requests fast retransmission of the oldest data.
    void timeout(uint32_t flight, bool repeated = false);
    void established(bool syn_retransmitted);
    void idle();
    // Preserve congestion and recovery state when the path changes packet size.
    void segment_size(uint32_t maximum_segment);

  private:
    uint32_t mss, initial_window, congestion_window, slow_start_threshold = 1u << 30;
    uint64_t avoidance_bytes = 0;
    unsigned duplicates = 0;
    bool recovering = false;
    void loss_threshold(uint32_t flight);
};
} // namespace ax::tcp
