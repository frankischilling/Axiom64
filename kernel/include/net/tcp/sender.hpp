// SPDX-License-Identifier: GPL-3.0-or-later
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

  private:
    uint32_t mss, initial_window, congestion_window, slow_start_threshold = 1u << 30;
    uint64_t avoidance_bytes = 0;
    unsigned duplicates = 0;
    bool recovering = false;
    void loss_threshold(uint32_t flight);
};
} // namespace ax::tcp
