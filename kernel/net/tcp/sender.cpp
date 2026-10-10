// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/sender.hpp"

namespace ax::tcp {
namespace {
constexpr uint32_t maximum_window = 1u << 30;

uint32_t minimum(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

uint32_t maximum(uint32_t a, uint32_t b) {
    return a > b ? a : b;
}

uint32_t grow(uint32_t value, uint32_t bytes) {
    return value + minimum(bytes, maximum_window - value);
}
} // namespace

void Retransmission::sample(uint32_t milliseconds, bool retransmitted) {
    if (retransmitted)
        return;
    uint64_t value = milliseconds;
    if (!measured) {
        smoothed8 = value * 8;
        variation4 = value * 2;
        measured = true;
    } else {
        uint64_t previous = smoothed8 / 8;
        uint64_t difference = previous > value ? previous - value : value - previous;
        variation4 = variation4 - variation4 / 4 + difference;
        smoothed8 = smoothed8 - smoothed8 / 8 + value;
    }
    uint64_t variance = variation4 > 10 ? variation4 : 10;
    uint64_t calculated = (smoothed8 + 7) / 8 + variance;
    timeout_ms = calculated > 60000 ? 60000 : calculated < 1000 ? 1000 : calculated;
}

void Retransmission::backoff() {
    timeout_ms = minimum(timeout_ms * 2, 60000);
}

void Retransmission::established(bool syn_retransmitted) {
    if (!measured && syn_retransmitted)
        timeout_ms = maximum(timeout_ms, 3000);
}

Congestion::Congestion(uint32_t maximum_segment) {
    mss = maximum_segment ? minimum(maximum_segment, 65535) : 536;
    initial_window = minimum(4 * mss, maximum(2 * mss, 4380));
    congestion_window = initial_window;
}

void Congestion::loss_threshold(uint32_t flight) {
    slow_start_threshold = minimum(maximum(flight / 2, 2 * mss), maximum_window);
}

void Congestion::acknowledged(uint32_t bytes) {
    duplicates = 0;
    if (!bytes)
        return;
    if (recovering) {
        congestion_window = slow_start_threshold;
        recovering = false;
        avoidance_bytes = 0;
    } else if (congestion_window < slow_start_threshold)
        congestion_window = grow(congestion_window, minimum(bytes, mss));
    else {
        avoidance_bytes += bytes;
        if (avoidance_bytes >= congestion_window) {
            avoidance_bytes %= congestion_window;
            congestion_window = grow(congestion_window, mss);
        }
    }
}

bool Congestion::duplicate(uint32_t flight) {
    if (recovering) {
        congestion_window = grow(congestion_window, mss);
        return false;
    }
    if (++duplicates != 3)
        return false;
    loss_threshold(flight);
    congestion_window = grow(slow_start_threshold, 3 * mss);
    avoidance_bytes = 0;
    recovering = true;
    return true;
}

void Congestion::timeout(uint32_t flight, bool repeated) {
    if (!repeated)
        loss_threshold(flight);
    congestion_window = mss;
    duplicates = 0;
    avoidance_bytes = 0;
    recovering = false;
}

void Congestion::established(bool syn_retransmitted) {
    if (syn_retransmitted)
        congestion_window = mss;
}

void Congestion::idle() {
    congestion_window = minimum(congestion_window, initial_window);
    avoidance_bytes = 0;
    duplicates = 0;
    recovering = false;
}
} // namespace ax::tcp
