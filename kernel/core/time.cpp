// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/core/time.cpp
 * @brief   Kernel elapsed and realtime clocks.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Converts elapsed counter values to kernel time and exposes the clock values
 * used by timer consumers.
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
#include "core/time.hpp"

namespace ax::Clock {
bool Counter::reset(uint64_t initial, uint64_t n, uint64_t d) {
    if (!n || !d || n > 100000000 || d > 10000000000000ull || n > d)
        return false;
    last = initial;
    numerator = n;
    denominator = d;
    fraction = elapsed = 0;
    return true;
}

uint64_t Counter::sample(uint64_t reading) {
    if (!denominator)
        return elapsed;
    uint64_t delta = reading - last;
    // Small unsigned differences admit wrap. Large differences are ambiguous/backward.
    if (delta > INT64_MAX)
        return elapsed;
    last = reading;
    uint64_t whole;
    if (delta <= (UINT64_MAX - fraction) / numerator) {
        uint64_t scaled = delta * numerator + fraction;
        whole = scaled / denominator;
        fraction = scaled % denominator;
    } else {
        // Rare large gaps: quotient first, then multiply the remainder in <=27 steps.
        uint64_t quotient = delta / denominator;
        if (quotient > UINT64_MAX / numerator)
            return elapsed = UINT64_MAX;
        whole = quotient * numerator;
        uint64_t part = delta % denominator, carry = 0, rest = 0;
        for (uint64_t factor = numerator; factor; factor >>= 1) {
            if (factor & 1) {
                whole += carry;
                rest += part;
                if (rest >= denominator) {
                    rest -= denominator;
                    whole++;
                }
            }
            carry *= 2;
            part *= 2;
            if (part >= denominator) {
                part -= denominator;
                carry++;
            }
        }
        rest += fraction;
        whole += rest / denominator;
        fraction = rest % denominator;
    }
    elapsed = whole > UINT64_MAX - elapsed ? UINT64_MAX : elapsed + whole;
    return elapsed;
}
} // namespace ax::Clock
