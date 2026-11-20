// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/time.hpp
 * @brief   Kernel clock types and conversion.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares time measurement, clock conversion, and integer scaling helpers.
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
#include <stdint.h>

namespace ax::Clock {
// Converts a free-running 64-bit counter into 10 ms units without losing fractions.
class Counter {
  public:
    bool reset(uint64_t initial, uint64_t numerator, uint64_t denominator);
    uint64_t sample(uint64_t reading);

  private:
    uint64_t last = 0, numerator = 0, denominator = 0, fraction = 0, elapsed = 0;
};
} // namespace ax::Clock

namespace ax {
extern uint64_t ticks;
void clock_init(uint64_t rsdp);
void clock_realtime_init();
uint64_t clock_realtime_ticks();
// Called with interrupts disabled; timer=true supplies the IRQ-only fallback.
void clock_refresh(bool timer = false);
} // namespace ax
