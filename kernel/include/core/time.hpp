// SPDX-License-Identifier: GPL-3.0-or-later
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
// Called with interrupts disabled; timer=true supplies the IRQ-only fallback.
void clock_refresh(bool timer = false);
} // namespace ax
