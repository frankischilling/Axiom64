// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax::Rtc {
struct Fields {
    uint8_t second, minute, hour, day, month, year, century, control;
};

using Reader = uint8_t (*)(uint8_t reg, void* context);
constexpr unsigned attempts = 8, update_polls = 2048;
constexpr int64_t maximum_seconds = 253402300799;

// The PC century register is 0x32. Without it, the two-digit window is 1970–2069.
bool decode(const Fields&, int64_t& seconds);
// Two matching complete snapshots, valid battery state, and bounded UIP retries.
bool read(Reader, void* context, int64_t& seconds);
} // namespace ax::Rtc
