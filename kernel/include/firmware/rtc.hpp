// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/firmware/rtc.hpp
 * @brief   Firmware real-time clock interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines calendar time data and declares helpers that interpret firmware clock
 * readings.
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
