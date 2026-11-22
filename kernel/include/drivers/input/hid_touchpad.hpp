// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/input/hid_touchpad.hpp
 * @brief   Describes HID touchpad input reports.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Parses HID fields and decodes the length-prefixed input packets used by I²C touchpads.
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
#include <stddef.h>
#include <stdint.h>

namespace ax::HidTouchpad {
constexpr unsigned max_fingers = 10, max_reports = 8;

struct Field {
    uint16_t offset;
    uint8_t width;
    int32_t minimum, maximum;
};

struct FingerLayout {
    Field x, y, id, tip, confidence;
};

struct ReportLayout {
    uint8_t id, finger_count;
    uint16_t bits;
    Field button, contact_count;
    FingerLayout fingers[max_fingers];
};

struct Layouts {
    ReportLayout reports[max_reports];
    unsigned count;
    bool numbered;
};

struct Finger {
    int32_t x, y;
    uint32_t id;
    bool touching, confident;
};

struct Frame {
    Finger fingers[max_fingers];
    unsigned slots, contact_count;
    bool button, has_contact_count;
};

enum class Packet { input, reset, unknown, invalid };

bool parse(const uint8_t* descriptor, size_t length, unsigned max_input_bytes, Layouts&);
Packet decode(const Layouts&, const uint8_t* packet, size_t received, Frame&);
} // namespace ax::HidTouchpad
