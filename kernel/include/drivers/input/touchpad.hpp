// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/input/touchpad.hpp
 * @brief   Tracks touchpad contacts for the Linux input interface.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Keeps multitouch slots, contact lifetimes and per-reader event positions.
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
#include "drivers/input/hid_touchpad.hpp"

namespace ax::TouchpadInput {
constexpr uint16_t sync = 0, key = 1, absolute = 3;
constexpr uint16_t report = 0, dropped = 3;
constexpr uint16_t abs_x = 0, abs_y = 1, mt_slot = 0x2f, mt_x = 0x35, mt_y = 0x36;
constexpr uint16_t mt_tool = 0x37, mt_id = 0x39;
constexpr uint16_t btn_left = 0x110, btn_finger = 0x145, btn_five = 0x148, btn_touch = 0x14a;
constexpr uint16_t btn_two = 0x14d, btn_three = 0x14e, btn_four = 0x14f;
constexpr uint16_t finger_keys[]{0, btn_finger, btn_two, btn_three, btn_four, btn_five};
constexpr unsigned finger_key_limit = sizeof(finger_keys) / sizeof(*finger_keys) - 1;
constexpr uint16_t slot_codes[]{mt_id, mt_x, mt_y, mt_tool};
constexpr uint16_t axis_codes[]{abs_x, abs_y, mt_slot, mt_x, mt_y, mt_tool, mt_id};
constexpr unsigned max_slots = HidTouchpad::max_fingers;

struct InputEvent {
    int64_t sec, usec;
    uint16_t type, code;
    int32_t value;
};

struct Time {
    uint64_t monotonic, realtime;
};

struct Axis {
    int32_t value, minimum, maximum, fuzz, flat, resolution;
};

static_assert(sizeof(InputEvent) == 24 && sizeof(Axis) == 24);

enum class EventClock : uint8_t { realtime = 0, monotonic = 1, boottime = 7 };

class State {
    static constexpr unsigned queue_size = 256;

    struct Pending {
        HidTouchpad::Finger fingers[max_slots];
        unsigned expected, used;
        bool button;
        uint8_t report_id;
    };

    struct Slot {
        uint64_t created;
        uint32_t hardware_id;
        int32_t tracking, x, y, tool;
        bool occupied;
    };

    struct Record {
        Time time;
        uint16_t type, code;
        int32_t value;
    };

    Pending pending{};
    Slot slots[max_slots]{};
    Record events[queue_size]{};
    Axis x_axis{}, y_axis{};
    uint64_t sequence = 0, serial = 0;
    int32_t slot_limit = 0, selected = 0;
    unsigned down = 0;
    bool button_defined = false, button = false;

    void emit(Time, uint16_t type, uint16_t code, int32_t value);
    void select(Time, unsigned slot);
    bool apply(const HidTouchpad::Finger*, unsigned count, bool pressed, Time);

  public:
    bool configure(const HidTouchpad::Layouts&);
    bool submit(const HidTouchpad::Frame&, Time);
    void reset(Time);

    uint64_t position() const {
        return sequence;
    }

    unsigned capacity() const {
        return unsigned(slot_limit);
    }

    bool has_button() const {
        return button_defined;
    }

    bool key_down(uint16_t code) const;
    bool axis(uint16_t code, Axis&) const;
    bool slot_values(uint16_t code, int32_t* out, unsigned count) const;

    void discard_pending(uint64_t& cursor, uint8_t& recovery) const;
    int64_t read(uint64_t& cursor, uint8_t& recovery, EventClock, void*, size_t length, Time) const;

    bool ready(uint64_t cursor, uint8_t recovery) const {
        return cursor != sequence || recovery;
    }
};

// Register the transport's input endpoint after a successful HID initialization.
bool register_device(const HidTouchpad::Layouts&, uint16_t vendor, uint16_t product,
                     uint16_t revision, bool clickpad);
bool submit(const HidTouchpad::Frame&);
void reset();
} // namespace ax::TouchpadInput
