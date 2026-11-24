// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/input/touchpad.cpp
 * @brief   Assembles HID touch reports into Linux type-B multitouch frames.
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
#include "drivers/input/touchpad.hpp"
#include "core/base.hpp"

namespace ax::TouchpadInput {
namespace {
InputEvent event(Time time, EventClock clock, uint16_t type, uint16_t code, int32_t value) {
    const uint64_t ticks = clock == EventClock::realtime ? time.realtime : time.monotonic;
    return {int64_t(ticks / 100), int64_t(ticks % 100) * 10000, type, code, value};
}

void axis_bounds(Axis& axis, const HidTouchpad::Field& field, bool first) {
    if (first) {
        axis = {field.minimum, field.minimum, field.maximum, 0, 0, field.resolution};
    } else {
        axis.minimum = min(axis.minimum, field.minimum);
        axis.maximum = max(axis.maximum, field.maximum);
        if (axis.resolution != field.resolution)
            axis.resolution = 0;
    }
}
} // namespace

bool State::configure(const HidTouchpad::Layouts& layouts) {
    if (slot_limit || !layouts.count || layouts.count > HidTouchpad::max_reports)
        return false;
    Axis x{}, y{};
    unsigned limit = 0;
    bool has_button = false, first = true;
    for (unsigned i = 0; i < layouts.count; ++i) {
        const auto& info = layouts.reports[i];
        if (!info.finger_count || info.finger_count > max_slots)
            return false;
        limit = max(limit, unsigned(info.finger_count));
        if (info.contact_count.width && info.contact_count.maximum > 0)
            limit = max(limit, min(max_slots, unsigned(info.contact_count.maximum)));
        has_button |= info.button.width != 0;
        for (unsigned j = 0; j < info.finger_count; ++j) {
            const auto& finger = info.fingers[j];
            if (finger.x.maximum <= finger.x.minimum || finger.y.maximum <= finger.y.minimum)
                return false;
            axis_bounds(x, finger.x, first);
            axis_bounds(y, finger.y, first);
            first = false;
        }
    }
    x_axis = x;
    y_axis = y;
    button_defined = has_button;
    slot_limit = int32_t(limit);
    return true;
}

void State::emit(Time time, uint16_t type, uint16_t code, int32_t value) {
    events[sequence++ % queue_size] = {time, type, code, value};
}

void State::select(Time time, unsigned slot) {
    if (selected != int32_t(slot)) {
        selected = int32_t(slot);
        emit(time, absolute, mt_slot, selected);
    }
}

bool State::apply(const HidTouchpad::Finger* incoming, unsigned count, bool pressed, Time time) {
    const HidTouchpad::Finger* active[max_slots]{};
    unsigned contacts = 0;
    for (unsigned i = 0; i < count; ++i) {
        const auto& finger = incoming[i];
        if (!finger.touching)
            continue;
        if (finger.x < x_axis.minimum || finger.x > x_axis.maximum || finger.y < y_axis.minimum ||
            finger.y > y_axis.maximum)
            return false;
        for (unsigned j = 0; j < contacts; ++j)
            if (active[j]->id == finger.id)
                return false;
        active[contacts++] = &finger;
    }
    if (contacts > capacity())
        return false;

    const uint64_t start = sequence;
    if (bool(down) != bool(contacts))
        emit(time, key, btn_touch, bool(contacts));
    const unsigned old_tool = min(down, finger_key_limit),
                   new_tool = min(contacts, finger_key_limit);
    if (old_tool != new_tool) {
        if (old_tool)
            emit(time, key, finger_keys[old_tool], 0);
        if (new_tool)
            emit(time, key, finger_keys[new_tool], 1);
    }
    down = contacts;
    if (button_defined && button != pressed) {
        button = pressed;
        emit(time, key, btn_left, button);
    }

    const HidTouchpad::Finger* assigned[max_slots]{};
    for (unsigned i = 0; i < capacity(); ++i) {
        if (!slots[i].occupied)
            continue;
        for (unsigned j = 0; j < contacts; ++j)
            if (active[j] && active[j]->id == slots[i].hardware_id) {
                assigned[i] = active[j];
                active[j] = nullptr;
                break;
            }
        if (!assigned[i]) {
            select(time, i);
            emit(time, absolute, mt_id, -1);
            slots[i].occupied = false;
        }
    }
    unsigned next = 0;
    const Slot* primary = nullptr;
    for (unsigned i = 0; i < capacity(); ++i) {
        auto& slot = slots[i];
        if (!assigned[i] && !slot.occupied) {
            while (next < contacts && !active[next])
                ++next;
            if (next != contacts)
                assigned[i] = active[next++];
        }
        if (!assigned[i])
            continue;
        const auto& finger = *assigned[i];
        const bool fresh = !slot.occupied;
        const int32_t tool = finger.confident ? 0 : 2; // MT_TOOL_FINGER or MT_TOOL_PALM.
        if (fresh) {
            slot.occupied = true;
            slot.hardware_id = finger.id;
            slot.created = ++serial;
            do {
                slot.tracking = int32_t(serial++ & 0xffff);
                bool collision = false;
                for (const auto& other : slots)
                    collision |=
                        &other != &slot && other.occupied && slot.tracking == other.tracking;
                if (!collision)
                    break;
            } while (true);
            select(time, i);
            emit(time, absolute, mt_id, slot.tracking);
        }
        if (fresh || slot.tool != tool) {
            select(time, i);
            emit(time, absolute, mt_tool, tool);
            slot.tool = tool;
        }
        if (fresh || slot.x != finger.x) {
            select(time, i);
            emit(time, absolute, mt_x, finger.x);
            slot.x = finger.x;
        }
        if (fresh || slot.y != finger.y) {
            select(time, i);
            emit(time, absolute, mt_y, finger.y);
            slot.y = finger.y;
        }
        if (finger.confident && (!primary || slot.created < primary->created))
            primary = &slot;
    }
    if (primary && x_axis.value != primary->x) {
        x_axis.value = primary->x;
        emit(time, absolute, abs_x, primary->x);
    }
    if (primary && y_axis.value != primary->y) {
        y_axis.value = primary->y;
        emit(time, absolute, abs_y, primary->y);
    }
    if (sequence != start)
        emit(time, sync, report, 0);
    return true;
}

bool State::submit(const HidTouchpad::Frame& frame, Time time) {
    if (!slot_limit || frame.slots > max_slots)
        return false;
    if (!frame.has_contact_count) {
        pending = {};
        return apply(frame.fingers, frame.slots, frame.button, time);
    }
    if (frame.contact_count) {
        pending = {};
        if (frame.contact_count > capacity() || !frame.slots)
            return false;
        pending.expected = frame.contact_count;
        pending.report_id = frame.report_id;
        pending.button = frame.button;
    } else if (!pending.expected) {
        return apply(nullptr, 0, frame.button, time);
    } else if (frame.report_id != pending.report_id || !frame.slots) {
        pending = {};
        return false;
    }
    const unsigned received = min(frame.slots, pending.expected - pending.used);
    for (unsigned i = 0; i < received; ++i)
        pending.fingers[pending.used++] = frame.fingers[i];
    if (pending.used != pending.expected)
        return true;
    const bool valid = apply(pending.fingers, pending.used, pending.button, time);
    pending = {};
    return valid;
}

void State::reset(Time time) {
    pending = {};
    apply(nullptr, 0, false, time);
}

bool State::key_down(uint16_t code) const {
    if (code == btn_touch)
        return down != 0;
    if (code == btn_left)
        return button;
    return down && code == finger_keys[min(down, finger_key_limit)];
}

bool State::axis(uint16_t code, Axis& out) const {
    if (!slot_limit)
        return false;
    const auto& slot = slots[selected];
    switch (code) {
    case abs_x:
        out = x_axis;
        return true;
    case abs_y:
        out = y_axis;
        return true;
    case mt_slot:
        out = {selected, 0, slot_limit - 1, 0, 0, 0};
        return true;
    case mt_x:
        out = x_axis;
        out.value = slot.x;
        return true;
    case mt_y:
        out = y_axis;
        out.value = slot.y;
        return true;
    case mt_tool:
        out = {slot.tool, 0, 2, 0, 0, 0};
        return true;
    case mt_id:
        out = {slot.occupied ? slot.tracking : -1, 0, 0xffff, 0, 0, 0};
        return true;
    default:
        return false;
    }
}

bool State::slot_values(uint16_t code, int32_t* out, unsigned count) const {
    if (count > capacity())
        return false;
    switch (code) {
    case mt_id:
        for (unsigned i = 0; i < count; ++i)
            out[i] = slots[i].occupied ? slots[i].tracking : -1;
        return true;
    case mt_x:
    case mt_y:
    case mt_tool:
        for (unsigned i = 0; i < count; ++i) {
            const auto& slot = slots[i];
            out[i] = code == mt_x ? slot.x : code == mt_y ? slot.y : slot.tool;
        }
        return true;
    default:
        return false;
    }
}

void State::discard_pending(uint64_t& cursor, uint8_t& recovery) const {
    if (cursor != sequence || recovery) {
        cursor = sequence;
        recovery = 2;
    }
}

int64_t State::read(uint64_t& cursor, uint8_t& recovery, EventClock clock, void* buffer,
                    size_t length, Time now) const {
    const auto capacity = length / sizeof(InputEvent);
    if (!capacity)
        return -22;
    if (sequence - cursor > queue_size)
        discard_pending(cursor, recovery);
    auto* output = static_cast<InputEvent*>(buffer);
    size_t count = 0;
    while (count < capacity && recovery) {
        output[count++] = event(now, clock, sync, recovery == 2 ? dropped : report, 0);
        --recovery;
    }
    while (count < capacity && cursor != sequence) {
        const auto& record = events[cursor++ % queue_size];
        output[count++] = event(record.time, clock, record.type, record.code, record.value);
    }
    return count ? int64_t(count * sizeof(InputEvent)) : -11;
}
} // namespace ax::TouchpadInput
