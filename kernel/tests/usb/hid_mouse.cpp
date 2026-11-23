// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/usb/hid_mouse.cpp
 * @brief   Verify HID mouse report layouts and wheel input.
 * @author  frankischilling
 * @date    2026-11-22
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
#include "drivers/usb/hid_mouse.hpp"

#include <cassert>

int main() {
    const uint8_t descriptor[] =
        {
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x04, // Mouse, report 4.
            0x09, 0x01, 0xa1, 0x00,                         // Pointer.
            0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, // Buttons 1–3.
            0x25, 0x01, 0x75, 0x01, 0x95, 0x03, 0x81, 0x02, 0x75,
            0x05, 0x95, 0x01, 0x81, 0x03,       // Padding.
            0x05, 0x01, 0x09, 0x30, 0x09, 0x31, // Relative X and Y.
            0x16, 0x01, 0x80, 0x26, 0xff, 0x7f, 0x75, 0x10, 0x95,
            0x02, 0x81, 0x06, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, // Relative wheel.
            0x75, 0x08, 0x95, 0x01, 0x81, 0x06, 0xc0, 0xc0, 0x05,
            0x0c, 0x09, 0x01, 0xa1, 0x01, 0x85, 0x05, // Separate consumer report.
            0x09, 0xe9, 0x81, 0x02, 0xc0,
        };
    ax::HidMouseLayout layout{};
    assert(ax::hid_mouse_layout(descriptor, sizeof(descriptor), layout));
    assert(layout.report_id == 4 && layout.bytes == 7 && layout.wheel.bit == 48);
    uint8_t input[] = {4, 5, 0x34, 0x12, 0xd4, 0xfe, 0xfe};
    ax::HidMouseReport report{};
    assert(ax::hid_mouse_report(layout, input, sizeof(input), report));
    assert(report.buttons == 5 && report.x == 4660 && report.y == -300 && report.wheel == -2);
    input[6] = 1;
    assert(ax::hid_mouse_report(layout, input, sizeof(input), report) && report.wheel == 1);
    input[0] = 5;
    assert(!ax::hid_mouse_report(layout, input, sizeof(input), report));
    input[0] = 4;
    assert(!ax::hid_mouse_report(layout, input, sizeof(input) - 1, report));
    assert(!ax::hid_mouse_layout(descriptor, sizeof(descriptor) - 1, layout));
    assert(!ax::hid_mouse_layout(nullptr, 0, layout));
}
