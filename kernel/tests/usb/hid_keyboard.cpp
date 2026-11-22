// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/usb/hid_keyboard.cpp
 * @brief   Checks supported HID keyboard layouts and malformed descriptors.
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
#include "drivers/usb/hid_keyboard.hpp"
#include <array>
#include <cassert>
#include <cstdio>

int main() {
    constexpr auto numbered =
        std::to_array<uint8_t>(
            {
                0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, // Keyboard, ID 1
                0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x75, 0x01,
                0x95, 0x08, 0x81, 0x02,                         // Modifier bits
                0x19, 0x00, 0x29, 0xff, 0x75, 0x08, 0x95, 0x0e, // 14 usages
                0x81, 0x00, 0xc0, 0x05, 0x0c, 0x09, 0x01, 0xa1,
                0x01, 0x85, 0x02, // Separate consumer report
                0x75, 0x10, 0x95, 0x01, 0x81, 0x00, 0xc0,
            });
    ax::HidKeyboardLayout layout{};
    assert(ax::hid_keyboard_layout(numbered.data(), numbered.size(), layout));
    assert(layout.report_id == 1 && layout.modifiers == 1 && layout.keys == 2 &&
           layout.key_count == 14 && layout.bytes == 16);
    assert(!ax::hid_keyboard_layout(numbered.data(), numbered.size() - 3, layout));
    assert(!ax::hid_keyboard_layout(numbered.data(), 30, layout));
    auto changed = numbered;
    changed[38] = 1; // Reports with the same ID share an input layout.
    assert(!ax::hid_keyboard_layout(changed.data(), changed.size(), layout));
    changed = numbered;
    changed[8] = 0xfe;
    assert(!ax::hid_keyboard_layout(changed.data(), changed.size(), layout));
    changed = numbered;
    changed[27] = 127;
    assert(!ax::hid_keyboard_layout(changed.data(), changed.size(), layout));
    changed = numbered;
    changed[29] = 2; // A variable field is not a key array.
    assert(!ax::hid_keyboard_layout(changed.data(), changed.size(), layout));
    std::puts("HID_KEYBOARD_PASS numbered-array separate-collection and malformed controls");
}
