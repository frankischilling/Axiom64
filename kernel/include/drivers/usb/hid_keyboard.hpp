// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/usb/hid_keyboard.hpp
 * @brief   Describes HID keyboard input with a modifier byte and key array.
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
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
constexpr unsigned max_hid_keyboard_keys = 32;

struct HidKeyboardLayout {
    unsigned report_id, modifiers, keys, key_count, bytes;
};

bool hid_keyboard_layout(const uint8_t* descriptor, size_t length, HidKeyboardLayout&);
} // namespace ax
