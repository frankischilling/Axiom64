// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/usb/hid_keyboard.cpp
 * @brief   Read modifier and key-array fields from a HID report descriptor.
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

namespace ax {
bool hid_keyboard_layout(const uint8_t* descriptor, size_t length, HidKeyboardLayout& out) {
    unsigned depth = 0, page = 0, size = 0, count = 0, id = 0, bits = 0;
    unsigned usage = 0, minimum = 0, maximum = 0;
    bool keyboard = false, modifiers = false, matched = false;
    bool other_input_ids[256]{};
    HidKeyboardLayout layout{};
    for (size_t offset = 0; offset < length;) {
        const auto prefix = descriptor[offset++];
        unsigned width = prefix & 3;
        if (width == 3)
            width = 4;
        if (prefix == 0xfe || width > length - offset)
            return false;
        uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value |= uint32_t(descriptor[offset++]) << (8 * i);
        switch (prefix & 0xfc) {
        case 0x04:
            page = value;
            break; // Usage Page
        case 0x74:
            size = value;
            break; // Report Size
        case 0x84:
            if (!value || value > 255 || (keyboard && bits))
                return false;
            id = value;
            break;
        case 0x94:
            count = value;
            break; // Report Count
        case 0xa4: // Global Push
        case 0xb4: // Global Pop
            return false;
        case 0x08:
            usage = value;
            break; // Usage
        case 0x18:
            minimum = value;
            break; // Usage Minimum
        case 0x28:
            maximum = value;
            break; // Usage Maximum
        case 0xa0:
            if (!depth && page == 1 && usage == 6 && value == 1) {
                if (matched)
                    return false;
                keyboard = true;
                bits = 0;
            }
            ++depth;
            break;
        case 0xc0:
            if (!depth)
                return false;
            if (--depth == 0 && keyboard) {
                if (!modifiers || !layout.key_count || bits % 8 || other_input_ids[id])
                    return false;
                layout.report_id = id;
                layout.bytes = bits / 8 + unsigned(id != 0);
                matched = true;
                keyboard = false;
            }
            break;
        case 0x80:
            if (keyboard) {
                if (!size || size > 128 || !count || count > 128 || size * count > 512 - bits)
                    return false;
                const unsigned byte = bits / 8 + unsigned(id != 0);
                if (value & 1) {
                    // Constant input fields change the offset only.
                } else if (page == 7 && bits % 8 == 0 && size == 1 && count == 8 &&
                           minimum == 224 && maximum == 231 && value == 2 && !modifiers) {
                    modifiers = true;
                    layout.modifiers = byte;
                } else if (page == 7 && bits % 8 == 0 && size == 8 &&
                           count <= max_hid_keyboard_keys && value == 0 && !layout.key_count) {
                    layout.keys = byte;
                    layout.key_count = count;
                } else {
                    return false;
                }
                bits += size * count;
            } else {
                if (matched && id == layout.report_id)
                    return false;
                other_input_ids[id] = true;
            }
            break;
        }
        if ((prefix & 0x0c) == 0) // Main items clear the local state.
            usage = minimum = maximum = 0;
    }
    if (depth || !matched)
        return false;
    out = layout;
    return true;
}
} // namespace ax
