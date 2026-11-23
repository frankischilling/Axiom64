// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/usb/hid_mouse.cpp
 * @brief   Decode relative mouse controls from USB HID reports.
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

namespace ax {
namespace {
constexpr unsigned mouse_usage = 0x10002, x_usage = 0x10030, y_usage = 0x10031;
constexpr unsigned wheel_usage = 0x10038, first_button_usage = 0x90001;
constexpr unsigned max_report_bits = 1024 * 8;

struct Format {
    unsigned page, size, count, id;
    bool is_signed;
};

struct Usages {
    unsigned list[32], count;
    unsigned minimum, maximum;
    bool has_minimum, has_maximum;

    unsigned at(unsigned index) const {
        if (count)
            return list[index < count ? index : count - 1];
        if (has_minimum && has_maximum && maximum >= minimum && index <= maximum - minimum)
            return minimum + index;
        return 0;
    }
};

int read_field(const uint8_t* bytes, HidMouseField field, bool is_signed) {
    if (!field.size)
        return 0;
    uint32_t value = 0;
    for (unsigned i = 0; i < field.size; ++i) {
        const unsigned bit = field.bit + i;
        value |= uint32_t((bytes[bit / 8] >> (bit % 8)) & 1) << i;
    }
    if (is_signed) {
        const uint32_t sign = uint32_t(1) << (field.size - 1);
        return int32_t((value ^ sign) - sign);
    }
    return value;
}
} // namespace

bool hid_mouse_layout(const uint8_t* descriptor, size_t length, HidMouseLayout& result) {
    if (!descriptor || !length || length > 512)
        return false;
    Format format{}, stack[8]{};
    Usages usages{};
    unsigned bits[256]{};
    bool saw_id = false;
    HidMouseLayout layout{};
    bool mouse = false, seen_mouse = false, seen_field = false;
    unsigned pushed = 0, depth = 0;
    for (size_t offset = 0; offset < length;) {
        const auto prefix = descriptor[offset++];
        const unsigned width = (prefix & 3) == 3 ? 4 : prefix & 3;
        if (prefix == 0xfe || width > length - offset)
            return false;
        uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value |= uint32_t(descriptor[offset++]) << (8 * i);
        const unsigned usage = width == 4 ? value : (format.page << 16) | value;
        switch (prefix & 0xfc) {
        case 0x04: // Usage Page
            if (value > UINT16_MAX)
                return false;
            format.page = value;
            break;
        case 0x14: // Logical Minimum
            format.is_signed = width && (value & (uint32_t(1) << (width * 8 - 1)));
            break;
        case 0x74: // Report Size
            format.size = value;
            break;
        case 0x84: // Report ID
            if (!value || value > UINT8_MAX || bits[0])
                return false;
            format.id = value;
            saw_id = true;
            break;
        case 0x94: // Report Count
            format.count = value;
            break;
        case 0xa4: // Push
            if (pushed == sizeof(stack) / sizeof(*stack))
                return false;
            stack[pushed++] = format;
            break;
        case 0xb4: // Pop
            if (!pushed)
                return false;
            format = stack[--pushed];
            break;
        case 0x08: // Usage
            if (usages.count == sizeof(usages.list) / sizeof(*usages.list))
                return false;
            usages.list[usages.count++] = usage;
            break;
        case 0x18: // Usage Minimum
            usages.minimum = usage;
            usages.has_minimum = true;
            break;
        case 0x28: // Usage Maximum
            usages.maximum = usage;
            usages.has_maximum = true;
            break;
        case 0xa0: // Collection
            if (!depth && usages.at(0) == mouse_usage && value == 1) {
                if (seen_mouse)
                    return false;
                mouse = seen_mouse = true;
            }
            ++depth;
            break;
        case 0xc0: // End Collection
            if (!depth)
                return false;
            if (!--depth)
                mouse = false;
            break;
        case 0x80: { // Input
            if (!depth || (saw_id && !format.id) || !format.size || !format.count ||
                format.count > (max_report_bits - bits[format.id]) / format.size)
                return false;
            if (mouse && (value & 3) == 2) {
                for (unsigned index = 0; index < format.count; ++index) {
                    const auto field_usage = usages.at(index);
                    HidMouseField* field = nullptr;
                    if ((value & 4) && format.is_signed) {
                        if (field_usage == x_usage)
                            field = &layout.x;
                        else if (field_usage == y_usage)
                            field = &layout.y;
                        else if (field_usage == wheel_usage)
                            field = &layout.wheel;
                    } else if (!(value & 4) && format.size == 1 &&
                               field_usage >= first_button_usage &&
                               field_usage < first_button_usage + 3) {
                        field = &layout.buttons[field_usage - first_button_usage];
                    }
                    if (!field)
                        continue;
                    if (field->size || format.size > 32 ||
                        (seen_field && layout.report_id != format.id))
                        return false;
                    *field = {bits[format.id] + index * format.size + (format.id ? 8 : 0),
                              format.size};
                    layout.report_id = format.id;
                    seen_field = true;
                }
            }
            bits[format.id] += format.count * format.size;
            break;
        }
        }
        if (!(prefix & 0x0c))
            usages = {};
    }
    if (depth || pushed || !layout.x.size || !layout.y.size)
        return false;
    layout.bytes = (bits[layout.report_id] + 7) / 8 + (layout.report_id ? 1 : 0);
    result = layout;
    return true;
}

bool hid_mouse_report(const HidMouseLayout& layout, const uint8_t* bytes, size_t length,
                      HidMouseReport& report) {
    if (!bytes || !length || length != layout.bytes ||
        (layout.report_id && bytes[0] != layout.report_id))
        return false;
    report = {read_field(bytes, layout.x, true), read_field(bytes, layout.y, true),
              read_field(bytes, layout.wheel, true), 0};
    for (unsigned button = 0; button < 3; ++button)
        report.buttons |= uint8_t(read_field(bytes, layout.buttons[button], false) << button);
    return true;
}
} // namespace ax
