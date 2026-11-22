// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/input/hid_touchpad.cpp
 * @brief   Decodes HID touchpad descriptors and input packets.
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
#include "drivers/input/hid_touchpad.hpp"

namespace ax::HidTouchpad {
namespace {
constexpr unsigned max_descriptor_bytes = 4096, max_packet_bytes = 4096;
constexpr uint32_t touchpad_usage = 0x000d0005, finger_usage = 0x000d0022;
constexpr uint32_t x_usage = 0x00010030, y_usage = 0x00010031;
constexpr uint32_t button_usage = 0x00090001, tip_usage = 0x000d0042;
constexpr uint32_t confidence_usage = 0x000d0047, contact_id_usage = 0x000d0051;
constexpr uint32_t count_usage = 0x000d0054;

int32_t signed_value(uint32_t value, unsigned bits) {
    const uint32_t sign = uint32_t(1) << (bits - 1);
    return int32_t((value ^ sign) - sign);
}

struct Global {
    uint32_t page, size, count;
    int32_t minimum;
    int64_t maximum;
    int32_t physical_minimum;
    int64_t physical_maximum;
    uint32_t unit;
    int unit_exponent;
    uint8_t id;
};

struct Local {
    struct Range {
        uint32_t first, last;
    };

    Range usages[32];
    unsigned count;
    uint32_t minimum;
    bool pending_minimum;

    bool add(uint32_t first, uint32_t last) {
        if (count == sizeof(usages) / sizeof(*usages) || last < first ||
            (first >> 16) != (last >> 16))
            return false;
        usages[count++] = {first, last};
        return true;
    }

    uint32_t at(unsigned index) const {
        for (unsigned i = 0; i < count; ++i) {
            const auto range = usages[i];
            const unsigned span = range.last - range.first + 1;
            if (index < span)
                return range.first + index;
            index -= span;
        }
        return count ? usages[count - 1].last : 0;
    }
};

struct Collection {
    unsigned finger;
    bool touchpad;
};

struct Parser {
    Layouts& result;
    unsigned input_bits[256]{};
    unsigned fingers[max_reports][max_fingers]{};
    Global globals{}, stack[8]{};
    Local local{};
    Collection scope{}, collections[16]{};
    unsigned pushed = 0, collection_depth = 0, next_finger = 0;
    const unsigned max_input_bits;
    bool saw_report_id = false;

    int32_t axis_resolution() const {
        if (globals.maximum <= globals.minimum ||
            globals.physical_maximum <= globals.physical_minimum)
            return 0;
        uint64_t coordinates = globals.maximum - globals.minimum;
        uint64_t length = globals.physical_maximum - globals.physical_minimum;
        int exponent = globals.unit_exponent;
        if (globals.unit == 0x11) { // Centimeters.
            ++exponent;
        } else if (globals.unit == 0x13) { // Inches.
            length *= 254;
            --exponent;
        } else {
            return 0;
        }
        for (; exponent > 0; --exponent)
            length *= 10;
        for (; exponent < 0; ++exponent)
            coordinates *= 10;
        const uint64_t resolution = (coordinates + length / 2) / length;
        return resolution <= INT32_MAX ? int32_t(resolution) : 0;
    }

    bool global(unsigned tag, uint32_t value, unsigned width) {
        switch (tag) {
        case 0: // Usage Page
            if (value > UINT16_MAX)
                return false;
            globals.page = value;
            break;
        case 1: // Logical Minimum
            globals.minimum = signed_value(value, width * 8);
            break;
        case 2: // Logical Maximum
            globals.maximum =
                globals.minimum < 0 ? int64_t(signed_value(value, width * 8)) : int64_t(value);
            break;
        case 3: // Physical Minimum
            globals.physical_minimum = signed_value(value, width * 8);
            break;
        case 4: // Physical Maximum
            globals.physical_maximum = globals.physical_minimum < 0
                                           ? int64_t(signed_value(value, width * 8))
                                           : int64_t(value);
            break;
        case 5: // Unit Exponent: a signed four-bit value.
            globals.unit_exponent = signed_value(value & 15u, 4);
            break;
        case 6: // Unit
            globals.unit = value;
            break;
        case 7: // Report Size
            globals.size = value;
            break;
        case 8: // Report ID
            if (!value || value > UINT8_MAX)
                return false;
            globals.id = value;
            saw_report_id = true;
            break;
        case 9: // Report Count
            globals.count = value;
            break;
        case 10: // Push
            if (pushed == sizeof(stack) / sizeof(*stack))
                return false;
            stack[pushed++] = globals;
            break;
        case 11: // Pop
            if (!pushed)
                return false;
            globals = stack[--pushed];
            break;
        }
        return true;
    }

    bool local_item(unsigned tag, uint32_t value, unsigned width) {
        const uint32_t usage = width == 4 ? value : (globals.page << 16) | value;
        switch (tag) {
        case 0: // Usage
            return local.add(usage, usage);
        case 1: // Usage Minimum
            if (local.pending_minimum)
                return false;
            local.minimum = usage;
            local.pending_minimum = true;
            return true;
        case 2: // Usage Maximum
            if (!local.pending_minimum)
                return false;
            local.pending_minimum = false;
            return local.add(local.minimum, usage);
        case 10: // Delimiter
            return false;
        default:
            return true;
        }
    }

    ReportLayout* report() {
        unsigned slot = 0;
        while (slot < result.count && result.reports[slot].id != globals.id)
            ++slot;
        if (slot == result.count) {
            if (slot == max_reports)
                return nullptr;
            result.reports[result.count++].id = globals.id;
        }
        return result.reports + slot;
    }

    FingerLayout* finger(ReportLayout& layout) {
        auto& ids = fingers[&layout - result.reports];
        unsigned slot = 0;
        while (slot < layout.finger_count && ids[slot] != scope.finger)
            ++slot;
        if (slot == layout.finger_count) {
            if (slot == max_fingers)
                return nullptr;
            ids[layout.finger_count++] = scope.finger;
        }
        return layout.fingers + slot;
    }

    bool input(unsigned flags) {
        if (!collection_depth || !globals.size || !globals.count)
            return false;
        const auto size = uint64_t(globals.size) * globals.count;
        auto& offset = input_bits[globals.id];
        if (size > max_input_bits - offset)
            return false;
        const unsigned start = offset;
        offset += unsigned(size);
        if (!scope.touchpad || (flags & 7) != 2)
            return true;

        for (unsigned i = 0; i < globals.count; ++i) {
            const auto usage = local.at(i);
            const bool per_finger =
                scope.finger && (usage == x_usage || usage == y_usage || usage == tip_usage ||
                                 usage == contact_id_usage || usage == confidence_usage);
            if (!per_finger && usage != button_usage && usage != count_usage)
                continue;
            if (globals.size > 32 || globals.maximum < globals.minimum ||
                globals.maximum > INT32_MAX)
                return false;
            auto* layout = report();
            if (!layout)
                return false;
            Field* field;
            if (per_finger) {
                auto* contact = finger(*layout);
                if (!contact)
                    return false;
                switch (usage) {
                case x_usage:
                    field = &contact->x;
                    break;
                case y_usage:
                    field = &contact->y;
                    break;
                case contact_id_usage:
                    field = &contact->id;
                    break;
                case tip_usage:
                    field = &contact->tip;
                    break;
                default:
                    field = &contact->confidence;
                    break;
                }
            } else {
                field = usage == button_usage ? &layout->button : &layout->contact_count;
            }
            // Some devices describe a target position and a center position. Use the first axes.
            if (!field->width)
                *field = {uint16_t(start + i * globals.size), uint8_t(globals.size),
                          globals.minimum, int32_t(globals.maximum),
                          (usage == x_usage || usage == y_usage) ? axis_resolution() : 0};
        }
        return true;
    }

    bool main(unsigned tag, uint32_t value) {
        if (local.pending_minimum)
            return false;
        switch (tag) {
        case 8: // Input
            return input(value);
        case 10: // Collection
            if (collection_depth == sizeof(collections) / sizeof(*collections))
                return false;
            collections[collection_depth++] = scope;
            if (value == 1)
                scope = {0, local.at(0) == touchpad_usage};
            else if (scope.touchpad && local.at(0) == finger_usage)
                scope.finger = ++next_finger;
            return true;
        case 12: // End Collection
            if (!collection_depth)
                return false;
            scope = collections[--collection_depth];
            return true;
        default:
            return true;
        }
    }

    bool finish() {
        if (collection_depth || pushed || local.pending_minimum || (saw_report_id && input_bits[0]))
            return false;
        result.numbered = saw_report_id;
        unsigned complete = 0;
        for (unsigned i = 0; i < result.count; ++i) {
            auto& layout = result.reports[i];
            if (!layout.finger_count)
                continue;
            const unsigned bits = input_bits[layout.id];
            if (!bits || bits % 8 || (layout.id && bits + 8 > max_input_bits))
                return false;
            for (unsigned j = 0; j < layout.finger_count; ++j) {
                const auto& finger = layout.fingers[j];
                if (!finger.tip.width || !finger.x.width || !finger.y.width ||
                    finger.x.minimum == finger.x.maximum || finger.y.minimum == finger.y.maximum)
                    return false;
            }
            layout.bits = uint16_t(bits);
            result.reports[complete++] = layout;
        }
        result.count = complete;
        return complete != 0;
    }
};

bool fits(const Field& field, unsigned bits) {
    return !field.width || (field.width <= 32 && unsigned(field.offset) + field.width <= bits);
}

int64_t extract(const uint8_t* payload, Field field) {
    uint32_t value = 0;
    for (unsigned i = 0; i < field.width; ++i) {
        const unsigned bit = field.offset + i;
        value |= uint32_t((payload[bit / 8] >> (bit % 8)) & 1) << i;
    }
    return field.minimum < 0 && field.width ? int64_t(signed_value(value, field.width))
                                            : int64_t(value);
}

bool parse_items(Parser& parser, const uint8_t* descriptor, size_t length) {
    while (length) {
        const unsigned prefix = *descriptor++;
        --length;
        if (prefix == 0xfe) { // A long item carries its size and tag in two separate bytes.
            if (length < 2 || descriptor[0] > length - 2)
                return false;
            const unsigned skip = 2 + descriptor[0];
            descriptor += skip;
            length -= skip;
            continue;
        }
        const unsigned width = (prefix & 3) == 3 ? 4 : prefix & 3;
        if (width > length)
            return false;
        uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value |= uint32_t(*descriptor++) << (8 * i);
        length -= width;
        const unsigned type = (prefix >> 2) & 3, tag = prefix >> 4;
        if (type == 0) {
            if (!parser.main(tag, value))
                return false;
            parser.local = {};
        } else if (type == 1) {
            if (!parser.global(tag, value, width ? width : 1))
                return false;
        } else if (type == 2 && !parser.local_item(tag, value, width)) {
            return false;
        }
    }
    return parser.finish();
}
} // namespace

bool parse(const uint8_t* descriptor, size_t length, unsigned max_input_bytes, Layouts& result) {
    result = {};
    if (!descriptor || !length || length > max_descriptor_bytes || max_input_bytes < 3 ||
        max_input_bytes > max_packet_bytes)
        return false;
    Parser parser{.result = result, .max_input_bits = (max_input_bytes - 2) * 8};
    if (parse_items(parser, descriptor, length))
        return true;
    result = {};
    return false;
}

Packet decode(const Layouts& layouts, const uint8_t* packet, size_t received, Frame& frame) {
    frame = {};
    if (!packet || received < 2 || layouts.count > max_reports)
        return Packet::invalid;
    const unsigned length = unsigned(packet[0]) | unsigned(packet[1]) << 8;
    if (!length)
        return Packet::reset;
    if (length < (layouts.numbered ? 3u : 2u) || length > received)
        return Packet::invalid;
    const uint8_t id = layouts.numbered ? packet[2] : 0;
    const uint8_t* payload = packet + (layouts.numbered ? 3 : 2);
    for (unsigned i = 0; i < layouts.count; ++i) {
        const auto& report = layouts.reports[i];
        if (report.id != id)
            continue;
        if (length - unsigned(payload - packet) != report.bits / 8 || report.bits % 8 ||
            report.finger_count > max_fingers || !fits(report.button, report.bits) ||
            !fits(report.contact_count, report.bits))
            return Packet::invalid;
        frame.slots = report.finger_count;
        frame.report_id = id;
        frame.button = extract(payload, report.button) != 0;
        frame.has_contact_count = report.contact_count.width != 0;
        const auto contacts = extract(payload, report.contact_count);
        if (contacts < 0 || contacts > UINT8_MAX)
            return Packet::invalid;
        frame.contact_count = unsigned(contacts);
        for (unsigned j = 0; j < report.finger_count; ++j) {
            const auto& fields = report.fingers[j];
            if (!fits(fields.id, report.bits) || !fits(fields.tip, report.bits) ||
                !fits(fields.confidence, report.bits) || !fits(fields.x, report.bits) ||
                !fits(fields.y, report.bits))
                return Packet::invalid;
            auto& finger = frame.fingers[j];
            const auto contact = extract(payload, fields.id);
            if (contact < 0 || contact > UINT32_MAX)
                return Packet::invalid;
            finger.id = fields.id.width ? uint32_t(contact) : j;
            finger.touching = extract(payload, fields.tip) != 0;
            finger.confident = !fields.confidence.width || extract(payload, fields.confidence) != 0;
            if (!finger.touching)
                continue;
            const auto x = extract(payload, fields.x), y = extract(payload, fields.y);
            if (x < fields.x.minimum || x > fields.x.maximum || y < fields.y.minimum ||
                y > fields.y.maximum)
                return Packet::invalid;
            finger.x = int32_t(x);
            finger.y = int32_t(y);
        }
        return Packet::input;
    }
    return Packet::unknown;
}
} // namespace ax::HidTouchpad
