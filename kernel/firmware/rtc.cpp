// SPDX-License-Identifier: GPL-3.0-or-later
#include "firmware/rtc.hpp"
#include "core/base.hpp"

namespace ax::Rtc {
namespace {
bool number(uint8_t raw, bool binary, unsigned& value) {
    if (!binary && ((raw & 15) > 9 || (raw >> 4) > 9))
        return false;
    value = binary ? raw : (raw >> 4) * 10 + (raw & 15);
    return true;
}

bool leap(unsigned year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

bool snapshot(Reader reader, void* context, Fields& value) {
    bool ready = false;
    for (unsigned i = 0; i < update_polls; i++) {
        uint8_t state = reader(0x0a, context);
        if ((state & 0x70) > 0x20)
            return false;
        if (!(state & 0x80)) {
            ready = true;
            break;
        }
    }
    if (!ready || !(reader(0x0d, context) & 0x80))
        return false;
    value.control = reader(0x0b, context);
    value.second = reader(0x00, context);
    value.minute = reader(0x02, context);
    value.hour = reader(0x04, context);
    value.day = reader(0x07, context);
    value.month = reader(0x08, context);
    value.year = reader(0x09, context);
    value.century = reader(0x32, context);
    return !(reader(0x0a, context) & 0x80) && (reader(0x0d, context) & 0x80);
}
} // namespace

bool decode(const Fields& raw, int64_t& seconds) {
    if (raw.control & 0x80)
        return false;
    bool binary = raw.control & 4, hours24 = raw.control & 2, afternoon = raw.hour & 0x80;
    unsigned second, minute, hour, day, month, year, century = 0;
    if (!number(raw.second, binary, second) || !number(raw.minute, binary, minute) ||
        !number(raw.hour & 0x7f, binary, hour) || !number(raw.day, binary, day) ||
        !number(raw.month, binary, month) || !number(raw.year, binary, year) || year > 99 ||
        second > 59 || minute > 59 || month < 1 || month > 12 || day < 1)
        return false;
    if (hours24) {
        if (afternoon || hour > 23)
            return false;
    } else {
        if (hour < 1 || hour > 12)
            return false;
        hour = hour % 12 + (afternoon ? 12 : 0);
    }
    if (raw.century && raw.century != 0xff && !number(raw.century, binary, century))
        return false;
    year += century ? century * 100 : year >= 70 ? 1900 : 2000;
    if (year < 1970 || year > 9999)
        return false;
    const unsigned lengths[]{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (day > lengths[month - 1] + (month == 2 && leap(year)))
        return false;
    // Gregorian days before this year, relative to 1970; bounded through year 9999.
    unsigned previous = year - 1;
    int64_t days =
        int64_t(previous) * 365 + previous / 4 - previous / 100 + previous / 400 - 719162;
    for (unsigned i = 1; i < month; i++)
        days += lengths[i - 1] + (i == 2 && leap(year));
    days += day - 1;
    int64_t value = days * 86400 + hour * 3600 + minute * 60 + second;
    if (value < 0 || value > maximum_seconds)
        return false;
    seconds = value;
    return true;
}

bool read(Reader reader, void* context, int64_t& seconds) {
    if (!reader)
        return false;
    for (unsigned i = 0; i < attempts; i++) {
        Fields first{}, second{};
        if (snapshot(reader, context, first) && snapshot(reader, context, second) &&
            !memcmp(&first, &second, sizeof(first)) && decode(first, seconds))
            return true;
    }
    return false;
}
} // namespace ax::Rtc
