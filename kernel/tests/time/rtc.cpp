// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include "firmware/rtc.hpp"

using namespace ax;

static void require(bool condition, const char* operation) {
    if (!condition) {
        std::fprintf(stderr, "RTC_CODEC_FAIL %s\n", operation);
        std::exit(1);
    }
}

static uint8_t bcd(unsigned value) {
    return (value / 10) * 16 + value % 10;
}

static Rtc::Fields fields(unsigned year, unsigned month, unsigned day, unsigned hour,
                          unsigned minute, unsigned second, bool binary, bool hours24) {
    Rtc::Fields value{uint8_t(second),     uint8_t(minute),
                      uint8_t(hour),       uint8_t(day),
                      uint8_t(month),      uint8_t(year % 100),
                      uint8_t(year / 100), uint8_t((binary ? 4 : 0) | (hours24 ? 2 : 0))};
    bool afternoon = hour >= 12;
    if (!hours24)
        value.hour = hour % 12 ? hour % 12 : 12;
    if (!binary) {
        value.second = bcd(value.second);
        value.minute = bcd(value.minute);
        value.hour = bcd(value.hour);
        value.day = bcd(value.day);
        value.month = bcd(value.month);
        value.year = bcd(value.year);
        value.century = bcd(value.century);
    }
    if (!hours24 && afternoon)
        value.hour |= 0x80;
    return value;
}

struct Device {
    Rtc::Fields value;
    unsigned reads = 0, update_reads = 0, snapshots = 0, mode = 0;
};

static uint8_t read(uint8_t reg, void* context) {
    auto& device = *static_cast<Device*>(context);
    device.reads++;
    if (reg == 0x0a) {
        device.update_reads++;
        if (device.mode == 5)
            return 0x60;
        return device.mode == 1 || (device.mode == 2 && device.update_reads < 20) ? 0xa0 : 0x20;
    }
    if (reg == 0x0d)
        return device.mode == 3 ? 0 : 0x80;
    if (reg == 0x0b) {
        device.snapshots++;
        return device.value.control;
    }
    if (reg == 0x00)
        return device.mode == 4 ? uint8_t(device.value.second + device.snapshots % 2)
                                : device.value.second;
    if (reg == 0x02)
        return device.value.minute;
    if (reg == 0x04)
        return device.value.hour;
    if (reg == 0x07)
        return device.value.day;
    if (reg == 0x08)
        return device.value.month;
    if (reg == 0x09)
        return device.value.year;
    require(reg == 0x32, "only documented RTC registers are read");
    return device.value.century;
}

int main() {
    unsigned dates = 0;
    const unsigned years[]{1970, 1999, 2000, 2026, 2038, 2069, 2099, 2100, 2400, 9999};
    for (unsigned year : years)
        for (unsigned month = 1; month <= 12; month++)
            for (unsigned day = 1; day <= 31; day++)
                for (unsigned mode = 0; mode < 4; mode++) {
                    unsigned hour = (year + month + day) % 24;
                    std::tm native{};
                    native.tm_year = year - 1900;
                    native.tm_mon = month - 1;
                    native.tm_mday = day;
                    native.tm_hour = hour;
                    native.tm_min = 37;
                    native.tm_sec = 59;
                    time_t expected = timegm(&native);
                    bool valid = native.tm_year == int(year - 1900) &&
                                 native.tm_mon == int(month - 1) && native.tm_mday == int(day);
                    int64_t result = -123;
                    auto value = fields(year, month, day, hour, 37, 59, mode & 1, mode & 2);
                    require(Rtc::decode(value, result) == valid &&
                                result == (valid ? int64_t(expected) : -123),
                            "calendar and encoding agree with native UTC conversion");
                    dates++;
                }
    for (unsigned hour = 0; hour < 24; hour++) {
        int64_t first = -1, second = -1;
        require(Rtc::decode(fields(2026, 1, 1, hour, 0, 0, false, false), first) &&
                    Rtc::decode(fields(2026, 1, 1, hour, 0, 0, true, true), second) &&
                    first == second,
                "all noon midnight and afternoon encodings agree");
    }
    for (unsigned year = 1970; year <= 2069; year++) {
        auto value = fields(year, 1, 1, 0, 0, 0, true, true);
        int64_t expected = -1, result = -1;
        require(Rtc::decode(value, expected), "explicit century");
        value.century = 0;
        require(Rtc::decode(value, result) && result == expected, "absent century window");
        value.century = 0xff;
        require(Rtc::decode(value, result) && result == expected, "unpopulated century window");
    }
    uint32_t random = 0x4f391758;
    unsigned rejected = 0;
    for (unsigned trial = 0; trial < 16000; trial++) {
        auto value = fields(2026, 10, 11, 12, 30, 45, false, true);
        auto bytes = reinterpret_cast<uint8_t*>(&value);
        random = random * 1664525 + 1013904223;
        bytes[(random >> 8) % sizeof(value)] ^= random >> 24;
        int64_t seconds = -123;
        if (!Rtc::decode(value, seconds)) {
            require(seconds == -123, "invalid date preserves result");
            rejected++;
        } else
            require(seconds >= 0 && seconds <= Rtc::maximum_seconds,
                    "accepted date remains bounded");
    }
    for (unsigned mode = 0; mode < 6; mode++) {
        Device device{fields(2026, 10, 11, 12, 30, 45, false, true), 0, 0, 0, mode};
        int64_t seconds = -123;
        bool valid = mode == 0 || mode == 2;
        require(Rtc::read(read, &device, seconds) == valid && (valid || seconds == -123),
                "stable progress and failed source controls");
        require(device.reads <= Rtc::attempts * (2 * Rtc::update_polls + 24),
                "bounded RTC retry reads");
    }
    std::printf(
        "RTC_CODEC_PASS dates=%u hours=24 century=100 mutations=16000 rejected=%u sources=6\n",
        dates, rejected);
}
