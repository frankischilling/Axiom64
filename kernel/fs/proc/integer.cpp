// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
#include "fs/proc/integer.hpp"

namespace ax::proc {
namespace {
bool space(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

int digit(char c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}

bool parse_number(const char* bytes, size_t length, uint64_t limit, bool allow_negative,
                  uint64_t& value, bool& negative, size_t& consumed) {
    size_t at = 0;
    while (at < length && space(bytes[at]))
        at++;
    size_t start = at;
    negative = at < length && bytes[at] == '-';
    if (negative)
        at++;
    if ((negative && !allow_negative) || at == length || bytes[at] < '0' || bytes[at] > '9')
        return false;
    unsigned base = 10;
    if (bytes[at] == '0') {
        base = 8;
        if (at + 2 < length && (bytes[at + 1] == 'x' || bytes[at + 1] == 'X') &&
            digit(bytes[at + 2]) >= 0) {
            base = 16;
            at += 2;
        }
    }
    uint64_t number = 0;
    limit += negative;
    while (at < length) {
        int next = digit(bytes[at]);
        if (next < 0 || unsigned(next) >= base)
            break;
        if (number > (limit - unsigned(next)) / base)
            return false;
        number = number * base + unsigned(next);
        at++;
    }
    // Linux's numeric token buffer rejects a token filling all 21 slots.
    if (at - start >= 21 ||
        (at < length && bytes[at] != ' ' && bytes[at] != '\t' && bytes[at] != '\n'))
        return false;
    while (at < length && space(bytes[at]))
        at++;
    value = number;
    consumed = at;
    return true;
}

int64_t read_number(uint64_t number, bool negative, uint64_t& offset, void* output, size_t length) {
    if (!length || offset)
        return 0;
    char text[22], reverse[20];
    size_t count = 0, digits = 0;
    do {
        reverse[digits++] = char('0' + number % 10);
        number /= 10;
    } while (number);
    if (negative)
        text[count++] = '-';
    while (digits)
        text[count++] = reverse[--digits];
    text[count++] = '\n';
    count = min(count, length);
    memcpy(output, text, count);
    offset += count;
    return int64_t(count);
}
} // namespace

bool parse_integer(const char* bytes, size_t length, bool unsigned_value, int32_t& value,
                   size_t& consumed) {
    uint64_t magnitude;
    bool negative;
    if (!parse_number(bytes, length, unsigned_value ? UINT32_MAX : uint64_t(INT32_MAX),
                      !unsigned_value, magnitude, negative, consumed))
        return false;
    value = negative ? int32_t(-int64_t(magnitude)) : int32_t(magnitude);
    return true;
}

bool parse_unsigned_long(const char* bytes, size_t length, uint64_t& value, size_t& consumed) {
    bool negative;
    return parse_number(bytes, length, UINT64_MAX, false, value, negative, consumed);
}

int64_t read_integer(int32_t value, uint64_t& offset, void* output, size_t length) {
    uint64_t magnitude = value < 0 ? uint64_t(-int64_t(value)) : uint64_t(value);
    return read_number(magnitude, value < 0, offset, output, length);
}

int64_t read_unsigned_long(uint64_t value, uint64_t& offset, void* output, size_t length) {
    return read_number(value, false, offset, output, length);
}
} // namespace ax::proc
