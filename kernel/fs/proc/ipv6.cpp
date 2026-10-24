// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/proc/ipv6.hpp"
#include "net/ipv6/configuration.hpp"
#include "core/random/primitives.hpp"

namespace ax::proc6 {
namespace {
constexpr ip6::ConfigurationKey keys[] = {ip6::ConfigurationKey::generation_mode,
                                          ip6::ConfigurationKey::disabled,
                                          ip6::ConfigurationKey::accept_ra,
                                          ip6::ConfigurationKey::autoconf,
                                          ip6::ConfigurationKey::dad_transmits,
                                          ip6::ConfigurationKey::enhanced_dad,
                                          ip6::ConfigurationKey::router_solicitations,
                                          ip6::ConfigurationKey::max_addresses};

bool space(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

int digit(char c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}

bool integer(const char* bytes, size_t length, bool unsigned_value, int32_t& value,
             size_t& consumed) {
    size_t at = 0;
    while (at < length && space(bytes[at]))
        at++;
    size_t start = at;
    bool negative = at < length && bytes[at] == '-';
    if (negative)
        at++;
    if ((negative && unsigned_value) || at == length || bytes[at] < '0' || bytes[at] > '9')
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
    uint64_t limit = unsigned_value ? UINT32_MAX : uint64_t(INT32_MAX) + negative;
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
    value = negative ? int32_t(-int64_t(number)) : int32_t(number);
    consumed = at;
    return true;
}

void secret_text(const ip6::Address& address, char (&text)[48]) {
    size_t at = 0;
    for (unsigned n = 0; n < 16; n++) {
        if (n && !(n & 1))
            text[at++] = ':';
        text[at++] = "0123456789abcdef"[address.bytes[n] >> 4];
        text[at++] = "0123456789abcdef"[address.bytes[n] & 15];
    }
    text[at] = 0;
}

bool secret_address(const char* text, ip6::Address& address) {
    uint16_t words[8]{};
    unsigned count = 0;
    int compressed = -1;
    auto cursor = text;
    if (*cursor == ':') {
        if (cursor[1] != ':')
            return false;
        cursor += 2;
        compressed = 0;
    }
    while (*cursor) {
        if (count == 8 || digit(*cursor) < 0)
            break;
        auto start = cursor;
        unsigned word = 0;
        while (digit(*cursor) >= 0) {
            if (word > 0xfff)
                return false;
            word = (word << 4) | unsigned(digit(*cursor++));
        }
        if (*cursor == '.') {
            if (count > 6)
                return false;
            cursor = start;
            uint8_t tail[4];
            for (unsigned n = 0; n < 4; n++) {
                unsigned byte = 0;
                if (*cursor < '0' || *cursor > '9')
                    return false;
                do {
                    byte = byte * 10 + unsigned(*cursor++ - '0');
                    if (byte > 255)
                        return false;
                } while (*cursor >= '0' && *cursor <= '9');
                tail[n] = uint8_t(byte);
                if (n < 3 && *cursor++ != '.')
                    return false;
            }
            words[count++] = uint16_t(tail[0]) << 8 | tail[1];
            words[count++] = uint16_t(tail[2]) << 8 | tail[3];
            break;
        }
        words[count++] = uint16_t(word);
        if (*cursor != ':')
            break;
        if (count == 8)
            return false;
        cursor++;
        if (*cursor == ':') {
            if (compressed >= 0)
                return false;
            compressed = int(count);
            cursor++;
            if (!*cursor)
                break;
        } else if (!*cursor)
            return false;
    }
    // The Linux stable-secret handler accepts an address terminated by a
    // non-address delimiter. Colons, dots and extra hexadecimal digits fail.
    if (*cursor == ':' || *cursor == '.' || digit(*cursor) >= 0 ||
        (compressed < 0 ? count != 8 : count >= 8))
        return false;
    unsigned zeros = 8 - count;
    for (unsigned n = 0; n < count; n++) {
        unsigned at = compressed >= 0 && n >= unsigned(compressed) ? n + zeros : n;
        address.bytes[2 * at] = uint8_t(words[n] >> 8);
        address.bytes[2 * at + 1] = uint8_t(words[n]);
    }
    return true;
}

int64_t secret_read(unsigned index, uint64_t& offset, void* output, size_t length) {
    ip6::Address secret;
    int error = ip6::configuration_secret_read(index, secret);
    if (error)
        return error;
    char text[48];
    secret_text(secret, text);
    random::erase(&secret, sizeof(secret));
    text[39] = '\n';
    size_t count = offset < 40 ? min(uint64_t(length), 40 - offset) : 0;
    if (count)
        memcpy(output, text + offset, count);
    offset += count;
    random::erase(text, sizeof(text));
    return int64_t(count);
}

int64_t secret_write(unsigned index, uint64_t& offset, const void* input, size_t length) {
    if (index == ip6::configuration_all)
        return -5;
    ip6::Address secret;
    int error = ip6::configuration_secret_read(index, secret);
    if (error && error != -5)
        return error;
    char text[48];
    secret_text(secret, text);
    size_t at = size_t(min(offset, uint64_t(47)));
    uint64_t next = offset;
    if (length && offset <= 39) {
        next += length;
        auto bytes = static_cast<const char*>(input);
        for (size_t n = 0; n < length && at < sizeof(text) - 1; n++) {
            if (!bytes[n] || bytes[n] == '\n')
                break;
            text[at++] = bytes[n];
        }
        text[at] = 0;
    }
    secret = {};
    bool valid = secret_address(text, secret);
    random::erase(text, sizeof(text));
    error = valid ? ip6::configuration_secret(index, secret) : -5;
    random::erase(&secret, sizeof(secret));
    if (error)
        return error;
    offset = next;
    return int64_t(length);
}
} // namespace

const char* property_name(unsigned property) {
    static constexpr const char* names[] = {
        "addr_gen_mode", "disable_ipv6",         "accept_ra",     "autoconf",     "dad_transmits",
        "enhanced_dad",  "router_solicitations", "max_addresses", "stable_secret"};
    return property < property_count ? names[property] : nullptr;
}

const char* scope_name(unsigned cookie) {
    if (cookie < 3)
        return cookie == 0 ? "all" : cookie == 1 ? "default" : "lo";
    auto info = cookie - 2 <= max_net_devices ? net_info(cookie - 2) : nullptr;
    return info ? info->name : nullptr;
}

bool scope_index(const char* name, unsigned& index) {
    if (!strcmp(name, "all"))
        index = ip6::configuration_all;
    else if (!strcmp(name, "default"))
        index = ip6::configuration_default;
    else if (!strcmp(name, "lo"))
        index = ipv6_loopback;
    else {
        for (unsigned at = 1; at <= max_net_devices; at++)
            if (auto info = net_info(at); info && !strcmp(info->name, name)) {
                index = at;
                return true;
            }
        return false;
    }
    return true;
}

int64_t read(unsigned index, unsigned property, uint64_t& offset, void* output, size_t length) {
    if (property == secret_property)
        return secret_read(index, offset, output, length);
    if (property >= secret_property)
        return -22;
    if (!length || offset)
        return 0;
    int32_t value;
    if (int error = ip6::configuration_read(index, keys[property], value))
        return error;
    char text[12], reverse[10];
    size_t count = 0, digits = 0;
    uint32_t number = value < 0 ? uint32_t(-int64_t(value)) : uint32_t(value);
    do {
        reverse[digits++] = char('0' + number % 10);
        number /= 10;
    } while (number);
    if (value < 0)
        text[count++] = '-';
    while (digits)
        text[count++] = reverse[--digits];
    text[count++] = '\n';
    count = min(count, length);
    memcpy(output, text, count);
    offset += count;
    return int64_t(count);
}

int64_t write(unsigned index, unsigned property, uint64_t& offset, const void* input,
              size_t length) {
    if (property == secret_property)
        return secret_write(index, offset, input, length);
    if (property >= secret_property)
        return -22;
    if (!length)
        return 0;
    if (offset) {
        offset += length;
        return int64_t(length);
    }
    int32_t value;
    size_t consumed = 0, parsed = min(length, size_t(4095));
    if (!integer(static_cast<const char*>(input), parsed, !property, value, consumed))
        return -22;
    if (int error = ip6::configuration_write(index, keys[property], value))
        return error;
    if (!property)
        return int64_t(length);
    consumed += length - parsed;
    offset += consumed;
    return int64_t(consumed);
}
} // namespace ax::proc6
