// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_rsn.cpp
 * @brief   Check WPA2 association suites and RSN element lengths.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_rsn.hpp"

namespace ax::IntelWifi {
namespace {
struct RsnReader {
    const uint8_t* bytes;
    size_t length;

    bool read16(unsigned& value) {
        if (length < 2)
            return false;
        value = bytes[0] | (unsigned(bytes[1]) << 8);
        bytes += 2;
        length -= 2;
        return true;
    }

    bool suites(uint8_t type, bool single) {
        unsigned count;
        if (!read16(count) || !count || count > length / 4 || (single && count != 1))
            return false;
        bool match = false;
        for (unsigned i = 0; i < count; ++i) {
            match |= selector(type);
            bytes += 4;
            length -= 4;
        }
        return match;
    }

    bool selector(uint8_t type) const {
        return length >= 4 && bytes[0] == 0 && bytes[1] == 0x0f && bytes[2] == 0xac &&
               bytes[3] == type;
    }
};
} // namespace

bool supports_rsn(const uint8_t* body, size_t length, RsnAkm akm, bool station_request) {
    constexpr unsigned mfp_required = 1u << 6, mfp_capable = 1u << 7;
    constexpr unsigned spp_amsdu_required = 1u << 11, extended_key_id = 1u << 13;
    if (!body || akm == RsnAkm::open)
        return false;
    RsnReader rsn{body, length};
    unsigned version;
    if (!rsn.read16(version) || version != 1 || !rsn.selector(4))
        return false;
    rsn.bytes += 4;
    rsn.length -= 4;
    if (!rsn.suites(4, station_request) || !rsn.suites(uint8_t(akm), station_request))
        return false;
    if (!rsn.length)
        return true;
    unsigned capabilities;
    if (!rsn.read16(capabilities) || (capabilities & (mfp_required | spp_amsdu_required)) ||
        (station_request && (capabilities & (mfp_capable | extended_key_id))))
        return false;
    if (!rsn.length)
        return true;
    unsigned pmkids;
    if (!rsn.read16(pmkids) || pmkids > rsn.length / 16)
        return false;
    rsn.length -= pmkids * 16;
    return !rsn.length || (!station_request && rsn.length == 4 && (capabilities & mfp_capable));
}

bool station_rsn_matches(const uint8_t* elements, size_t length, RsnAkm akm) {
    bool seen = false;
    while (length) {
        if (!elements || length < 2 || elements[1] > length - 2)
            return false;
        const auto element_bytes = elements[1];
        if (elements[0] == rsn_element) {
            if (seen || !supports_rsn(elements + 2, element_bytes, akm, true))
                return false;
            seen = true;
        }
        length -= 2 + element_bytes;
        elements += 2 + element_bytes;
    }
    return seen == (akm != RsnAkm::open);
}
} // namespace ax::IntelWifi
