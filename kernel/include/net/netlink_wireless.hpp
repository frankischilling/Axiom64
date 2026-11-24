// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/netlink_wireless.hpp
 * @brief   nl80211 passive scan discovery and dump cursor.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax {
struct NetlinkHeader;
inline constexpr uint16_t nl80211_family = 17;
inline constexpr uint8_t nl80211_get_wiphy = 1, nl80211_get_interface = 5, nl80211_get_scan = 32;

struct WirelessDump {
    uint32_t sequence = 0;
    unsigned next = 0;
    bool active = false;
};

bool wireless_scan_available();
size_t wireless_reply(const void*, const NetlinkHeader&, uint32_t port, bool capped, void*,
                      void* followup, size_t& followup_length, WirelessDump&);
size_t wireless_dump_record(const WirelessDump&, uint32_t port, void* output);
void wireless_dump_advance(WirelessDump&);
} // namespace ax
