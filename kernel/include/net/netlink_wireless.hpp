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
inline constexpr uint16_t nl80211_max_attribute = 315; // NL80211_ATTR_MLO_SUPPORT
inline constexpr uint8_t nl80211_get_wiphy = 1, nl80211_get_interface = 5, nl80211_get_scan = 32;
inline constexpr uint8_t nl80211_trigger_scan = 33;
inline constexpr uint8_t nl80211_abort_scan = 114;
inline constexpr uint8_t nl80211_connect = 46, nl80211_disconnect = 48;
inline constexpr uint8_t nl80211_get_station = 17, nl80211_set_station = 18;
inline constexpr uint8_t nl80211_new_key = 11, nl80211_del_key = 12;
inline constexpr unsigned nl80211_scan_group = 17, nl80211_mlme_group = 18;

struct WirelessDump {
    uint32_t sequence = 0;
    uint32_t generation = 0;
    unsigned next = 0;
    bool active = false;
};

bool wireless_scan_available();
bool wireless_trigger_available();
bool wireless_connect_available();
size_t wireless_reply_capacity(const NetlinkHeader&, const uint8_t* request);
size_t wireless_reply(const void*, const NetlinkHeader&, uint32_t port, bool capped,
                      bool privileged, void*, void* followup, size_t& followup_length,
                      WirelessDump&);
size_t wireless_dump_record(const WirelessDump&, uint32_t port, void* output);
void wireless_dump_advance(WirelessDump&);
void wireless_scan_finished(unsigned ifindex, bool complete);

struct WirelessElements {
    const uint8_t* bytes = nullptr;
    size_t length = 0;
};

void wireless_connection_finished(unsigned ifindex, const uint8_t (&bssid)[6], uint16_t status,
                                  bool timeout, WirelessElements request,
                                  WirelessElements response);
void wireless_disconnected(unsigned ifindex, uint16_t reason = 1, bool from_ap = false);
void wireless_socket_closed(unsigned port);
void netlink_broadcast_wireless(unsigned group, const void*, size_t);
} // namespace ax
