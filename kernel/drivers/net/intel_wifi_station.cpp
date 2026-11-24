// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_station.cpp
 * @brief   Dispatch AX201 station traffic and peer notifications.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#include "intel_wifi_station.hpp"

namespace ax::IntelWifi {
bool is_eapol(const uint8_t* frame, size_t length) {
    return frame && length >= 14 && frame[12] == 0x88 && frame[13] == 0x8e;
}

bool allows_station_data(const LiveStation& station, const uint8_t* frame, size_t length) {
    return (station.port_authorized && (!station.ccmp || station.keys.pairwise.installed)) ||
           is_eapol(frame, length);
}

uint64_t station_beacon_timeout(const LiveStation& station) {
    return max(3000u, 8u * station.peer.beacon_interval_tu * 1024 / 1000);
}

void leave_after_link_loss(LiveScanSession& session, uint16_t reason, bool from_ap) {
    session.leave = {LeavePhase::drain, reason};
    session.leave.send_deauthentication = false;
    session.leave.from_ap = from_ap;
    if (session.active)
        session.exchange.request_abort();
}

bool observe_station_packet(LiveScanSession& session, const FirmwarePacket& packet, uint64_t now_ms,
                            const StationEvents& events) {
    auto& station = session.station;
    if (station.pending_bytes) {
        const auto tx = observe_authentication_tx(packet, station.queue);
        if (tx == AuthEvent::malformed)
            return false;
        if (tx == AuthEvent::accepted || tx == AuthEvent::denied) {
            const auto bytes = station.pending_bytes;
            station.pending_bytes = 0;
            ++station.queue.write_pointer;
            events.complete(events.context, bytes, tx == AuthEvent::denied);
        }
    }
    if (session.active)
        session.exchange.observe(packet, now_ms);
    if (session.leave.phase != LeavePhase::idle)
        return true;
    uint16_t reason;
    if (observe_station_disconnect(packet, session.station_address, station.peer, station.channel,
                                   reason)) {
        leave_after_link_loss(session, reason, true);
        return true;
    }
    AssociationTiming timing;
    if (observe_association_beacon(packet, station.peer, station.channel, timing)) {
        station.beacon_deadline = now_ms + station_beacon_timeout(station);
        if (timing.signal_dbm != scan_signal_unavailable)
            station.peer.signal_dbm = timing.signal_dbm;
    }
    uint8_t frame[station_frame_bytes];
    if (const auto bytes =
            receive_station_data(packet, session.station_address, station.peer.bssid,
                                 station.channel, frame, station.ccmp ? &station.keys : nullptr);
        bytes && allows_station_data(station, frame, bytes))
        events.receive(events.context, frame, bytes);
    return true;
}
} // namespace ax::IntelWifi
