// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_auth.hpp
 * @brief   AX201 management transmit, authentication, and association exchanges.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_peer.hpp"

namespace ax::IntelWifi {
inline constexpr unsigned session_protection_bytes = 24;
inline constexpr unsigned station_frame_bytes = 1518;
inline constexpr unsigned authentication_dma_bytes = 128 + 8 + station_frame_bytes - 14;
// Capability, listen interval, SSID, and up to twelve rates in two elements.
inline constexpr unsigned association_extra_limit = 64;
inline constexpr unsigned association_body_bytes =
    4 + 2 + 32 + 2 + 12 + 2 + association_extra_limit;

struct AssociationRequest {
    uint8_t body[association_body_bytes]{};
    unsigned length = 0;
};

struct AssociationTiming {
    uint64_t beacon_tsf = 0;
    uint32_t receive_time = 0;
    uint16_t beacon_interval_tu = 0;
    uint8_t dtim_count = 0, dtim_period = 0;
};

enum class ManagementFrame : uint8_t { associate = 0x00, authenticate = 0xb0, leave = 0xc0 };

struct AuthenticationDma {
    CommandDescriptor* ring = nullptr;
    uint16_t* byte_counts = nullptr;
    uint8_t* payload = nullptr;
    uint64_t address = 0;
};

enum class AuthEvent { unrelated, accepted, denied, malformed, ended };

void prepare_session_protection(bool start, uint8_t (&wire)[session_protection_bytes]);
AuthEvent observe_session_protection(const FirmwarePacket&);
uint32_t authentication_rate(const uint8_t* ies, unsigned bytes, bool high_band, uint8_t antennas);
bool valid_authentication_dma(const AuthenticationDma&);
void prepare_authentication_mac(const uint8_t (&station)[6], const AccessPoint&,
                                uint8_t (&wire)[mac_context_bytes]);
bool observe_association_beacon(const FirmwarePacket&, const AccessPoint&, uint8_t channel,
                                AssociationTiming&);
void prepare_associated_mac(const uint8_t (&station)[6], const AccessPoint&, uint16_t aid,
                            const AssociationTiming&, uint8_t (&wire)[mac_context_bytes]);
bool prepare_association_request(const AccessPoint&, const uint8_t* ies, unsigned bytes,
                                 bool high_band, AssociationRequest&,
                                 const uint8_t* extra = nullptr, unsigned extra_bytes = 0);
bool prepare_management_frame(const AuthenticationDma&, PeerQueue, uint32_t,
                              const uint8_t (&station)[6], const AccessPoint&, ManagementFrame,
                              const AssociationRequest&, uint16_t sequence, uint16_t reason = 3);
bool prepare_arp_request(const AuthenticationDma&, PeerQueue, uint32_t, const uint8_t (&station)[6],
                         const AuthenticationTarget&, uint16_t sequence);
bool observe_arp_response(const FirmwarePacket&, const uint8_t (&station)[6], uint8_t channel,
                          const AuthenticationTarget&);
bool prepare_station_data(const AuthenticationDma&, PeerQueue, uint32_t rate,
                          const uint8_t (&station)[6], const uint8_t (&bssid)[6],
                          const uint8_t* frame, size_t length, uint16_t sequence);
size_t receive_station_data(const FirmwarePacket&, const uint8_t (&station)[6],
                            const uint8_t (&bssid)[6], uint8_t channel,
                            uint8_t (&frame)[station_frame_bytes]);
bool observe_station_disconnect(const FirmwarePacket&, const uint8_t (&station)[6],
                                const AccessPoint&, uint8_t channel);
AuthEvent observe_authentication_tx(const FirmwarePacket&, PeerQueue);
AuthEvent observe_authentication_reply(const FirmwarePacket&, const uint8_t (&station)[6],
                                       const AccessPoint&, uint8_t channel);
AuthEvent observe_association_reply(const FirmwarePacket&, const uint8_t (&station)[6],
                                    const AccessPoint&, uint8_t channel, uint16_t& aid);
} // namespace ax::IntelWifi
