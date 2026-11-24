// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_auth.hpp
 * @brief   AX201 management transmit and open-system authentication exchange.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_peer.hpp"

namespace ax::IntelWifi {
inline constexpr unsigned session_protection_bytes = 24;
inline constexpr unsigned authentication_dma_bytes = 192;

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
bool prepare_authentication_frame(const AuthenticationDma&, PeerQueue, uint32_t,
                                  const uint8_t (&station)[6], const AccessPoint&);
AuthEvent observe_authentication_tx(const FirmwarePacket&, PeerQueue);
AuthEvent observe_authentication_reply(const FirmwarePacket&, const uint8_t (&station)[6],
                                       const AccessPoint&, uint8_t channel);
} // namespace ax::IntelWifi
