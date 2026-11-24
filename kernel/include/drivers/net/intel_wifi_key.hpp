// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_key.hpp
 * @brief   CCMP key commands for the AX201 firmware.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax::IntelWifi {
inline constexpr uint8_t key_command_group = 5, key_command_opcode = 0x18;
inline constexpr unsigned key_command_bytes = 80, ccmp_key_bytes = 16;

struct StationKeyRequest {
    const uint8_t* material = nullptr; // Null for removal.
    uint64_t receive_sequence = 0;
    uint8_t peer[6]{};
    uint8_t index = 0;
    bool group = false;
};

struct CcmpKeySlot {
    uint8_t station, index;
    bool group;
};

bool prepare_ccmp_key_install(CcmpKeySlot, const uint8_t* key, uint64_t receive_sequence,
                              uint64_t transmit_sequence, uint8_t (&wire)[key_command_bytes]);
bool prepare_ccmp_key_remove(CcmpKeySlot, uint8_t (&wire)[key_command_bytes]);
void erase_key_bytes(void*, size_t);
} // namespace ax::IntelWifi
