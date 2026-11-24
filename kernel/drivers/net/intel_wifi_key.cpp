// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_key.cpp
 * @brief   Encode AX201 security key commands.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Layout follows version 1 of the firmware data-path security key command.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_key.hpp"

namespace ax::IntelWifi {
namespace {
void put_le(uint8_t* bytes, uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        bytes[i] = uint8_t(value >> (i * 8));
}

bool prepare_slot(CcmpKeySlot slot, uint8_t action, uint8_t (&wire)[key_command_bytes]) {
    if (slot.station >= 32 || slot.index >= 4)
        return false;
    memset(wire, 0, sizeof(wire));
    wire[0] = action;
    put_le(wire + 4, uint32_t(1) << slot.station, 4);
    wire[8] = slot.index;
    wire[12] = 2 | (slot.group ? 0x40 : 0); // CCMP-128 and optional multicast key.
    return true;
}
} // namespace

bool prepare_ccmp_key_install(CcmpKeySlot slot, const uint8_t* key, uint64_t receive_sequence,
                              uint64_t transmit_sequence, uint8_t (&wire)[key_command_bytes]) {
    constexpr uint64_t sequence_limit = uint64_t(1) << 48;
    if (!key || receive_sequence >= sequence_limit || transmit_sequence >= sequence_limit ||
        !prepare_slot(slot, 1, wire))
        return false;
    memcpy(wire + 16, key, ccmp_key_bytes);
    put_le(wire + 64, receive_sequence, 8);
    put_le(wire + 72, transmit_sequence, 8);
    return true;
}

bool prepare_ccmp_key_remove(CcmpKeySlot slot, uint8_t (&wire)[key_command_bytes]) {
    return prepare_slot(slot, 3, wire);
}

void erase_key_bytes(void* buffer, size_t length) {
    auto* bytes = static_cast<volatile uint8_t*>(buffer);
    for (size_t i = 0; i < length; ++i)
        bytes[i] = 0;
}
} // namespace ax::IntelWifi
