// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_context.hpp
 * @brief   AX201 QuZ firmware boot records and queue descriptors.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi.hpp"

namespace ax::IntelWifi {
inline constexpr uint16_t quz_mac_revision = 0x0351;
inline constexpr unsigned rx_ring_entries = 2048;
inline constexpr unsigned command_ring_entries = 32;
inline constexpr unsigned command_sequence_count = 256;
inline constexpr uint64_t rx_buffer_id_mask = 0xfff;
inline constexpr unsigned invalid_command_size = 8;

using FirmwareAddresses = uint64_t[region_count][max_sections];

struct ReceiveStatus {
    uint16_t closed_buffer, closed_frame;
    uint16_t finished_buffer, finished_frame;
    uint32_t reserved;
};

static_assert(sizeof(ReceiveStatus) == 12);

struct ReceiveQueues {
    uint64_t free_ring;
    uint64_t used_ring;
    uint64_t status;
};

// QuZ uses the pre-AX210 version-zero context. These records are little-endian on x86-64.
struct BootContext {
    uint16_t mac_id, version, dwords, reserved_version;
    uint32_t control, reserved_control;
    uint64_t reserved_before_queues;
    ReceiveQueues rx;
    uint64_t commands;
    uint8_t command_size;
    uint8_t reserved_before_images[135];
    uint64_t umac[max_sections], lmac[max_sections], paging[max_sections];
    uint8_t reserved_after_images[64];
};

static_assert(sizeof(BootContext) == 1792);
static_assert(offsetof(BootContext, rx) == 24 && offsetof(BootContext, commands) == 48);
static_assert(offsetof(BootContext, umac) == 192 && offsetof(BootContext, lmac) == 704 &&
              offsetof(BootContext, paging) == 1216);

struct [[gnu::packed]] TransmitBuffer {
    uint16_t length;
    uint64_t address;
};

struct [[gnu::packed]] CommandDescriptor {
    uint16_t buffer_count;
    TransmitBuffer buffers[25];
    uint32_t reserved;
};

static_assert(sizeof(CommandDescriptor) == 256);
static_assert(offsetof(CommandDescriptor, buffers) == 2);

bool make_boot_context(const FirmwareImage&, const FirmwareAddresses&, ReceiveQueues,
                       uint64_t command_ring, BootContext&);
bool encode_receive_buffer(uint64_t address, unsigned id, uint64_t& descriptor);
bool prepare_command_ring(uint64_t invalid_command, uint8_t (&payload)[invalid_command_size],
                          CommandDescriptor (&ring)[command_ring_entries]);
} // namespace ax::IntelWifi
