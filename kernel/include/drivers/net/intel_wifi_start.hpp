// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_start.hpp
 * @brief   Polled AX201 firmware startup and shutdown.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_command.hpp"

namespace ax::IntelWifi {
struct FirmwareBootIo {
    void* context;
    uint32_t (*read)(void*, unsigned offset);
    void (*write)(void*, unsigned offset, uint32_t value);
    bool (*delay)(void*, unsigned microseconds);
    bool (*bus_master)(void*, bool enable);
    const uint8_t* (*receive_buffer)(void*, unsigned id);
};

struct FirmwareBootMemory {
    uint64_t context_address;
    volatile const ReceiveStatus* receive_status;
    volatile const uint32_t* used_ring;
    CommandDescriptor* commands = nullptr;
    CommandPayloads* command_payloads = nullptr;
    uint64_t command_dma = 0;
};

enum class AlivePacket { missing, success, rejected, malformed };
AlivePacket read_alive_notification(const uint8_t* data, size_t length);

struct FirmwareBootResult {
    const char* status;
    bool alive;
    bool dma_idle;
    NvmInfo nvm{};
};

// The caller must retain every DMA allocation if the adapter cannot be stopped.
FirmwareBootResult start_and_stop_quz(const FirmwareBootIo&, const FirmwareBootMemory&);
} // namespace ax::IntelWifi
