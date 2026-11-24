// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/net/intel_wifi_rx.hpp
 * @brief   Track AX201 receive buffer ownership and completion cursors.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "drivers/net/intel_wifi_start.hpp"

namespace ax::IntelWifi {
class ReceiveReader {
    const FirmwareBootIo& io;
    unsigned read = 0, write = 0, published = 0, current_id = 0;
    size_t offset = 0;
    uint8_t* buffer = nullptr;
    uint64_t device_buffers[rx_ring_entries / 64]{};

    bool change_owner(unsigned id, bool device);
    bool release_buffer();
    void publish(unsigned);

  public:
    const FirmwareBootMemory& memory;

    ReceiveReader(const FirmwareBootIo& io, const FirmwareBootMemory& memory)
        : io(io), memory(memory) {
    }

    ReceiveReader(const ReceiveReader&) = delete;
    ReceiveReader& operator=(const ReceiveReader&) = delete;

    void post_initial();
    // A returned packet borrows its DMA buffer until the next call.
    PacketRead next(FirmwarePacket&);
};
} // namespace ax::IntelWifi
