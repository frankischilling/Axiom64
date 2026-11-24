// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_rx.cpp
 * @brief   Drain the QuZ completion ring and post consumed buffers again.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * QuZ uses 12-bit receive buffer IDs. The free ring tail is visible to the
 * device only in groups of eight descriptors.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_rx.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned receive_write_pointer = 0x1c80;
constexpr unsigned initial_buffers = rx_ring_entries - 1;
constexpr unsigned publish_mask = ~7u;
constexpr unsigned ring_mask = rx_ring_entries - 1;

constexpr unsigned advance(unsigned index) {
    return (index + 1) & ring_mask;
}

constexpr unsigned distance(unsigned begin, unsigned end) {
    return (end - begin) & ring_mask;
}
} // namespace

bool ReceiveReader::change_owner(unsigned id, bool device) {
    if (!id || id > initial_buffers)
        return false;
    auto& bits = device_buffers[id / 64];
    const auto bit = uint64_t{1} << (id % 64);
    if (bool(bits & bit) == device)
        return false;
    bits ^= bit;
    return true;
}

void ReceiveReader::publish(unsigned tail) {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    io.write(io.context, receive_write_pointer, tail);
    published = tail;
}

void ReceiveReader::post_initial() {
    write = initial_buffers;
    const unsigned tail = write & publish_mask;
    for (unsigned id = 1; id <= tail; ++id)
        change_owner(id, true);
    publish(tail);
}

bool ReceiveReader::release_buffer() {
    // The diagnostic without recycling leaves consumed buffers idle until reset.
    if (memory.free_ring) {
        const unsigned next = advance(write);
        if (next == read)
            return false;
        // A shorter DMA write must not expose packets left from a previous use.
        memset(buffer, 0, page_size);
        memory.free_ring[write] = memory.receive_descriptors[current_id - 1];
        write = next;
        if (!(write & 7)) {
            for (unsigned index = published; index != write; index = advance(index))
                if (!change_owner(memory.free_ring[index] & rx_buffer_id_mask, true))
                    return false;
            publish(write);
        }
    }
    buffer = nullptr;
    return true;
}

PacketRead ReceiveReader::next(FirmwarePacket& packet) {
    const unsigned closed =
        memory.receive_status->closed_buffer & (memory.free_ring ? ring_mask : rx_buffer_id_mask);
    if (closed > ring_mask || distance(read, closed) > distance(read, published))
        return PacketRead::malformed;
    // The completion index publishes the descriptor and DMA payload together.
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    for (;;) {
        if (buffer) {
            const auto result = next_firmware_packet(buffer, page_size, offset, packet);
            if (result != PacketRead::end)
                return result;
            if (!release_buffer())
                return PacketRead::malformed;
        }
        if (read == closed)
            return PacketRead::end;
        current_id = memory.used_ring[read] & rx_buffer_id_mask;
        if (!change_owner(current_id, false))
            return PacketRead::malformed;
        buffer = io.receive_buffer(io.context, current_id);
        if (!buffer)
            return PacketRead::malformed;
        read = advance(read);
        offset = 0;
    }
}
} // namespace ax::IntelWifi
