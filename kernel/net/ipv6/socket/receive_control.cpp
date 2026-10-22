// SPDX-License-Identifier: GPL-3.0-or-later
#include "receive_control.hpp"

namespace ax {
void Inet6ControlWriter::append(uint32_t type, const void* bytes, size_t size) {
    if (!address || capacity < 16) {
        flags |= 8;
        return;
    }
    uint64_t length = min(capacity, uint64_t(16 + size));
    if (length < 16 + size)
        flags |= 8;
    if (address >= user_limit || length > user_limit - address)
        return;
    uint32_t level = 41;
    // A failed control copy leaves its written prefix visible. It consumes
    // no capacity, so later enabled controls still try the same position.
    if (!task.memory->space.copy_out(address, &length, 8) ||
        !task.memory->space.copy_out(address + 8, &level, 4) ||
        !task.memory->space.copy_out(address + 12, &type, 4))
        return;
    auto source = static_cast<const uint8_t*>(bytes);
    size_t remaining = length - 16;
    uint64_t at = address + 16;
    while (remaining) {
        // Linux x86-64 control copies commit complete 8/4/2/1-byte stores.
        size_t copied = remaining >= 8 ? 8 : remaining >= 4 ? 4 : remaining >= 2 ? 2 : 1;
        if (!task.memory->space.copy_out(at, source, copied))
            return;
        at += copied;
        source += copied;
        remaining -= copied;
    }
    // Account for alignment without writing padding bytes.
    uint64_t consumed = min(capacity, uint64_t((16 + size + 7) & ~size_t(7)));
    used += consumed;
    address += consumed;
    capacity -= consumed;
}

void Inet6ControlWriter::metadata(const Inet6Socket* socket, const ip6::Address& destination,
                                  unsigned index, uint8_t hops, uint8_t traffic_class) {
    if (socket->receive_packet_info) {
        struct PacketInfo {
            ip6::Address address;
            uint32_t index;
        } info{destination, index};

        static_assert(sizeof(info) == 20);
        append(50, &info, sizeof(info));
    }
    if (socket->receive_hops) {
        int value = hops;
        append(52, &value, sizeof(value));
    }
    if (socket->receive_traffic_class) {
        int value = traffic_class;
        append(67, &value, sizeof(value));
    }
}

size_t inet6_receive_control(Task& task, Inet6Socket* socket, const Inet6Frame& frame,
                             uint64_t address, uint64_t capacity, uint32_t& flags) {
    Inet6ControlWriter output(task, address, capacity, flags);
    output.metadata(socket, frame.destination, frame.index, frame.hops, frame.traffic_class);
    const auto* bytes = inet6_bytes(&frame) + frame.length;
    uint8_t protocol = frame.extension_protocol;
    for (size_t at = 0; at < frame.extension_length;) {
        if (frame.extension_length - at < 8 ||
            (protocol != 0 && protocol != 43 && protocol != 44 && protocol != 60))
            break;
        size_t length = protocol == 44 ? 8 : (size_t(bytes[at + 1]) + 1) * 8;
        if (length > frame.extension_length - at)
            break;
        if (protocol == 0 && socket->receive_hop_options)
            output.append(54, bytes + at, length);
        else if (protocol == 60 && socket->receive_destination_options)
            output.append(59, bytes + at, length);
        protocol = bytes[at];
        at += length;
    }
    return output.used;
}
} // namespace ax
