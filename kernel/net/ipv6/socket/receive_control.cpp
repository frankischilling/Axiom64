// SPDX-License-Identifier: GPL-3.0-or-later
#include "receive_control.hpp"

namespace ax {

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

void Inet6ControlWriter::extensions(const Inet6Socket* socket, const uint8_t* bytes, size_t size,
                                    uint8_t protocol) {
    for (size_t at = 0; at < size;) {
        if (size - at < 8 || (protocol != 0 && protocol != 43 && protocol != 44 && protocol != 60))
            break;
        size_t length = protocol == 44 ? 8 : (size_t(bytes[at + 1]) + 1) * 8;
        if (length > size - at)
            break;
        if (protocol == 0 && socket->receive_hop_options)
            append(54, bytes + at, length);
        else if (protocol == 43 && socket->receive_routing)
            append(57, bytes + at, length);
        else if (protocol == 60 && socket->receive_destination_options)
            append(59, bytes + at, length);
        protocol = bytes[at];
        at += length;
    }
}

void Inet6ControlWriter::legacy_metadata(const Inet6Socket* socket, uint8_t hops) {
    if (socket->receive_legacy_hops) {
        int value = hops;
        append(8, &value, sizeof(value));
    }
}

size_t inet6_receive_control(Task& task, Inet6Socket* socket, const Inet6Frame& frame,
                             uint64_t address, uint64_t capacity, uint32_t& flags) {
    Inet6ControlWriter output(task, address, capacity, flags);
    output.metadata(socket, frame.destination, frame.index, frame.hops, frame.traffic_class);
    output.extensions(socket, inet6_bytes(&frame) + frame.length, frame.extension_length,
                      frame.extension_protocol);
    output.legacy_metadata(socket, frame.hops);
    return output.used;
}
} // namespace ax
