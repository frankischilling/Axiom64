// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/io/packet.hpp
 * @brief   Packet I/O preparation and completion.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Captures packet destinations, ancillary data, and queued receive results.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once

#include "request.hpp"
#include "io/io.hpp"
#include "net/tcp/socket.hpp"
#include "security/credentials.hpp"

namespace ax::io_detail {
static int prepare_packet(Task& task, IoRequest& request) {
    const auto& f = request.call;
    if (request.handle->inet && !inet_payload(request.handle->inet))
        return -95;
    if (request.accept)
        return -95;
    if (request.positioned)
        return -29;
    unsigned allowed = request.write ? 0x4040 : 2 | 0x20 | 0x40;
    if (!request.write && request.handle->netlink)
        allowed |= 0x4100; // Netlink datagrams ignore MSG_WAITALL and MSG_NOSIGNAL.
    if (request.write && (inet_udp(request.handle->inet) || inet6_udp(request.handle->inet6)))
        allowed |= 0x8000; // MSG_MORE
    if (request.write && request.handle->inet && inet_header_included(request.handle->inet))
        allowed |= 0x8010; // Header-included output accepts MSG_MORE and MSG_PROBE.
    if (request.flags & ~allowed)
        return -95;
    if (request.write && request.handle->packet)
        request.destination_index = packet_interface(request.handle->packet);
    if (request.write && request.handle->inet)
        request.inet_destination = inet_peer(request.handle->inet);
    if (request.write && request.handle->inet6)
        request.inet6_destination = inet6_peer(request.handle->inet6);
    uint64_t address = f.rax == 44 ? f.r8 : 0;
    uint64_t address_length = f.rax == 44 ? f.r9 : 0;
    uint64_t control_pointer = 0, control_length = 0;
    bool inet_address_copied = false;
    if (f.rax == 19 || f.rax == 20) {
        int error = import_vectors(task, request, f.rsi, f.rdx);
        if (error)
            return error;
    } else if (f.rax == 46 || f.rax == 47) {
        Message message;
        if (!task.memory->space.copy_in(&message, f.rsi, sizeof(message)))
            return -14;
        if ((request.handle->inet6 || request.handle->inet) && message.name) {
            if (int32_t(message.name_length) < 0)
                return -22;
            message.name_length = min(message.name_length, uint32_t(128));
            if (request.write && !message.name_length)
                message.name = 0;
        }
        if (request.write && message.control_length) {
            if (!request.handle->inet6 && !request.handle->inet)
                return -95;
            control_pointer = message.control;
            control_length = message.control_length;
        }
        if (request.write) {
            address = message.name;
            address_length = message.name_length;
            if (request.handle->inet && address) {
                // sendmsg imports its bounded name before importing vectors.
                // Protocol address-length checks follow control-buffer copying.
                uint8_t bytes[128];
                if (address_length && !task.memory->space.copy_in(bytes, address, address_length))
                    return -14;
                request.inet_destination = {};
                memcpy(&request.inet_destination, bytes,
                       min(size_t(address_length), sizeof(InetAddress)));
                inet_address_copied = true;
            }
        } else {
            request.address_pointer = message.name;
            request.address_capacity = message.name_length;
            request.control_pointer = message.control;
            request.control_capacity = message.control_length;
        }
        int error = import_vectors(task, request, message.iov, message.iov_count);
        if (error)
            return error;
    } else {
        request.single = {f.rsi, min(f.rdx, uint64_t(0x7ffff000))};
        request.vectors = &request.single;
        request.count = 1;
    }
    for (size_t i = 0; i < request.count; i++) {
        const auto& vector = request.vectors[i];
        if (vector.base >= user_limit || vector.length > user_limit - vector.base)
            return -14;
    }
    if (request.write && address) {
        if (request.handle->netlink) {
            if (address_length < sizeof(NetlinkAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.netlink_destination, address,
                                            sizeof(NetlinkAddress)))
                return -14;
        } else if (request.handle->inet6) {
            uint32_t length = address_length;
            if (length > 128)
                return -22;
            uint8_t bytes[128];
            if (length && !task.memory->space.copy_in(bytes, address, length))
                return -14;
            request.inet6_destination = {};
            memcpy(&request.inet6_destination, bytes, min(size_t(length), sizeof(Inet6Address)));
            if (length < sizeof(Inet6Address))
                request.inet6_destination.scope = 0;
        } else if (request.handle->inet) {
            if (!inet_address_copied) {
                uint32_t length = address_length;
                if (length > 128)
                    return -22;
                uint8_t bytes[128];
                if (length && !task.memory->space.copy_in(bytes, address, length))
                    return -14;
                request.inet_destination = {};
                memcpy(&request.inet_destination, bytes, min(size_t(length), sizeof(InetAddress)));
            }
        } else {
            if (address_length < sizeof(PacketAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.destination, address, sizeof(PacketAddress)))
                return -14;
            if (request.destination.family != 17 || request.destination.length > 8)
                return -22;
            request.destination_index = request.destination.index;
        }
    }
    if (f.rax == 45 && f.r8) {
        request.address_pointer = f.r8;
        request.address_length_pointer = f.r9;
        if (!request.handle->inet6 && !request.handle->inet &&
            !task.memory->space.copy_in(&request.address_capacity, f.r9, 4))
            return -14;
    }
    if (request.write && request.handle->inet6) {
        // Import the complete control buffer after vectors and address bytes,
        // before protocol-specific destination and control validation.
        if (int error = inet6_capture_control(task, control_pointer, control_length,
                                              request.send_control_data))
            return error;
    } else if (request.write && request.handle->inet) {
        if (int error = inet_capture_send_control(task, control_pointer, control_length,
                                                  request.send_control_data))
            return error;
    }
    for (size_t i = 0; i < request.count; i++)
        request.packet_length += request.vectors[i].length;
    if (!request.write)
        return 0;
    if (request.handle->netlink) {
        if (int error = netlink_target(request.netlink_destination))
            return error;
        if (request.packet_length > netlink_max_request)
            return -90;
    } else if (request.handle->inet6) {
        request.inet_destination_named = address != 0;
        int error = inet6_target(request.handle->inet6, request.inet6_destination,
                                 request.inet_destination_named, uint32_t(address_length));
        if (error)
            return error;
    } else if (request.handle->inet) {
        request.inet_destination_named = address != 0;
        int error = inet_prepare_send(
            request.handle->inet, request.inet_destination, request.inet_destination_named,
            uint32_t(address_length), request.packet_length, request.send_control_data,
            control_length, request.inet_output, capable(task.credentials, Capability::net_raw));
        if (error)
            return error;
        request.inet_output.probe = request.flags & 0x10;
        release(request.send_control_data);
        request.send_control_data = nullptr;
    } else {
        if (!request.destination_index || !net_info(request.destination_index))
            return -6;
        if (request.packet_length > max_ethernet_frame)
            return -90;
        if (request.packet_length < ethernet_header)
            return -22;
    }
    if (request.handle->inet6) {
        int error = inet6_parse_send_control(
            request.handle->inet6, request.inet6_destination, request.send_control_data,
            control_length, request.inet6_output, capable(task.credentials, Capability::net_raw));
        if (error)
            return error;
        // Sticky views can change through another alias while output waits.
        // Keep only immutable selected bytes through request teardown.
        if (int error = inet6_own_send_extensions(request.inet6_output, request.send_control_data))
            return error;
    }
    size_t prefix = request.handle->inet6 ? inet6_send_prefix(request.handle->inet6)
                    : request.handle->inet
                        ? inet_send_prefix(request.handle->inet, &request.inet_output)
                        : 0;
    if (request.packet_length < prefix)
        return -14;
    uint8_t protocol_bytes[2];
    if (prefix) {
        // Import raw protocol bytes before routing and length admission.
        if (int error = copy_packet(task, request, 0, prefix, protocol_bytes))
            return error;
    }
    if (request.handle->inet6) {
        if (int error = inet6_send_admit(request.handle->inet6, request.inet6_destination,
                                         request.packet_length, prefix ? protocol_bytes : nullptr,
                                         request.inet_destination_named, &request.inet6_output))
            return error;
    } else if (request.handle->inet) {
        if (int error = inet_send_admit(request.handle->inet, request.inet_destination,
                                        request.packet_length, request.inet_output))
            return error;
        // Route and ancillary input precede the socket-memory wait. User
        // payload is read after space becomes available, including raw bytes
        // that were inspected above only for protocol admission.
        return 0;
    }
    if (request.packet_length) {
        request.packet_data = static_cast<uint8_t*>(alloc(request.packet_length));
        if (!request.packet_data)
            return -12;
    }
    if (prefix) {
        memcpy(request.packet_data, protocol_bytes, prefix);
    }
    return copy_packet(task, request, prefix, request.packet_length - prefix);
}

static int64_t packet_attempt(Task& task, IoRequest& request) {
    net_poll();
    const auto& f = request.call;
    if (request.write) {
        if (request.handle->netlink)
            return netlink_send(task, request.handle->netlink, request.packet_data,
                                request.packet_length);
        if (request.handle->inet) {
            if (request.inet_output.header_included && request.inet_output.probe)
                return int64_t(request.packet_length);
            if (!request.packet_ready) {
                if (int error = inet_send_ready(request.handle->inet, request.packet_length,
                                                &request.inet_output))
                    return error;
                if (request.packet_length) {
                    request.packet_data = static_cast<uint8_t*>(alloc(request.packet_length));
                    if (!request.packet_data)
                        return -12;
                }
                if (int error = copy_packet(task, request, 0, request.packet_length))
                    return error;
                request.packet_ready = true;
            }
            return inet_send(request.handle->inet, request.inet_destination, request.packet_data,
                             request.packet_length, request.inet_destination_named,
                             &request.inet_output, request.flags & 0x8000);
        }
        if (request.handle->inet6)
            return inet6_send(request.handle->inet6, request.inet6_destination, request.packet_data,
                              request.packet_length, request.inet_destination_named,
                              &request.inet6_output, request.flags & 0x8000);
        int result = net_send(request.destination_index, request.packet_data, request.packet_length,
                              request.handle->packet);
        return result ? result : int64_t(request.packet_length);
    }
    if (!request.socket && !request.packet_length)
        return 0;
    if (request.handle->inet)
        if (int error = inet_error(request.handle->inet, true))
            return -error;
    if (request.handle->inet6)
        if (int error = inet6_error(request.handle->inet6, true))
            return -error;
    if (request.handle->netlink)
        if (int error = netlink_error(request.handle->netlink, true))
            return -error;
    auto frame = request.handle->packet ? packet_front(request.handle->packet) : nullptr;
    auto ip = request.handle->inet ? inet_front(request.handle->inet) : nullptr;
    auto ip6 = request.handle->inet6 ? inet6_front(request.handle->inet6) : nullptr;
    auto nl = request.handle->netlink ? netlink_front(request.handle->netlink) : nullptr;
    if (!frame && !ip && !ip6 && !nl) {
        if (request.handle->netlink)
            return -11;
        if (request.handle->inet6) {
            int error = inet6_error(request.handle->inet6, true);
            bool blocking = !(request.handle->flags & 04000) && !(request.flags & 0x40);
            return error                                                     ? -error
                   : blocking && (inet6_shutdown(request.handle->inet6) & 1) ? 0
                                                                             : -11;
        }
        if (request.handle->inet) {
            int error = inet_error(request.handle->inet, true);
            bool blocking = !(request.handle->flags & 04000) && !(request.flags & 0x40);
            return error ? -error : blocking && (inet_shutdown(request.handle->inet) & 1) ? 0 : -11;
        }
        auto info = net_info(packet_interface(request.handle->packet));
        return info && !info->live ? -5 : -11;
    }
    size_t length = nl ? nl->length : ip ? ip->length : ip6 ? ip6->length : frame->length;
    const auto bytes = nl    ? netlink_bytes(nl)
                       : ip  ? inet_bytes(ip)
                       : ip6 ? inet6_bytes(ip6)
                             : packet_bytes(frame);
    const void* source = nl    ? static_cast<const void*>(&nl->source)
                         : ip  ? static_cast<const void*>(&ip->source)
                         : ip6 ? static_cast<const void*>(&ip6->source)
                               : &frame->source;
    const auto copy_fault = [&request](int error = -14) -> int64_t {
        // Linux raw Internet receives dequeue even when a non-peek copy faults.
        if (request.handle->inet && !(request.flags & 2))
            inet_consume(request.handle->inet);
        if (request.handle->inet6 && !(request.flags & 2))
            inet6_consume(request.handle->inet6);
        if (request.handle->netlink && !(request.flags & 2))
            netlink_consume(request.handle->netlink);
        return error;
    };
    size_t remaining = min(length, request.packet_length), at = 0;
    for (size_t i = 0; i < request.count && remaining; i++) {
        const auto& vector = request.vectors[i];
        size_t count = min(remaining, size_t(vector.length));
        if (count && !copy_packet_output(task, vector.base, bytes + at, count))
            return copy_fault();
        at += count;
        remaining -= count;
    }
    if (frame)
        packet_observed(request.handle->packet, *frame);
    uint32_t actual_address = nl    ? sizeof(NetlinkAddress)
                              : ip  ? sizeof(InetAddress)
                              : ip6 ? sizeof(Inet6Address)
                                    : sizeof(PacketAddress);
    if ((ip || ip6) && f.rax == 45 && request.address_pointer) {
        if (!task.memory->space.copy_in(&request.address_capacity, request.address_length_pointer,
                                        4))
            return copy_fault();
        if (int32_t(request.address_capacity) < 0)
            return copy_fault(-22);
    }
    uint32_t message_flags = length > request.packet_length ? 0x20 : 0;
    uint64_t control_length = 0;
    if (f.rax == 47) {
        if (nl)
            control_length =
                netlink_receive_control(task, request.handle->netlink, request.control_pointer,
                                        request.control_capacity, message_flags);
        else if (ip)
            control_length =
                inet_receive_control(task, request.handle->inet, *ip, request.control_pointer,
                                     request.control_capacity, message_flags);
        else if (ip6)
            control_length =
                inet6_receive_control(task, request.handle->inet6, *ip6, request.control_pointer,
                                      request.control_capacity, message_flags);
    }
    if ((ip || ip6) && request.address_pointer) {
        // Linux stores the full source length before copying any address bytes.
        uint64_t length_pointer =
            f.rax == 47 ? f.rsi + offsetof(Message, name_length) : request.address_length_pointer;
        if (!task.memory->space.copy_out(length_pointer, &actual_address, 4))
            return copy_fault();
    }
    if (request.address_pointer &&
        (!copy_packet_output(task, request.address_pointer, source,
                             min(request.address_capacity, actual_address)) ||
         (!ip && !ip6 && request.address_length_pointer &&
          !task.memory->space.copy_out(request.address_length_pointer, &actual_address, 4))))
        return copy_fault();
    if (f.rax == 47) {
        uint32_t address_length = request.address_pointer ? actual_address : 0;
        // A NULL Internet source-name pointer leaves the caller's length untouched.
        if ((!ip && !ip6 &&
             !task.memory->space.copy_out(f.rsi + offsetof(Message, name_length), &address_length,
                                          4)) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, flags), &message_flags, 4) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, control_length), &control_length,
                                         8))
            return copy_fault();
    }
    int64_t result = request.flags & 0x20 ? length : at;
    if (!(request.flags & 2)) {
        if (request.handle->netlink)
            netlink_consume(request.handle->netlink);
        else if (request.handle->inet)
            inet_consume(request.handle->inet);
        else if (request.handle->inet6)
            inet6_consume(request.handle->inet6);
        else
            packet_consume(request.handle->packet);
    }
    return result;
}
} // namespace ax::io_detail
