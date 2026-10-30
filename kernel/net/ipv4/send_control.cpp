// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"
#include "process/task.hpp"

namespace ax {
int inet_capture_send_control(Task& task, uint64_t pointer, uint64_t length, uint8_t*& bytes) {
    if (!length)
        return 0;
    if (length >= 131072)
        return -105;
    bytes = static_cast<uint8_t*>(alloc(length));
    if (!bytes)
        return -105;
    return task.memory->space.copy_in(bytes, pointer, length) ? 0 : -14;
}

int inet_prepare_send(InetSocket* socket, InetAddress& address, bool named, uint32_t address_length,
                      size_t payload_length, const uint8_t* bytes, size_t length,
                      InetSendControl& result, bool net_raw) {
    // Protocol dispatch owns automatic binding after generic address/vector and
    // control-buffer copying, before rejecting destination or control values.
    if (socket->type == 2 && !socket->local_port) {
        if (int error = inet_bind_port(socket, socket->local, 0))
            return error;
    }
    if (payload_length > 65535)
        return -90;
    if (named && address_length < sizeof(InetAddress))
        return -22;
    bool zero_destination = named && !address.address;
    InetAddress checked = address;
    if (zero_destination)
        checked.address = __builtin_bswap32(uint32_t(0x7f000001));
    if (int error = inet_target(socket, checked, named))
        return error;
    result = inet_send_defaults(socket, checked, named);

    struct Header {
        uint64_t length;
        uint32_t level, type;
    };

    static_assert(sizeof(Header) == 16);
    for (size_t at = 0; at <= length && length - at >= sizeof(Header);) {
        Header header;
        memcpy(&header, bytes + at, sizeof(header));
        if (header.length < sizeof(Header) || header.length > length - at)
            return -22;
        const auto* data = bytes + at + sizeof(Header);
        if (header.level == 17 && socket->type == 2) {
            if (header.type != 103 || header.length != sizeof(Header) + sizeof(uint16_t))
                return -22;
            uint16_t segment;
            memcpy(&segment, data, sizeof(segment));
            if (segment)
                return -95;
        } else {
            // A per-message IP lookup must not replace the description's
            // connected default route with its transient source or device.
            result.cache_destination = false;
            if (header.level == 1) {
                if (header.type != 1 && header.type != 2)
                    return -22;
            } else if (header.level == 0) {
                if (header.type == 8) {
                    struct Info {
                        uint32_t index, source, destination;
                    };

                    static_assert(sizeof(Info) == 12);
                    if (header.length != sizeof(Header) + sizeof(Info))
                        return -22;
                    Info info;
                    memcpy(&info, data, sizeof(info));
                    if (info.index)
                        result.index = info.index;
                    result.source = __builtin_bswap32(info.source);
                } else if (header.type == 1 || header.type == 2) {
                    int value;
                    if (header.length == sizeof(Header) + sizeof(int))
                        memcpy(&value, data, sizeof(value));
                    else if (header.type == 1 && header.length == sizeof(Header) + 1)
                        value = *data;
                    else
                        return -22;
                    if (value < (header.type == 2 ? 1 : 0) || value > 255)
                        return -22;
                    (header.type == 2 ? result.ttl : result.tos) = uint8_t(value);
                } else if (header.type == 7) {
                    ip4::OptionPolicy policy{net_raw, inet_option_unicast};
                    if (int error = result.options.assign(
                            data, min(size_t(40), size_t(header.length - sizeof(Header))), policy))
                        return error;
                } else
                    return -22;
            }
        }
        at += (header.length + 7) & ~size_t(7);
    }
    if (ip4::multicast(__builtin_bswap32(checked.address)) && !result.source.selected &&
        socket->multicast.output_address)
        result.source = socket->multicast.output_address;
    if (socket->type == 2 && result.cache_destination &&
        ipv4_destination_current(socket->destination))
        result.source = Ipv4Source::retained(socket->local);
    address = checked;
    if (zero_destination)
        address.address = 0;
    return 0;
}

size_t inet_send_prefix(const InetSocket* socket) {
    return socket->type == 3 && socket->protocol == 1 ? 2 : 0;
}

int inet_send_admit(InetSocket* socket, InetAddress& address, size_t length,
                    InetSendControl& control) {
    if (length > 65535)
        return -90;
    if (int error = inet_error(socket, true))
        return -error;
    if (socket->shutdown & 2)
        return -32;
    if (!address.address) {
        Ipv4Path path;
        int error = ipv4_path(control.source, 0, control.index, path);
        if (error)
            return error == -99 ? -101 : error;
        address.address = __builtin_bswap32(path.source);
        control.source = path.source;
        control.index = ipv4_loopback;
        control.cache_destination = false;
    }
    size_t transport = socket->type == 2 ? 8 : 0;
    if (int error =
            ipv4_send_admit(socket, control.source, __builtin_bswap32(address.address),
                            control.index, control.ttl, socket->broadcast, length + transport,
                            control.cache_destination, &control.route, &control.options))
        return error;
    // Queue pressure is handled by the retained I/O request after payload
    // import. This phase rejects only a packet that can never fit its limit.
    return length + transport + 20 + control.options.size() > socket->send_limit ? -90 : 0;
}
} // namespace ax
