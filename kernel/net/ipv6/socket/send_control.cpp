// SPDX-License-Identifier: GPL-3.0-or-later
#include "../socket.hpp"
#include "process/task.hpp"

namespace ax {
int inet6_capture_control(Task& task, uint64_t pointer, uint64_t length, uint8_t*& bytes) {
    if (!length)
        return 0;
    // Match the native option-memory admission boundary before reading bytes.
    if (length >= 131072)
        return -105;
    bytes = static_cast<uint8_t*>(alloc(length));
    if (!bytes)
        return -105;
    return task.memory->space.copy_in(bytes, pointer, length) ? 0 : -14;
}

int inet6_parse_send_control(const Inet6Socket* socket, const Inet6Address& destination,
                             const uint8_t* bytes, size_t length, Inet6SendControl& result) {
    result = inet6_send_defaults(socket, destination);
    result.present = length != 0;

    struct Header {
        uint64_t length;
        uint32_t level, type;
    };

    static_assert(sizeof(Header) == 16);
    for (size_t at = 0; at <= length && length - at >= sizeof(Header);) {
        Header header;
        memcpy(&header, bytes + at, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - at)
            return -22;
        const auto* data = bytes + at + sizeof(header);
        if (header.level == 1) {
            // These messages have Unix-domain meaning and are ignored here.
            if (header.type != 1 && header.type != 2)
                return -22;
        } else if (header.level == 41) {
            if (header.type == 50 || header.type == 2) {
                struct Info {
                    ip6::Address source;
                    uint32_t index;
                };

                static_assert(sizeof(Info) == 20);
                if (header.length < sizeof(Header) + sizeof(Info))
                    return -22;
                Info info;
                memcpy(&info, data, sizeof(info));
                if (info.index) {
                    if (result.index && info.index != result.index)
                        return -22;
                    result.index = info.index;
                }
                if (result.index && result.index != ipv6_loopback && !net_info(result.index))
                    return -19;
                if (info.source.link_local() && !result.index)
                    return -22;
                if (!info.source.unspecified()) {
                    if (!ipv6_owned(
                            info.source.link_local() || info.source.loopback() ? result.index : 0,
                            info.source))
                        return -22;
                    result.source = info.source;
                }
            } else if (header.type == 52 || header.type == 8 || header.type == 67 ||
                       header.type == 62) {
                if (header.length != sizeof(Header) + sizeof(int))
                    return -22;
                int value;
                memcpy(&value, data, sizeof(value));
                if (header.type == 62) {
                    if (value < 0 || value > 1)
                        return -22;
                    result.dont_fragment = value != 0;
                } else {
                    if (value < -1 || value > 255)
                        return -22;
                    if (header.type == 67)
                        result.traffic_class = uint8_t(value);
                    else
                        result.hops = value < 0 ? socket->hops : value;
                }
            } else
                return -22;
        }
        // A final partial alignment tail is not another control header.
        at += (header.length + 7) & ~size_t(7);
    }
    return 0;
}
} // namespace ax
