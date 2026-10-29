// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/wire.hpp"
#include "core/base.hpp"

namespace ax::ip6 {
namespace {
bool valid(const uint8_t* bytes, size_t length) {
    return !length ||
           (bytes && length >= 8 && length <= 2048 && (size_t(bytes[1]) + 1) * 8 == length);
}
} // namespace

bool valid_segment_routing(const uint8_t* bytes, size_t length, bool reduced) {
    if (!valid(bytes, length) || length < 24 || bytes[2] != 4 ||
        unsigned(bytes[3]) > unsigned(bytes[4]) + unsigned(reduced))
        return false;
    size_t at = 8 + (size_t(bytes[4]) + 1) * 16;
    if (at > length)
        return false;
    while (at < length) {
        if (length - at < 2 || size_t(bytes[at + 1]) + 2 > length - at)
            return false;
        at += size_t(bytes[at + 1]) + 2;
    }
    return true;
}

bool valid_output_routing(const uint8_t* bytes, size_t length) {
    if (!length)
        return true;
    if (!valid(bytes, length))
        return false;
    return bytes[2] == 2 ? length == 24 && bytes[3] == 1
                         : valid_segment_routing(bytes, length, false);
}

int output_extension_size(const OutputExtensions& extensions) {
    if (!valid(extensions.hop, extensions.hop_length) ||
        !valid(extensions.destination, extensions.destination_length) ||
        !valid(extensions.before_routing, extensions.before_routing_length) ||
        !valid(extensions.routing, extensions.routing_length))
        return -22;
    if (!valid_output_routing(extensions.routing, extensions.routing_length))
        return -22;
    return int(extensions.hop_length + extensions.destination_length +
               (extensions.routing_length
                    ? extensions.routing_length + extensions.before_routing_length
                    : 0));
}

bool output_extension_destination(const OutputExtensions& extensions, const Address& final,
                                  Address& first) {
    if (output_extension_size(extensions) < 0)
        return false;
    first = final;
    if (extensions.routing_length) {
        size_t at = 8 + (extensions.routing[2] == 4 ? size_t(extensions.routing[3]) * 16 : 0);
        memcpy(first.bytes, extensions.routing + at, sizeof(first.bytes));
    }
    return true;
}

uint8_t output_next_header(uint8_t protocol, const OutputExtensions& extensions) {
    return extensions.hop_length           ? 0
           : extensions.routing_length     ? (extensions.before_routing_length ? 60 : 43)
           : extensions.destination_length ? 60
                                           : protocol;
}

bool encode_output_extensions(uint8_t* output, size_t capacity, uint8_t protocol,
                              const OutputExtensions& extensions, const Address* final) {
    int length = output_extension_size(extensions);
    if (length < 0 || size_t(length) > capacity || (length && !output) ||
        (extensions.routing_length && !final))
        return false;
    if (extensions.hop_length) {
        memcpy(output, extensions.hop, extensions.hop_length);
        output[0] = extensions.routing_length       ? (extensions.before_routing_length ? 60 : 43)
                    : extensions.destination_length ? 60
                                                    : protocol;
        output += extensions.hop_length;
    }
    if (extensions.routing_length) {
        if (extensions.before_routing_length) {
            memcpy(output, extensions.before_routing, extensions.before_routing_length);
            output[0] = 43;
            output += extensions.before_routing_length;
        }
        memcpy(output, extensions.routing, extensions.routing_length);
        output[0] = extensions.destination_length ? 60 : protocol;
        memcpy(output + 8, final->bytes, sizeof(final->bytes));
        output += extensions.routing_length;
    }
    if (extensions.destination_length) {
        memcpy(output, extensions.destination, extensions.destination_length);
        output[0] = protocol;
    }
    return true;
}

bool receive_extension_options(const Packet& packet, unsigned maximum_options) {
    const auto* bytes = packet.extensions;
    size_t size = packet.extension_length;
    if (size && !bytes)
        return false;
    uint8_t protocol = packet.header.next_header;
    for (size_t at = 0; at < size;) {
        if (size - at < 8 || (protocol != 0 && protocol != 43 && protocol != 44 && protocol != 60))
            return false;
        size_t length = protocol == 44 ? 8 : (size_t(bytes[at + 1]) + 1) * 8;
        if (length > size - at)
            return false;
        if (protocol == 0 || protocol == 60) {
            size_t padding = 0;
            unsigned count = 0;
            for (size_t option = at + 2; option < at + length;) {
                uint8_t type = bytes[option];
                if (!type) {
                    if (++padding > 7)
                        return false;
                    option++;
                    continue;
                }
                if (at + length - option < 2)
                    return false;
                size_t option_length = size_t(bytes[option + 1]) + 2;
                if (option_length > at + length - option)
                    return false;
                if (type == 1) {
                    padding += option_length;
                    if (padding > 7)
                        return false;
                    for (size_t n = option + 2; n < option + option_length; n++)
                        if (bytes[n])
                            return false;
                } else {
                    if (++count > maximum_options)
                        return false;
                    padding = 0;
                }
                option += option_length;
            }
        }
        protocol = bytes[at];
        at += length;
    }
    return true;
}

} // namespace ax::ip6
