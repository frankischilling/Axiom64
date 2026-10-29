// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"

namespace ax {
namespace {
constexpr unsigned kinds[] = {54, 55, 57, 59};

bool slot(ip6::OutputExtensions& options, unsigned kind, const uint8_t**& data, size_t*& length) {
    switch (kind) {
    case 54:
        data = &options.hop;
        length = &options.hop_length;
        return true;
    case 55:
        data = &options.before_routing;
        length = &options.before_routing_length;
        return true;
    case 57:
        data = &options.routing;
        length = &options.routing_length;
        return true;
    case 59:
        data = &options.destination;
        length = &options.destination_length;
        return true;
    default:
        return false;
    }
}
} // namespace

const uint8_t* inet6_extension_get(const Inet6Socket* socket, unsigned kind, size_t& length) {
    auto options = socket->extensions;
    const uint8_t** data;
    size_t* size;
    length = 0;
    if (!slot(options, kind, data, size))
        return nullptr;
    length = *size;
    return *data;
}

int inet6_extension_set(Inet6Socket* socket, unsigned kind, const uint8_t* input, size_t size) {
    const uint8_t** data;
    size_t* length;
    if (!slot(socket->extensions, kind, data, length))
        return -92;
    size_t actual = 0;
    uint8_t* bytes = nullptr;
    if (size) {
        if (!input || size < 8 || size > 2040 || size % 8)
            return -22;
        actual = (size_t(input[1]) + 1) * 8;
        if (actual > size || (kind == 57 && (!ip6::valid_output_routing(input, actual) ||
                                             (input[2] == 4 && actual != size))))
            return -22;
        bytes = static_cast<uint8_t*>(alloc(actual));
        if (!bytes)
            return -105;
        memcpy(bytes, input, actual);
    }
    release(const_cast<uint8_t*>(*data));
    *data = bytes;
    *length = actual;
    ipv6_destination_clear(socket->destination);
    return 0;
}

void inet6_extensions_clear(Inet6Socket* socket) {
    for (unsigned kind : kinds) {
        const uint8_t** data = nullptr;
        size_t* length = nullptr;
        if (!slot(socket->extensions, kind, data, length))
            continue;
        release(const_cast<uint8_t*>(*data));
        *data = nullptr;
        *length = 0;
    }
}

int inet6_own_send_extensions(Inet6SendControl& control, uint8_t*& request) {
    auto selected = control.extensions;
    if (ip6::output_extension_size(selected) < 0)
        return -22;
    size_t size = selected.hop_length + selected.before_routing_length + selected.routing_length +
                  selected.destination_length;
    auto bytes = size ? static_cast<uint8_t*>(alloc(size)) : nullptr;
    if (size && !bytes)
        return -105;
    size_t at = 0;
    for (unsigned kind : kinds) {
        const uint8_t** data = nullptr;
        size_t* length = nullptr;
        if (!slot(selected, kind, data, length))
            continue;
        if (*length) {
            memcpy(bytes + at, *data, *length);
            *data = bytes + at;
            at += *length;
        } else {
            *data = nullptr;
        }
    }
    release(request);
    request = bytes;
    control.extensions = selected;
    return 0;
}
} // namespace ax
