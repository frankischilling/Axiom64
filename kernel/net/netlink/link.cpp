// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"
#include "net/ipv6/configuration.hpp"

namespace ax {
namespace {
struct LinkHeader {
    uint8_t family, padding;
    uint16_t type;
    int32_t index;
    uint32_t flags, change;
};

struct Attribute {
    uint16_t length, type;
};

// Capture the selected byte only after validating every enclosing attribute.
// The caller applies the resulting configuration once the whole request parses.
int generation_mode(const uint8_t* data, size_t size, int& mode) {
    mode = -1;
    for (size_t at = 0; at < size;) {
        Attribute field;
        if (size - at < sizeof(field))
            return -22;
        memcpy(&field, data + at, sizeof(field));
        if (field.length < sizeof(field) || field.length > size - at)
            return -22;
        unsigned type = field.type & 0x3fff;
        if (type == 8) { // IFLA_INET6_ADDR_GEN_MODE is an unsigned byte.
            if (field.length < sizeof(field) + 1)
                return -34;
            mode = data[at + sizeof(field)];
        } else if (type == 7)
            return -95; // Explicit interface tokens are not implemented.
        else if (type == 9)
            return -22; // IFLA_INET6_RA_MTU is read-only.
        size_t length = (size_t(field.length) + 3) & ~size_t(3);
        if (length > size - at)
            return -22;
        at += length;
    }
    return mode < 0 ? -22 : 0;
}

int ipv6_family(const uint8_t* data, size_t size, int& mode) {
    bool found = false;
    for (size_t at = 0; at < size;) {
        Attribute field;
        if (size - at < sizeof(field))
            return -22;
        memcpy(&field, data + at, sizeof(field));
        if (field.length < sizeof(field) || field.length > size - at)
            return -22;
        if ((field.type & 0x3fff) == 10) {
            int error =
                generation_mode(data + at + sizeof(field), field.length - sizeof(field), mode);
            if (error)
                return error;
            found = true;
        } else
            return -95;
        size_t length = (size_t(field.length) + 3) & ~size_t(3);
        if (length > size - at)
            return -22;
        at += length;
    }
    return found ? 0 : -22;
}
} // namespace

int netlink_link_change(const void* data, const NetlinkHeader& request) {
    if (request.type != 16 || (request.flags & ~(1u | 4u)))
        return -95;
    if (request.length < sizeof(request) + sizeof(LinkHeader))
        return -22;
    auto input = static_cast<const uint8_t*>(data);
    LinkHeader link;
    memcpy(&link, input + sizeof(request), sizeof(link));
    if (link.family && link.family != 10)
        return -97;
    if (link.padding || link.type || link.flags || link.change)
        return -95;
    if (link.index <= 0 ||
        (unsigned(link.index) != ipv6_loopback && !net_info(unsigned(link.index))))
        return -19;
    int mode = -1;
    bool found = false;
    for (size_t at = sizeof(request) + sizeof(link); at < request.length;) {
        Attribute field;
        if (request.length - at < sizeof(field))
            return -22;
        memcpy(&field, input + at, sizeof(field));
        if (field.length < sizeof(field) || field.length > request.length - at)
            return -22;
        if ((field.type & 0x3fff) != 26)
            return -95;
        int error = ipv6_family(input + at + sizeof(field), field.length - sizeof(field), mode);
        if (error)
            return error;
        found = true;
        size_t length = (size_t(field.length) + 3) & ~size_t(3);
        if (length > request.length - at)
            return -22;
        at += length;
    }
    if (!found)
        return -95;
    return ip6::configuration_write(unsigned(link.index), ip6::ConfigurationKey::generation_mode,
                                    mode, ip6::ConfigurationWrite::netlink);
}
} // namespace ax
