// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"

namespace ax {
namespace {
struct RouteHeader {
    uint8_t family, destination_length, source_length, tos;
    uint8_t table, protocol, scope, type;
    uint32_t flags;
};

struct Attribute {
    uint16_t length, type;
};

static_assert(sizeof(RouteHeader) == 12 && sizeof(Attribute) == 4);

size_t aligned(size_t size) {
    return (size + 3) & ~size_t(3);
}

unsigned prefix(uint32_t mask) {
    unsigned length = 0;
    while (mask & 0x80000000) {
        length++;
        mask <<= 1;
    }
    return length;
}

void attribute(uint8_t* output, size_t& size, unsigned type, uint32_t value) {
    Attribute header{8, uint16_t(type)};
    memcpy(output + size, &header, 4);
    memcpy(output + size + 4, &value, 4);
    size += 8;
}

int parse(const uint8_t* input, const NetlinkHeader& message, Ipv4Route& value, bool dump) {
    if (message.length < sizeof(message) + sizeof(RouteHeader))
        return -22;
    RouteHeader route;
    memcpy(&route, input + sizeof(message), sizeof(route));
    if (route.family != 2 && !(dump && !route.family))
        return -97;
    if (route.destination_length > 32)
        return -22;
    if (route.source_length || route.tos || route.flags)
        return -95;
    if ((route.table && route.table != 254) || (route.type && route.type != 1))
        return -95;
    if (dump && (route.destination_length || route.scope))
        return -22;
    if (!dump && route.scope != 0 && route.scope != 253 && route.scope != 255)
        return -95;
    value = {};
    value.mask = route.destination_length ? UINT32_MAX << (32 - route.destination_length) : 0;
    value.protocol = route.protocol;
    value.scope = route.scope;
    uint32_t seen = 0;
    size_t at = sizeof(message) + sizeof(route);
    while (at < message.length) {
        if (message.length - at < sizeof(Attribute))
            return -22;
        Attribute field;
        memcpy(&field, input + at, sizeof(field));
        if (field.length != 8 || field.length > message.length - at)
            return -22;
        if (field.type != 1 && field.type != 4 && field.type != 5 && field.type != 6 &&
            field.type != 15)
            return -95;
        if ((dump && field.type != 4 && field.type != 15) || (seen & (1u << field.type)))
            return -22;
        seen |= 1u << field.type;
        uint32_t number;
        memcpy(&number, input + at + 4, 4);
        if (field.type == 1)
            value.destination = __builtin_bswap32(number);
        else if (field.type == 4)
            value.index = number;
        else if (field.type == 5)
            value.gateway = __builtin_bswap32(number);
        else if (field.type == 6)
            value.metric = number;
        else if (number != 254)
            return -95;
        at += aligned(field.length);
    }
    if (value.index && (!net_info(value.index) || value.index > max_net_devices))
        return -19;
    if ((value.destination & value.mask) != value.destination)
        return -22;
    if (message.type == 24) {
        if (!(message.flags & 0x400) || !(message.flags & 0x200))
            return -95;
        if (!value.index || !route.type || (value.gateway ? value.scope != 0 : value.scope != 253))
            return -22;
        if (!value.protocol)
            value.protocol = 3;
    }
    return 0;
}

size_t dump(const NetlinkHeader& request, uint32_t port, const Ipv4Route& filter, uint8_t* output) {
    Ipv4Route routes[32 + max_net_devices + 1];
    size_t count = ipv4_routes(routes, sizeof(routes) / sizeof(routes[0])), size = 0;
    for (size_t i = 0; i < count; i++) {
        const auto& value = routes[i];
        if ((filter.index && value.index != filter.index) ||
            (filter.protocol && value.protocol != filter.protocol))
            continue;
        size_t start = size;
        NetlinkHeader header{0, 24, 2, request.sequence, port};
        RouteHeader route{2, uint8_t(prefix(value.mask)), 0, 0, 254, value.protocol, value.scope, 1,
                          0};
        memcpy(output + size, &header, sizeof(header));
        size += sizeof(header);
        memcpy(output + size, &route, sizeof(route));
        size += sizeof(route);
        attribute(output, size, 15, 254);
        if (value.mask)
            attribute(output, size, 1, __builtin_bswap32(value.destination));
        if (value.gateway)
            attribute(output, size, 5, __builtin_bswap32(value.gateway));
        if (value.metric)
            attribute(output, size, 6, value.metric);
        attribute(output, size, 4, value.index);
        header.length = size - start;
        memcpy(output + start, &header, sizeof(header));
    }
    NetlinkHeader done{20, 3, 2, request.sequence, port};
    int status = 0;
    memcpy(output + size, &done, sizeof(done));
    memcpy(output + size + sizeof(done), &status, 4);
    return size + done.length;
}
} // namespace

size_t routing_capacity(const NetlinkHeader& request) {
    return request.type == 26 ? netlink_max_reply : aligned(request.length) + 20;
}

size_t routing_reply(const void* packet, uint32_t port, bool capped, void* reply) {
    auto input = static_cast<const uint8_t*>(packet);
    auto output = static_cast<uint8_t*>(reply);
    NetlinkHeader request;
    memcpy(&request, input, sizeof(request));
    if (!(request.flags & 1) || request.type < 16)
        return 0;
    int error = -95;
    bool is_dump = request.type == 26;
    unsigned allowed = 1 | 4 | (is_dump ? 0x300 : request.type == 24 ? 0x600 : 0);
    Ipv4Route value;
    if ((request.type == 20 || request.type == 21) &&
        !(request.flags & ~(1u | 4u | (request.type == 20 ? 0x600u : 0u))))
        error = netlink_address_change(packet, request);
    else if ((request.type == 24 || request.type == 25 || is_dump) && !(request.flags & ~allowed)) {
        if (is_dump && (request.flags & 0x300) != 0x300)
            error = -95;
        else
            error = parse(input, request, value, is_dump);
        if (!error) {
            if (is_dump)
                return dump(request, port, value, output);
            error = ipv4_route_control(value, request.type == 25, request.flags & 0x200);
        }
    }
    if (!error && !(request.flags & 4))
        return 0;
    size_t echo = capped || !error ? sizeof(request) : request.length;
    NetlinkHeader header{uint32_t(20 + aligned(echo)), 2,
                         uint16_t(echo == sizeof(request) ? 0x100 : 0), request.sequence, port};
    memcpy(output, &header, sizeof(header));
    memcpy(output + sizeof(header), &error, 4);
    memcpy(output + 20, input, echo);
    memset(output + 20 + echo, 0, aligned(echo) - echo);
    return header.length;
}
} // namespace ax
