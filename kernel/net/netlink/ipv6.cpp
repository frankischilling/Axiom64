// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
struct Attribute {
    uint16_t length, type;
};

struct AddressHeader {
    uint8_t family, prefix, flags, scope;
    uint32_t index;
};

struct RouteHeader {
    uint8_t family, destination_length, source_length, tos;
    uint8_t table, protocol, scope, type;
    uint32_t flags;
};

static_assert(sizeof(AddressHeader) == 8 && sizeof(RouteHeader) == 12);
static_assert((ipv6_route_capacity + ipv6_address_capacity) * 120 +
                  (ipv6_address_capacity + 1) * 116 + 20 <=
              netlink_ipv6_route_reply);

class Writer {
  public:
    Writer(void* data, size_t limit) : bytes(static_cast<uint8_t*>(data)), capacity(limit) {
    }

    bool append(const void* data, size_t length) {
        if (length > capacity - size)
            return false;
        memcpy(bytes + size, data, length);
        size += length;
        return true;
    }

    bool attribute(uint16_t type, const void* data, size_t length) {
        Attribute field{uint16_t(length + 4), type};
        uint32_t zero = 0;
        return append(&field, 4) && append(data, length) && append(&zero, (4 - length % 4) % 4);
    }

    void finish(size_t start, NetlinkHeader header) {
        header.length = size - start;
        memcpy(bytes + start, &header, sizeof(header));
    }

    size_t size = 0;

  private:
    uint8_t* bytes;
    size_t capacity;
};
} // namespace

int netlink_ipv6_address_change(const void* data, const NetlinkHeader& message) {
    if (message.length < sizeof(message) + sizeof(AddressHeader))
        return -22;
    const auto bytes = static_cast<const uint8_t*>(data);
    AddressHeader header;
    memcpy(&header, bytes + sizeof(message), sizeof(header));
    if (header.family != 10 || header.prefix > 128)
        return -22;
    if (header.scope != 0 && header.scope != 253)
        return -95;
    Ipv6Address value;
    Ipv6AddressLifetimes lifetime;
    value.index = header.index;
    value.prefix = header.prefix;
    value.flags = header.flags;
    bool present = false, local_present = false;
    ip6::Address local;
    uint32_t seen = 0;
    for (size_t at = sizeof(message) + sizeof(header); at < message.length;) {
        Attribute field;
        if (message.length - at < 4)
            return -22;
        memcpy(&field, bytes + at, 4);
        if (field.length < 4 || field.length > message.length - at || field.type > 8)
            return -22;
        if (seen & (1u << field.type))
            return -22;
        seen |= 1u << field.type;
        if (field.type == 1 || field.type == 2) {
            if (field.length != 20)
                return -22;
            memcpy(field.type == 1 ? value.address.bytes : local.bytes, bytes + at + 4, 16);
            present |= field.type == 1;
            local_present |= field.type == 2;
        } else if (field.type == 8) {
            if (field.length != 8)
                return -22;
            uint32_t flags;
            memcpy(&flags, bytes + at + 4, 4);
            if (flags & ~uint32_t(0x80 | 2 | 0x200))
                return -95;
            value.flags = flags;
        } else if (field.type == 6) {
            if (field.length < 20)
                return -34;
            memcpy(&lifetime, bytes + at + 4, sizeof(lifetime));
            if (message.type == 20 && (!lifetime.valid || lifetime.preferred > lifetime.valid))
                return -22;
        } else
            return -95;
        size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (aligned > message.length - at)
            return -22;
        at += aligned;
    }
    if (!present || (local_present && !(local == value.address)))
        return -22;
    if (message.type == 20) {
        return ipv6_address_add(value, lifetime,
                                (message.flags & 0x100) && !(message.flags & 0x200));
    }
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if (entry->index == value.index && entry->address == value.address &&
            entry->prefix == value.prefix)
            return ipv6_address_remove(value.index, value.address);
    return -99;
}

int netlink_ipv6_route(const void* data, const NetlinkHeader& message, uint32_t port, void* reply,
                       size_t capacity, size_t& size, bool strict) {
    bool dump = message.type == 26;
    if (message.length < sizeof(message) + 1)
        return -22;
    const auto bytes = static_cast<const uint8_t*>(data);
    RouteHeader header{};
    size_t body = message.length - sizeof(message);
    if (dump && body <= 4)
        header.family = bytes[sizeof(message)];
    else if (body >= sizeof(header))
        memcpy(&header, bytes + sizeof(message), sizeof(header));
    else
        return -22;
    if (header.family != 10 && !(dump && !header.family))
        return -97;
    if (dump && !strict) {
        if (header.flags & 0x800)
            return -95;
        uint8_t family = header.family;
        header = {};
        header.family = family;
    }
    if (header.destination_length > 128)
        return -22;
    if (header.source_length || header.tos || header.flags ||
        (header.table && header.table != 254 && !(dump && header.table == 255)) ||
        (header.type && header.type != 1 && !(dump && header.type == 2)) ||
        (header.scope && header.scope != 253 && header.scope != 255))
        return -95;
    if (dump && (header.destination_length || header.scope))
        return -22;
    Ipv6Route route;
    route.prefix = header.destination_length;
    route.protocol = header.protocol;
    uint32_t seen = 0;
    for (size_t at = dump && !strict ? message.length : sizeof(message) + sizeof(header);
         at < message.length;) {
        Attribute field;
        if (message.length - at < 4)
            return -22;
        memcpy(&field, bytes + at, 4);
        if (field.length < 4 || field.length > message.length - at || field.type >= 32 ||
            (seen & (1u << field.type)))
            return -22;
        seen |= 1u << field.type;
        if (field.type == 1 || field.type == 5) {
            if (field.length != 20)
                return -22;
            memcpy(field.type == 1 ? route.destination.bytes : route.gateway.bytes, bytes + at + 4,
                   16);
        } else if (field.type == 4 || field.type == 6 || field.type == 15) {
            if (field.length != 8)
                return -22;
            uint32_t value;
            memcpy(&value, bytes + at + 4, 4);
            if (field.type == 4)
                route.index = value;
            else if (field.type == 6)
                route.metric = value;
            else {
                if (value != 254 && !(dump && (value == 0 || value == 255)))
                    return -95;
                header.table = value;
            }
        } else
            return -95;
        size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (aligned > message.length - at)
            return -22;
        at += aligned;
    }
    if (!dump) {
        if (!route.index || (route.prefix && !(seen & 2)))
            return -22;
        if (message.type == 24 && (message.flags & 0x600) != 0x600)
            return -95;
        if (message.type == 25 && !(seen & (1u << 6)))
            route.metric = 0;
        return ipv6_route_control(route, message.type == 25, message.flags & 0x200);
    }
    Writer output(reply, capacity);
    uint16_t flags = 2 | (header.table || header.protocol || header.type || route.index ? 0x20 : 0);
    Ipv6Route entries[ipv6_route_capacity + ipv6_address_capacity + 1];
    size_t count = ipv6_routes(entries, sizeof(entries) / sizeof(*entries));
    for (size_t n = 0; n < count; n++) {
        const auto& entry = entries[n];
        if (header.table == 255 || header.type == 2 || entry.index == ipv6_loopback ||
            (header.protocol && header.protocol != entry.protocol) ||
            (route.index && route.index != entry.index))
            continue;
        size_t start = output.size;
        NetlinkHeader response{0, 24, flags, message.sequence, port};
        RouteHeader value{10, entry.prefix, 0, 0, 254, entry.protocol, 0, 1, 0};
        uint32_t cache[8]{};
        if (entry.expires)
            cache[2] = entry.expires >= ticks ? uint32_t(entry.expires - ticks)
                                              : 0u - uint32_t(ticks - entry.expires);
        if (!output.append(&response, sizeof(response)) || !output.append(&value, sizeof(value)) ||
            (entry.prefix && !output.attribute(1, entry.destination.bytes, 16)) ||
            (!entry.gateway.unspecified() && !output.attribute(5, entry.gateway.bytes, 16)) ||
            !output.attribute(4, &entry.index, 4) || !output.attribute(6, &entry.metric, 4) ||
            !output.attribute(12, cache, sizeof(cache)))
            return -90;
        output.finish(start, response);
    }
    if (header.table != 254 && header.type != 1 && (!header.protocol || header.protocol == 2)) {
        for (unsigned n = 0; auto entry = ipv6_address(n); n++) {
            if ((route.index && route.index != entry->index) ||
                !ipv6_owned(entry->index, entry->address))
                continue;
            size_t start = output.size;
            NetlinkHeader response{0, 24, flags, message.sequence, port};
            RouteHeader value{10, 128, 0, 0, 255, 2, 0, 2, 0};
            uint32_t table = 255, metric = 0, cache[8]{};
            uint8_t preference = 0;
            if (!output.append(&response, sizeof(response)) ||
                !output.append(&value, sizeof(value)) || !output.attribute(15, &table, 4) ||
                !output.attribute(1, entry->address.bytes, 16) ||
                !output.attribute(6, &metric, 4) || !output.attribute(4, &entry->index, 4) ||
                !output.attribute(12, cache, sizeof(cache)) ||
                !output.attribute(20, &preference, 1))
                return -90;
            output.finish(start, response);
        }
    }
    NetlinkHeader done{20, 3, 2, message.sequence, port};
    int status = 0;
    if (!output.append(&done, sizeof(done)) || !output.append(&status, 4))
        return -90;
    size = output.size;
    return 0;
}
} // namespace ax
