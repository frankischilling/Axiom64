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

struct AddressHeader {
    uint8_t family, prefix, flags, scope;
    uint32_t index;
};

struct Attribute {
    uint16_t length, type;
};

static_assert(sizeof(LinkHeader) == 16 && sizeof(AddressHeader) == 8);
static_assert((max_net_devices + 1) * 128 + 20 <= netlink_family_reply);
static_assert((ipv4_address_capacity + 1) * 76 + 20 <= netlink_family_reply);
static_assert((ipv4_address_capacity + 1) * 76 + (ipv6_address_capacity + 1) * 72 + 20 <=
              netlink_family_reply);

class Writer {
  public:
    explicit Writer(void* output) : bytes(static_cast<uint8_t*>(output)) {
    }

    bool append(const void* data, size_t length) {
        if (length > netlink_family_reply - size)
            return false;
        memcpy(bytes + size, data, length);
        size += length;
        return true;
    }

    bool attribute(unsigned type, const void* data, size_t length) {
        Attribute field{uint16_t(sizeof(Attribute) + length), uint16_t(type)};
        uint32_t padding = 0;
        return append(&field, sizeof(field)) && append(data, length) &&
               append(&padding, (4 - length % 4) % 4);
    }

    void finish(size_t start, NetlinkHeader header) {
        header.length = size - start;
        memcpy(bytes + start, &header, sizeof(header));
    }

    size_t size = 0;

  private:
    uint8_t* bytes;
};

unsigned prefix(uint32_t mask) {
    unsigned result = 0;
    while (mask & 0x80000000) {
        result++;
        mask <<= 1;
    }
    return result;
}

bool link(Writer& output, const NetlinkHeader& request, uint32_t port, const NetInfo& info,
          bool loopback, bool dump, bool inet6) {
    size_t start = output.size;
    NetlinkHeader message{0, 16, uint16_t(dump ? 2 : 0), request.sequence, port};
    uint32_t flags = loopback
                         ? 0x49
                         : 2 | 0x1000 | (info.administrative ? 1 : 0) |
                               (info.administrative && info.carrier && info.live ? 0x10040 : 0);
    uint32_t queue_length = 0; // There is no separate software transmit queue.
    LinkHeader header{uint8_t(inet6 ? 10 : 0), 0,     uint16_t(loopback ? 772 : 1),
                      int32_t(info.index),     flags, 0};
    uint8_t broadcast[6];
    memset(broadcast, loopback ? 0 : 0xff, sizeof(broadcast));
    uint8_t state = loopback ? 0 : info.administrative && info.carrier && info.live ? 6 : 2;
    if (!output.append(&message, sizeof(message)) || !output.append(&header, sizeof(header)) ||
        !output.attribute(3, info.name, strlen(info.name) + 1) ||
        !output.attribute(4, &info.mtu, sizeof(info.mtu)) ||
        !output.attribute(1, info.mac, sizeof(info.mac)) ||
        !output.attribute(2, broadcast, sizeof(broadcast)) ||
        !output.attribute(13, &queue_length, 4) || !output.attribute(16, &state, 1))
        return false;
    int32_t mode;
    if (ip6::configuration_read(info.index, ip6::ConfigurationKey::generation_mode, mode))
        return false;
    // AF_UNSPEC replies nest the IPv6 family inside IFLA_AF_SPEC. An IPv6
    // dump carries the same family attributes directly in IFLA_PROTINFO.
    uint8_t family[12]{12, 0, 10, 0, 5, 0, 8, 0, uint8_t(mode), 0, 0, 0};
    if (!(inet6 ? output.attribute(12, family + 4, 8) : output.attribute(26, family, 12)))
        return false;
    output.finish(start, message);
    return true;
}

bool address(Writer& output, const NetlinkHeader& request, uint32_t port, const NetInfo& info,
             const Ipv4Address& entry, bool loopback) {
    const auto& value = entry.config;
    size_t start = output.size;
    NetlinkHeader message{0, 20, 2, request.sequence, port};
    uint32_t flags = 0x80 | (entry.secondary ? 1 : 0);
    AddressHeader header{2, uint8_t(prefix(value.mask)), uint8_t(flags),
                         uint8_t(loopback ? 254 : 0), info.index};
    uint32_t local = __builtin_bswap32(value.address),
             broadcast = __builtin_bswap32(value.broadcast);
    if (!output.append(&message, sizeof(message)) || !output.append(&header, sizeof(header)) ||
        !output.attribute(1, &local, 4) || !output.attribute(2, &local, 4) ||
        !output.attribute(3, entry.label, strlen(entry.label) + 1) ||
        (!loopback && value.broadcast && !output.attribute(4, &broadcast, 4)) ||
        !output.attribute(8, &flags, 4))
        return false;
    output.finish(start, message);
    return true;
}

bool address6(Writer& output, const NetlinkHeader& request, uint32_t port,
              const Ipv6Address& entry) {
    size_t start = output.size;
    NetlinkHeader message{0, 20, 2, request.sequence, port};
    uint32_t flags = entry.flags;
    auto lifetime = ipv6_address_cache(entry);
    AddressHeader header{10, entry.prefix, uint8_t(flags),
                         uint8_t(entry.index == ipv6_loopback ? 254
                                 : entry.address.link_local() ? 253
                                                              : 0),
                         entry.index};
    if (!output.append(&message, sizeof(message)) || !output.append(&header, sizeof(header)) ||
        !output.attribute(1, entry.address.bytes, 16) || !output.attribute(8, &flags, 4) ||
        !output.attribute(6, &lifetime, sizeof(lifetime)))
        return false;
    output.finish(start, message);
    return true;
}
} // namespace

int netlink_inventory_reply(const void* data, const NetlinkHeader& request, uint32_t port,
                            void* reply, bool strict, size_t& size) {
    bool direct = request.type == 18 && !(request.flags & 0x300);
    if ((request.type != 18 && request.type != 22) || !(request.flags & 1) ||
        (!direct && (request.flags & 0x300) != 0x300) || (request.flags & ~(1 | 4 | 0x300)))
        return -95;
    if (request.length < sizeof(request))
        return -22;
    size_t body = request.length - sizeof(request);
    size_t complete = request.type == 18 ? sizeof(LinkHeader) : sizeof(AddressHeader);
    if (!body || (body > 4 && body != complete) || ((strict || direct) && body != complete))
        return -22;
    auto input = static_cast<const uint8_t*>(data) + sizeof(request);
    if (input[0] && input[0] != 2 && input[0] != 10 && !(request.type == 18 && input[0] == 17))
        return -97;
    int32_t selected = 0;
    if (direct) {
        memcpy(&selected, input + 4, sizeof(selected));
        if (selected <= 0)
            return -22;
        if (unsigned(selected) != ipv4_loopback && !net_info(unsigned(selected)))
            return -19;
    }
    // rtgenmsg contains only the family; legacy senders leave its alignment bytes uninitialized.
    for (size_t i = 1; body == complete && i < body; i++)
        if (input[i] && !(direct && i >= 4 && i < 8))
            return -22; // Filtered inventories and additional attributes remain unsupported.
    Writer output(reply);
    for (unsigned index = 1; index <= ipv4_loopback; index++) {
        bool loopback = index == ipv4_loopback;
        NetInfo lo;
        lo.index = index;
        memcpy(lo.name, "lo", 3);
        lo.mtu = 65536;
        auto info = loopback ? &lo : net_info(index);
        if (!info || (direct && index != unsigned(selected)))
            continue;
        if (request.type == 18) {
            if (!link(output, request, port, *info, loopback, !direct, !direct && input[0] == 10))
                return -90;
        } else if (input[0] != 10)
            for (unsigned n = 0; auto entry = ipv4_address(n); n++)
                if (entry->index == index &&
                    !address(output, request, port, *info, *entry, loopback))
                    return -90;
    }
    if (request.type == 22 && input[0] != 2)
        for (unsigned n = 0; auto entry = ipv6_address(n); n++)
            if (!address6(output, request, port, *entry))
                return -90;
    if (direct) {
        if (request.flags & 4) {
            NetlinkHeader acknowledgement{36, 2, 0x100, request.sequence, port};
            int status = 0;
            if (!output.append(&acknowledgement, sizeof(acknowledgement)) ||
                !output.append(&status, sizeof(status)) ||
                !output.append(&request, sizeof(request)))
                return -90;
        }
        size = output.size;
        return 0;
    }
    NetlinkHeader done{20, 3, 2, request.sequence, port};
    int status = 0;
    if (!output.append(&done, sizeof(done)) || !output.append(&status, sizeof(status)))
        return -90;
    size = output.size;
    return 0;
}
} // namespace ax
