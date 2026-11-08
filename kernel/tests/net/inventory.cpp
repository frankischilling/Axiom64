// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include "net/netlink.hpp"
#include "net/ipv6/configuration.hpp"

using namespace ax;

static void require(bool condition, const char* operation) {
    if (!condition) {
        std::fprintf(stderr, "NETLINK_INVENTORY_CODEC_FAIL %s\n", operation);
        std::exit(1);
    }
}

namespace ax {
const NetInfo* net_info(unsigned index) {
    static NetInfo information[max_net_devices];
    if (!index || index > max_net_devices)
        return nullptr;
    auto& value = information[index - 1];
    value.index = index;
    std::snprintf(value.name, sizeof(value.name), "eth%u", index - 1);
    memset(value.mac, uint8_t(index), sizeof(value.mac));
    value.administrative = index % 2;
    value.carrier = value.live = index % 3;
    return &value;
}

const Ipv4Address* ipv4_address(unsigned position) {
    if (position > ipv4_address_capacity)
        return nullptr;
    static Ipv4Address value;
    value = {};
    if (position == ipv4_address_capacity) {
        value.config = {0x7f000001, 0xff000000, 0};
        value.index = ipv4_loopback;
        memcpy(value.label, "lo", 3);
    } else {
        value.index = position % max_net_devices + 1;
        value.secondary = position >= max_net_devices;
        value.config = {0x0a000002 + (value.index << 8) + position / max_net_devices, 0xffffff00,
                        0x0a0000ff + (value.index << 8)};
        memcpy(value.label, "alias-label-001", 16);
        value.flags = position & 1 ? 0x20 : 0;
    }
    return &value;
}

Ipv4AddressCacheInfo ipv4_address_cache(const Ipv4Address& value) {
    return {value.index, value.index + 8, 0x12345678, 0x87654321};
}

const Ipv6Address* ipv6_address(unsigned position) {
    if (position > ipv6_address_capacity)
        return nullptr;
    static Ipv6Address value;
    value = {};
    value.index =
        position == ipv6_address_capacity ? ipv6_loopback : position % max_net_devices + 1;
    value.address.bytes[0] = 0x20;
    value.address.bytes[1] = 1;
    value.address.bytes[15] = uint8_t(position + 1);
    return &value;
}

Ipv6AddressCacheInfo ipv6_address_cache(const Ipv6Address&) {
    return {3, 9, 0xabcdef01, 0x10203040};
}

namespace ip6 {
int configuration_read(unsigned, ConfigurationKey key, int32_t& value) {
    if (key != ConfigurationKey::generation_mode)
        return -97;
    value = 0;
    return 0;
}
} // namespace ip6
} // namespace ax

static void address_attributes(const uint8_t* record, size_t length) {
    const bool inet6 = record[16] == 10;
    require(record[16] == 2 || inet6, "address family");
    uint32_t index;
    memcpy(&index, record + 20, 4);
    unsigned seen = 0;
    for (size_t at = 24; at < length;) {
        uint16_t size, type;
        require(length - at >= 4, "complete address attribute header");
        memcpy(&size, record + at, 2);
        memcpy(&type, record + at + 2, 2);
        require(size >= 4 && size <= length - at && type <= 8 && !(seen & (1u << type)),
                "unique bounded address attributes");
        seen |= 1u << type;
        if (type == 6) {
            require(size == 20, "complete cache information");
            uint32_t fields[4];
            memcpy(fields, record + at + 4, sizeof(fields));
            require(fields[0] == (inet6 ? 3 : index) && fields[1] == (inet6 ? 9 : index + 8) &&
                        fields[2] == (inet6 ? 0xabcdef01 : 0x12345678) &&
                        fields[3] == (inet6 ? 0x10203040 : 0x87654321),
                    "cache countdown and owned creation/update stamps survive serialization");
        } else if (type == 8) {
            uint32_t flags;
            require(size == 8, "complete address flags");
            memcpy(&flags, record + at + 4, 4);
            require(flags == record[18], "header and extended flags agree");
            if (!inet6 && index != ipv4_loopback)
                require(!(flags & 0x80), "finite addresses are not permanent");
        }
        at += (size + 3u) & ~3u;
        require(at <= length, "aligned attribute fits record");
    }
    require((seen & ((1u << 1) | (1u << 6) | (1u << 8))) == ((1u << 1) | (1u << 6) | (1u << 8)),
            "every address exports address, cache information and flags");
}

static int evaluate(const uint8_t* packet, bool strict, unsigned* records = nullptr) {
    uint8_t output[netlink_max_reply + 16];
    memset(output, 0xa5, sizeof(output));
    NetlinkHeader request;
    memcpy(&request, packet, sizeof(request));
    size_t size = 0;
    int error = netlink_inventory_reply(packet, request, 123, output, strict, size);
    size_t capacity =
        request.type == 22 && !packet[16] ? netlink_address_reply : netlink_family_reply;
    require(size <= capacity, "bounded reply size");
    for (size_t i = capacity; i < sizeof(output); i++)
        require(output[i] == 0xa5, "reply allocation canary");
    if (error) {
        require(!size, "failed parser preserves caller size");
        for (size_t i = 0; i < netlink_max_reply; i++)
            require(output[i] == 0xa5, "malformed input never publishes a partial reply");
        return error;
    }
    unsigned count = 0;
    for (size_t at = 0; at < size;) {
        NetlinkHeader header;
        require(size - at >= sizeof(header), "complete multipart header");
        memcpy(&header, output + at, sizeof(header));
        require(header.length >= sizeof(header) && header.length <= size - at &&
                    !(header.length % 4) && header.flags == 2 &&
                    header.sequence == request.sequence && header.port == 123,
                "bounded aligned multipart ownership");
        if (header.type == 3) {
            int status;
            memcpy(&status, output + at + sizeof(header), sizeof(status));
            require(header.length == 20 && at + header.length == size && !status,
                    "terminal completion and status");
        } else {
            require(header.type == (request.type == 18 ? 16 : 20) && header.length <= 128,
                    "supported inventory record and reserved bound");
            if (header.type == 20)
                address_attributes(output + at, header.length);
            count++;
        }
        at += header.length;
    }
    unsigned expected = request.type == 18 ? max_net_devices + 1
                        : packet[16] == 10 ? ipv6_address_capacity + 1
                        : packet[16] == 2  ? ipv4_address_capacity + 1
                                           : ipv4_address_capacity + ipv6_address_capacity + 2;
    require(size <=
                (request.type == 22 && !packet[16] ? netlink_address_reply : netlink_family_reply),
            "family-specific and combined reservations cover all records");
    if (request.type == 22 && !packet[16])
        require(size > netlink_family_reply, "maximum combined inventory exceeds the old bound");
    require(count == expected, "complete device/address inventory fits one reservation");
    if (records)
        *records = count;
    return 0;
}

int main() {
    uint8_t packet[128]{};
    unsigned cases = 0;
    for (uint16_t type : {uint16_t(18), uint16_t(22)}) {
        for (unsigned family : {0u, 2u, 10u, 17u}) {
            if (type == 22 && family == 17)
                continue;
            for (unsigned body : {1u, 4u, type == 18 ? 16u : 8u}) {
                memset(packet, 0, sizeof(packet));
                NetlinkHeader header{16 + body, type, 0x301, 456, 999};
                memcpy(packet, &header, sizeof(header));
                packet[16] = family;
                if (body == 4)
                    memset(packet + 17, 0xa5, 3);
                unsigned records = 0;
                require(!evaluate(packet, false, &records) &&
                            records == (type == 18     ? 9
                                        : family == 10 ? ipv6_address_capacity + 1
                                        : family == 2
                                            ? ipv4_address_capacity + 1
                                            : ipv4_address_capacity + ipv6_address_capacity + 2),
                        "valid compact and complete dumps");
                require(evaluate(packet, true) == (body == (type == 18 ? 16u : 8u) ? 0 : -22),
                        "strict dump requires the complete header");
                cases++;
            }
        }
    }
    uint32_t state = 0x357194ac;
    for (unsigned mutation = 0; mutation < 16000; mutation++) {
        for (auto& byte : packet) {
            state = state * 1664525 + 1013904223;
            byte = state >> 24;
        }
        NetlinkHeader header{16 + state % 65, uint16_t(state & 1 ? 18 : 22), 0x301, state, 17};
        memcpy(packet, &header, sizeof(header));
        (void)evaluate(packet, state & 2);
    }
    std::printf(
        "NETLINK_INVENTORY_CODEC_PASS valid=%u devices=9 mutations=16000 canaries=checked\n",
        cases);
}
