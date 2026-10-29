// SPDX-License-Identifier: GPL-3.0-or-later
// An empty IPv6 namespace for the isolated IPv4 netlink codec fixtures.
#include "net/netlink.hpp"
#include "net/ipv6/configuration.hpp"

namespace ax {
int netlink_link_change(const void*, const NetlinkHeader&) {
    return -95;
}

namespace ip6 {
int configuration_read(unsigned, ConfigurationKey key, int32_t& value) {
    if (key != ConfigurationKey::generation_mode)
        return -97;
    value = 0;
    return 0;
}
} // namespace ip6

const Ipv6Address* ipv6_address(unsigned) {
    return nullptr;
}

Ipv6AddressCacheInfo ipv6_address_cache(const Ipv6Address&) {
    return {0, 0, 0, 0};
}

int netlink_ipv6_address_change(const void*, const NetlinkHeader&) {
    return -97;
}

int netlink_ipv6_route(const void* data, const NetlinkHeader& request, uint32_t port, void* output,
                       size_t capacity, size_t& size, bool) {
    if (request.type != 26 || static_cast<const uint8_t*>(data)[16])
        return -97;
    if (capacity < 20)
        return -90;
    NetlinkHeader done{20, 3, 2, request.sequence, port};
    memcpy(output, &done, sizeof(done));
    memset(static_cast<uint8_t*>(output) + 16, 0, 4);
    size = 20;
    return 0;
}
} // namespace ax
