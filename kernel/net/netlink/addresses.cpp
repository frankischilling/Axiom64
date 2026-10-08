// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"
#include "net/ipv4_wire.hpp"

namespace ax {
namespace {
struct AddressHeader {
    uint8_t family, prefix, flags, scope;
    uint32_t index;
};

struct Attribute {
    uint16_t length, type;
};

static_assert(sizeof(AddressHeader) == 8 && sizeof(Attribute) == 4);
} // namespace

int netlink_address_change(const void* data, const NetlinkHeader& message) {
    unsigned allowed = 1 | 4 | (message.type == 20 ? 0x600 : 0);
    if ((message.type != 20 && message.type != 21) || !(message.flags & 1) ||
        (message.flags & ~allowed))
        return -95;
    if (message.length < sizeof(message) + sizeof(AddressHeader))
        return -22;
    auto input = static_cast<const uint8_t*>(data);
    AddressHeader address;
    memcpy(&address, input + sizeof(message), sizeof(address));
    if (address.family != 2)
        return -97;
    if (address.prefix > 32)
        return -22;
    if (address.scope || (address.flags & ~uint8_t(0x80)))
        return -95;
    if (!address.index || address.index > max_net_devices || !net_info(address.index))
        return -19;
    Ipv4Config desired;
    desired.mask = address.prefix ? UINT32_MAX << (32 - address.prefix) : 0;
    uint32_t local = 0, peer = 0, seen = 0;
    size_t at = sizeof(message) + sizeof(address);
    while (at < message.length) {
        Attribute field;
        if (message.length - at < sizeof(field))
            return -22;
        memcpy(&field, input + at, sizeof(field));
        if (field.length != 8 || field.length > message.length - at)
            return -22;
        if (field.type != 1 && field.type != 2 && field.type != 4)
            return -95;
        if (seen & (1u << field.type))
            return -22;
        seen |= 1u << field.type;
        uint32_t value = ip4::get32(input + at + 4);
        if (field.type == 1)
            peer = value;
        else if (field.type == 2)
            local = value;
        else
            desired.broadcast = value;
        at += 8;
    }
    if ((seen & 6) != 6 || local != peer || !ip4::unicast(local) || (local >> 24) == 127)
        return -22;
    uint32_t bits = ~desired.mask, host = local & bits;
    if (bits >= 2 && (!host || host == bits))
        return -22;
    desired.address = local;
    uint32_t broadcast = bits < 2 ? 0 : local | bits;
    if ((seen & (1u << 4)) && desired.broadcast != broadcast)
        return -22;
    desired.broadcast = broadcast;
    const auto current = ipv4_config(address.index);
    if (!current)
        return -19;
    if (message.type == 20) {
        if ((message.flags & 0x600) != 0x600)
            return -95;
        if (current->address)
            return -17; // Address aliases remain outside this one-address interface.
        return ipv4_configure(address.index, desired);
    }
    if (current->address != local || current->mask != desired.mask)
        return -99;
    return ipv4_configure(address.index, Ipv4Config{});
}
} // namespace ax
