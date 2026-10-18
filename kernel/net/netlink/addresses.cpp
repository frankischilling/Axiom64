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
    if (address.scope || (address.flags & ~uint8_t(0x81)))
        return -95;
    if (!address.index || address.index > max_net_devices || !net_info(address.index))
        return -19;
    Ipv4Config desired;
    char label[16];
    memcpy(label, net_info(address.index)->name, sizeof(label));
    desired.mask = address.prefix ? UINT32_MAX << (32 - address.prefix) : 0;
    uint32_t local = 0, peer = 0, seen = 0;
    size_t at = sizeof(message) + sizeof(address);
    while (at < message.length) {
        Attribute field;
        if (message.length - at < sizeof(field))
            return -22;
        memcpy(&field, input + at, sizeof(field));
        if (field.length < 4 || field.length > message.length - at)
            return -22;
        if (field.type != 1 && field.type != 2 && field.type != 3 && field.type != 4)
            return -95;
        if (seen & (1u << field.type))
            return -22;
        seen |= 1u << field.type;
        if (field.type == 3) {
            size_t length = field.length - 4;
            if (!length || length > sizeof(label) || input[at + field.length - 1])
                return -22;
            for (size_t n = 0; n + 1 < length; n++)
                if (!input[at + 4 + n])
                    return -22;
            memset(label, 0, sizeof(label));
            memcpy(label, input + at + 4, length);
        } else {
            if (field.length != 8)
                return -22;
            uint32_t value = ip4::get32(input + at + 4);
            if (field.type == 1)
                peer = value;
            else if (field.type == 2)
                local = value;
            else
                desired.broadcast = value;
        }
        size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (aligned > message.length - at)
            return -22;
        at += aligned;
    }
    if (message.type == 21 && (seen & 6) == 4)
        peer = local; // Linux address deletion permits IFA_LOCAL without a peer attribute.
    if (!(seen & 4) || (!(seen & 2) && message.type != 21) || local != peer ||
        !ip4::unicast(local) || (local >> 24) == 127)
        return -22;
    uint32_t bits = ~desired.mask, host = local & bits;
    if (message.type == 20 && bits >= 2 && (!host || host == bits))
        return -22;
    desired.address = local;
    uint32_t broadcast = bits < 2 ? 0 : local | bits;
    if (message.type == 20 && (seen & (1u << 4)) && desired.broadcast != broadcast)
        return -22;
    if (!(seen & (1u << 4)))
        desired.broadcast = 0;
    if (message.type == 20) {
        if ((message.flags & 0x600) != 0x600)
            return -95;
        return ipv4_address_add(address.index, label, desired);
    }
    for (unsigned n = 0; auto current = ipv4_address(n); n++)
        if (current->index == address.index && current->config.address == local &&
            (!(seen & (1u << 1)) || current->config.mask == desired.mask) &&
            (!(seen & (1u << 3)) || !strcmp(current->label, label)))
            return ipv4_address_remove(address.index, local, current->config.mask);
    return -99;
}
} // namespace ax
