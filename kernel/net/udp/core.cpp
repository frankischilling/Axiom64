// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/udp.hpp"
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"

namespace ax {
namespace {
uint16_t checksum(uint32_t source, uint32_t destination, const uint8_t* bytes, size_t length) {
    uint32_t sum = (source >> 16) + (source & 65535) + (destination >> 16) + (destination & 65535) +
                   17 + length;
    while (length >= 2) {
        sum += ip4::get16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += uint32_t(*bytes) << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return uint16_t(~sum);
}
} // namespace

UdpInput udp_receive(unsigned index, uint32_t source, uint32_t destination, bool broadcast,
                     const void* data, size_t length) {
    auto bytes = static_cast<const uint8_t*>(data);
    if (length < 8)
        return UdpInput::dropped;
    size_t declared = ip4::get16(bytes + 4);
    if (declared < 8 || declared > length ||
        (ip4::get16(bytes + 6) && checksum(source, destination, bytes, declared)))
        return UdpInput::dropped;
    return inet_datagram_deliver(index, source, destination, ip4::get16(bytes),
                                 ip4::get16(bytes + 2), broadcast, bytes + 8, declared - 8)
               ? UdpInput::delivered
               : UdpInput::unbound;
}

int udp_send(InetSocket* owner, const UdpOutput& output, const void* data, size_t length) {
    if (length > 65535 - 28)
        return -90;
    uint32_t source;
    int error = ipv4_source(output.source, output.destination, output.index, source);
    if (error)
        return error;
    auto bytes = static_cast<uint8_t*>(alloc(length + 8));
    if (!bytes)
        return -12;
    ip4::put16(bytes, output.source_port);
    ip4::put16(bytes + 2, output.destination_port);
    ip4::put16(bytes + 4, length + 8);
    ip4::put16(bytes + 6, 0);
    memcpy(bytes + 8, data, length);
    uint16_t sum = checksum(source, output.destination, bytes, length + 8);
    ip4::put16(bytes + 6, sum ? sum : 65535);
    error = ipv4_send(owner, source, output.destination, output.index, 17, output.ttl,
                      output.broadcast, bytes, length + 8);
    release(bytes);
    return error;
}
} // namespace ax
