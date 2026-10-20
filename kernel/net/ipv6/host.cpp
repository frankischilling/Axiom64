// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/reassembly.hpp"
#include "net/inet6.hpp"

namespace ax {
namespace {
struct Output {
    ip6::Address source, destination;
    uint8_t* bytes = nullptr;
    size_t length = 0;
    unsigned index = 0;
    uint8_t mac[6]{};
    uint64_t expires = 0;
    bool control = false;
    Inet6Socket* owner = nullptr;
};

Output outputs[32];
size_t queued_bytes;
bool polling;
unsigned error_tokens = 16;
uint64_t error_epoch;

bool allow_error() {
    if (ticks - error_epoch >= 100) {
        error_epoch = ticks;
        error_tokens = 16;
    }
    if (!error_tokens)
        return false;
    error_tokens--;
    return true;
}

void diagnostic(unsigned index, const uint8_t* original, size_t length, uint8_t type, uint8_t code,
                uint32_t pointer = 0) {
    if (length < ip6::header_size || !ip6::usable(index))
        return;
    ip6::Address source, destination;
    memcpy(source.bytes, original + 8, 16);
    memcpy(destination.bytes, original + 24, 16);
    if (source.unspecified() || source.multicast() || destination.multicast() ||
        !ipv6_owned(destination.link_local() ? index : 0, destination))
        return;
    uint8_t protocol = original[6];
    size_t at = ip6::header_size;
    while (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60 || protocol == 51) {
        if (length - at < 8)
            return;
        size_t size = protocol == 44   ? 8
                      : protocol == 51 ? (size_t(original[at + 1]) + 2) * 4
                                       : (size_t(original[at + 1]) + 1) * 8;
        // A nonfirst fragment cannot establish whether it quotes an ICMP error.
        if (size > length - at ||
            (protocol == 44 && (original[at + 2] || (original[at + 3] & 0xf8))))
            return;
        protocol = original[at];
        at += size;
    }
    if (protocol == 50 ||
        (protocol == 58 && (at == length || original[at] < 128 || original[at] == 137)) ||
        !allow_error())
        return;
    size_t quoted = min(length, size_t(1232));
    auto error = static_cast<uint8_t*>(alloc(8 + quoted));
    if (!error)
        return;
    memset(error, 0, 8);
    error[0] = type;
    error[1] = code;
    for (unsigned n = 0; n < 4; n++)
        error[4 + n] = pointer >> (24 - n * 8);
    memcpy(error + 8, original, quoted);
    uint16_t check = ip6::checksum(destination, source, 58, error, 8 + quoted);
    error[2] = check >> 8;
    error[3] = check;
    ipv6_send(destination, source, source.link_local() ? index : 0, 58, 64, error, 8 + quoted);
    release(error);
}

void fragment_expired(unsigned index, const uint8_t* bytes, size_t length) {
    diagnostic(index, bytes, length, 3, 1);
}

struct ReassembledInput {
    uint8_t* bytes = nullptr;

    ~ReassembledInput() {
        release(bytes);
    }
};

bool valid_mac(const uint8_t* mac) {
    bool nonzero = false;
    for (unsigned n = 0; n < 6; n++)
        nonzero |= mac[n] != 0;
    return nonzero && !(mac[0] & 1);
}

void clear(Output& item, int error = 0) {
    auto owner = item.owner;
    size_t cost = item.length - ethernet_header;
    queued_bytes -= item.length;
    release(item.bytes);
    item = {};
    inet6_complete(owner, cost, error);
}

int queue(const ip6::Address& source, const ip6::Address& destination, unsigned index,
          uint8_t protocol, uint8_t hop_limit, const void* data, size_t length, bool direct = false,
          Inet6Socket* owner = nullptr) {
    if (length > 65535)
        return -90;
    Output* selected = nullptr;
    for (auto& entry : outputs)
        if (!entry.bytes) {
            selected = &entry;
            break;
        }
    size_t needed = ethernet_header + ip6::header_size + length;
    if (!selected || needed > 262144 - queued_bytes)
        return -11;
    auto bytes = static_cast<uint8_t*>(alloc(needed));
    if (!bytes)
        return -12;
    memset(bytes, 0, ethernet_header);
    bytes[12] = 0x86;
    bytes[13] = 0xdd;
    ip6::Header header{source, destination, 0, uint16_t(length), 0, protocol, hop_limit};
    ip6::encode(bytes + ethernet_header, ip6::header_size, header);
    memcpy(bytes + ethernet_header + ip6::header_size, data, length);
    *selected = {source, destination, bytes, needed, index, {}, ticks + 400, direct, owner};
    queued_bytes += needed;
    return 0;
}

int control(unsigned index, const ip6::Address& source, const ip6::Address& destination,
            const uint8_t* mac, uint8_t* data, size_t length, bool queued) {
    auto info = net_info(index);
    if (!info || !ip6::usable(index))
        return -100;
    data[2] = data[3] = 0;
    uint16_t check = ip6::checksum(source, destination, 58, data, length);
    data[2] = check >> 8;
    data[3] = check;
    if (queued)
        return queue(source, destination, index, 58, 255, data, length, true);
    uint8_t frame[ethernet_header + ip6::header_size + 32]{};
    if (length > 32)
        return -90;
    memcpy(frame, mac, 6);
    memcpy(frame + 6, info->mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    ip6::Header header{source, destination, 0, uint16_t(length), 0, 58, 255};
    ip6::encode(frame + ethernet_header, ip6::header_size, header);
    memcpy(frame + ethernet_header + ip6::header_size, data, length);
    return net_send(index, frame, ethernet_header + ip6::header_size + length);
}

bool member(unsigned index, const ip6::Address& address) {
    if (address == ip6::all_nodes())
        return true;
    for (unsigned n = 0; auto entry = ipv6_address(n); n++)
        if (entry->index == index && !(entry->flags & 8) &&
            address == ip6::solicited_node(entry->address))
            return true;
    return false;
}

bool options(const uint8_t* data, size_t length, unsigned wanted, const uint8_t*& mac) {
    mac = nullptr;
    for (size_t at = 24; at < length;) {
        if (length - at < 2 || !data[at + 1])
            return false;
        size_t size = size_t(data[at + 1]) * 8;
        if (size > length - at)
            return false;
        if (data[at] == wanted) {
            if (mac || size != 8 || !valid_mac(data + at + 2))
                return false;
            mac = data + at + 2;
        }
        at += size;
    }
    return true;
}

void discovery(const NetInfo& info, const ip6::Packet& packet, const uint8_t* sender) {
    const auto bytes = packet.payload;
    if (packet.length < 24 || bytes[1] || packet.header.hop_limit != 255 || packet.fragmented)
        return;
    ip6::Address target;
    memcpy(target.bytes, bytes + 8, 16);
    if (target.unspecified() || target.multicast())
        return;
    const uint8_t* mac;
    bool solicitation = bytes[0] == 135;
    if (!options(bytes, packet.length, solicitation ? 1 : 2, mac))
        return;
    bool zero = packet.header.source.unspecified();
    if (solicitation) {
        if (zero && (mac || !(packet.header.destination == ip6::solicited_node(target))))
            return;
        if (!ipv6_owned(info.index, target)) {
            if (zero && memcmp(sender, info.mac, 6))
                ip6::address_duplicate(info.index, target);
            return;
        }
        if (!zero && mac)
            ip6::neighbor_solicitation(info.index, packet.header.source, mac);
        uint8_t reply[32]{};
        bool include_mac = packet.header.destination.multicast();
        reply[0] = 136;
        reply[4] = zero ? 0x20 : include_mac ? 0x60 : 0x40;
        memcpy(reply + 8, target.bytes, 16);
        reply[24] = 2;
        reply[25] = 1;
        memcpy(reply + 26, info.mac, 6);
        auto destination = zero ? ip6::all_nodes() : packet.header.source;
        control(info.index, target, destination, nullptr, reply, include_mac ? 32 : 24, true);
    } else {
        bool solicited = bytes[4] & 0x40;
        if (zero || (solicited && packet.header.destination.multicast()))
            return;
        ip6::address_duplicate(info.index, target);
        ip6::neighbor_advertisement(info.index, target, mac, solicited, bytes[4] & 0x20);
    }
}
} // namespace

int ipv6_send(const ip6::Address& source, const ip6::Address& destination, unsigned bound,
              uint8_t protocol, uint8_t hop_limit, const void* data, size_t length,
              Inet6Socket* owner) {
    Ipv6Path path;
    int error = ipv6_path(source, destination, bound, path);
    if (error)
        return error;
    if (length > 65535 || length > path.mtu - ip6::header_size)
        return -90;
    return queue(path.source, destination, bound, protocol, hop_limit, data, length, false, owner);
}

bool ipv6_output_ready() {
    for (const auto& item : outputs)
        if (!item.bytes && queued_bytes < 262144 - ethernet_header - ip6::header_size)
            return true;
    return false;
}

void ipv6_detach_owner(Inet6Socket* owner) {
    for (auto& item : outputs)
        if (item.owner == owner)
            item.owner = nullptr;
}

void ipv6_receive(const NetInfo& info, const void* frame, size_t length) {
    const auto bytes = static_cast<const uint8_t*>(frame);
    bool loopback = info.index == ipv6_loopback;
    if (!ip6::usable(info.index) || length < ethernet_header + ip6::header_size ||
        bytes[12] != 0x86 || bytes[13] != 0xdd || (!loopback && !valid_mac(bytes + 6)))
        return;
    const uint8_t* datagram = bytes + ethernet_header;
    auto packet = ip6::decode(datagram, length - ethernet_header);
    const auto& source = packet.header.source;
    const auto& destination = packet.header.destination;
    if ((packet.input != ip6::Input::payload && packet.input != ip6::Input::fragment &&
         !(packet.input == ip6::Input::parameter_problem && packet.fragment.header_offset)) ||
        source.multicast() || source.mapped() || destination.mapped() ||
        (!loopback && (source.loopback() || destination.loopback())) || destination.unspecified())
        return;
    if (destination.multicast()) {
        uint8_t mac[6];
        ip6::multicast_mac(destination, mac);
        if (!member(info.index, destination) || memcmp(mac, bytes, 6))
            return;
    } else if (memcmp(info.mac, bytes, 6) ||
               !ipv6_owned(destination.link_local() ? info.index : 0, destination))
        return;
    ReassembledInput owned;
    if (packet.input != ip6::Input::payload) {
        if (source.unspecified())
            return;
        auto result = ip6::reassemble(info.index, datagram, length - ethernet_header, ticks,
                                      fragment_expired);
        if (result.status == ip6::FragmentStatus::parameter_problem) {
            diagnostic(info.index, datagram, packet.size, 4, result.error_code,
                       result.error_pointer);
            return;
        }
        if (result.status != ip6::FragmentStatus::complete)
            return;
        owned.bytes = result.bytes;
        datagram = result.bytes;
        packet = ip6::decode(datagram, result.length);
        // Removing the header must not make fragmented ND look unfragmented.
        if (packet.input != ip6::Input::payload || packet.fragmented)
            return;
        packet.fragmented = true;
    }
    if (packet.length < 4)
        return;
    if (packet.protocol == 17) {
        if (source.unspecified())
            return;
        bool delivered = inet6_deliver(info.index, packet);
        if (!delivered)
            diagnostic(info.index, datagram, packet.size, 1, 4);
        return;
    }
    if (packet.protocol != 58 ||
        ip6::checksum(source, destination, 58, packet.payload, packet.length))
        return;
    inet6_deliver(info.index, packet);
    if (packet.payload[0] == 135 || packet.payload[0] == 136) {
        discovery(info, packet, bytes + 6);
        return;
    }
    if (source.unspecified() || packet.payload[0] != 128 || packet.payload[1] ||
        packet.length < 8 || destination.multicast())
        return;
    auto reply = static_cast<uint8_t*>(alloc(packet.length));
    if (!reply)
        return;
    memcpy(reply, packet.payload, packet.length);
    reply[0] = 129;
    reply[2] = reply[3] = 0;
    uint16_t check = ip6::checksum(destination, source, 58, reply, packet.length);
    reply[2] = check >> 8;
    reply[3] = check;
    ipv6_send(destination, source, source.link_local() ? info.index : 0, 58, 64, reply,
              packet.length);
    release(reply);
}

void ipv6_poll() {
    if (polling)
        return;
    polling = true;
    ip6::address_poll();
    ip6::reassembly_expire(ticks, fragment_expired);
    for (auto& item : outputs) {
        if (!item.bytes)
            continue;
        if (ticks >= item.expires) {
            clear(item, -113);
            continue;
        }
        Ipv6Path path;
        if (item.control) {
            path.index = item.index;
            path.source = item.source;
            path.next_hop = item.destination;
            if (!ip6::usable(path.index) || !ipv6_owned(path.index, item.source)) {
                clear(item, -100);
                continue;
            }
        } else {
            int error = ipv6_path(item.source, item.destination, item.index, path);
            if (error || item.length - ethernet_header > path.mtu) {
                clear(item, error ? error : -90);
                continue;
            }
            if (path.index == ipv6_loopback) {
                NetInfo loopback;
                loopback.index = ipv6_loopback;
                ipv6_receive(loopback, item.bytes, item.length);
                clear(item);
                continue;
            }
        }
        if (item.destination.multicast())
            ip6::multicast_mac(item.destination, item.mac);
        else if (!ip6::neighbor_resolve(path.index, path.source, path.next_hop, item.mac))
            continue;
        auto info = net_info(path.index);
        memcpy(item.bytes, item.mac, 6);
        memcpy(item.bytes + 6, info->mac, 6);
        int error = net_send(path.index, item.bytes, item.length);
        if (!error || (error != -11 && error != -100))
            clear(item, error);
    }
    ip6::neighbor_poll();
    polling = false;
}

void ipv6_shutdown() {
    for (auto& item : outputs)
        if (item.bytes)
            clear(item, -5);
    ip6::neighbor_reset();
    ip6::reassembly_discard();
    ip6::address_reset();
    error_tokens = 16;
    error_epoch = ticks;
}

namespace ip6 {
int neighbor_probe(unsigned index, const Address& source, const Address& target,
                   const uint8_t* unicast_mac) {
    auto info = net_info(index);
    if (!info)
        return -19;
    uint8_t data[32]{};
    data[0] = 135;
    memcpy(data + 8, target.bytes, 16);
    data[24] = 1;
    data[25] = 1;
    memcpy(data + 26, info->mac, 6);
    auto destination = unicast_mac ? target : solicited_node(target);
    uint8_t mac[6];
    if (unicast_mac)
        memcpy(mac, unicast_mac, 6);
    else
        multicast_mac(destination, mac);
    return control(index, source, destination, mac, data, sizeof(data), false);
}

int dad_probe(const Ipv6Address& address) {
    uint8_t data[24]{};
    data[0] = 135;
    memcpy(data + 8, address.address.bytes, 16);
    auto destination = solicited_node(address.address);
    uint8_t mac[6];
    multicast_mac(destination, mac);
    return control(address.index, {}, destination, mac, data, sizeof(data), false);
}
} // namespace ip6
} // namespace ax
