// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/ipv4/multicast_runtime.hpp"
#include "net/ipv4/addresses.hpp"
#include "net/ipv4/routes.hpp"
#include "net/ipv4/reassembly.hpp"
#include "net/ipv4/fragmentation.hpp"
#include "net/ipv4/path_mtu.hpp"
#include "net/inet.hpp"
#include "process/task.hpp"
#include "net/ipv4_wire.hpp"
#include "net/udp.hpp"
#include "net/tcp/socket.hpp"

namespace ax {
namespace {
constexpr unsigned neighbor_count = 128, output_count = 32;
constexpr uint64_t neighbor_lifetime = 30000, retry_interval = 100;

enum class NeighborState : uint8_t { free, resolving, reachable, failed };

struct Neighbor {
    uint32_t address = 0, request_source = 0;
    unsigned index = 0, attempts = 0;
    uint8_t mac[6]{};
    NeighborState state = NeighborState::free;
    uint64_t next = 0, expires = 0, touched = 0;
};

struct Output {
    InetSocket* owner = nullptr;
    uint8_t* bytes = nullptr;
    size_t length = 0;
    unsigned index = 0;
    uint32_t next_hop = 0;
    uint64_t expires = 0;
    bool ethernet_ready = false, local = false;
    bool multicast_loop = false, looped = false;
    bool submitting = false, discard_pending = false;
    int deferred_error = 0;
    uint8_t* fragment_bytes = nullptr;
    size_t fragment_capacity = 0, fragment_offset = 0;
    bool fragmentable = false;
    bool use_path_mtu = true, want_df = false;
    uint64_t path_owner = 0;
    uint32_t path_source = 0;
};

struct Selection {
    uint32_t source = 0, next_hop = 0;
    unsigned index = 0, prefix = 0, metric = UINT32_MAX;
    bool local = false, broadcast = false, found = false;
    uint64_t path_owner = 0;
    uint32_t path_source = 0;
};

static ip4::AddressBook addresses;
static Ipv4Config loopback{0x7f000001, 0xff000000, 0};
static ip4::RouteTable routes;
static Neighbor neighbors[neighbor_count];
static Output output[output_count];
static ip4::PathMtuCache path_mtu;
static uint64_t destination_generation = 1;
static uint16_t identifier;
static bool polling;
static uint64_t next_icmp_error[max_net_devices + 2];

static void retire_destinations() {
    if (destination_generation < UINT64_MAX)
        destination_generation++;
}

static unsigned prefix_length(uint32_t mask) {
    unsigned count = 0;
    while (mask & 0x80000000) {
        count++;
        mask <<= 1;
    }
    return count;
}

static bool is_loopback(uint32_t address) {
    return (address >> 24) == 127;
}

static bool directed_broadcast(const Ipv4Config& config, uint32_t address) {
    return config.address && config.mask < 0xfffffffe && config.broadcast &&
           config.broadcast == address;
}

static bool directed_broadcast(unsigned index, uint32_t address) {
    for (unsigned n = 0; auto entry = addresses.at(n); n++)
        if (entry->index == index && directed_broadcast(entry->config, address))
            return true;
    return false;
}

static bool assigned(unsigned index, uint32_t address) {
    for (unsigned n = 0; auto entry = addresses.at(n); n++)
        if (entry->index == index && entry->config.address == address)
            return true;
    return false;
}

static void clear(Output& item, int error = 0) {
    // Submission polls receive callbacks before copying this buffer. A callback
    // can cancel the queued packet, but cannot release its borrowed storage yet.
    if (item.submitting) {
        item.discard_pending = true;
        if (!item.deferred_error)
            item.deferred_error = error;
        return;
    }
    if (item.owner) {
        inet_reclaim(item.owner, ip4::get16(item.bytes + ethernet_header + 2));
        // Local device/address loss drops datagrams without a socket error.
        // Stream transports still need the failure to retire their state.
        if (error && (error != 100 || inet_stream(item.owner)))
            inet_failed(item.owner, error, item.index);
    }
    release(item.bytes);
    release(item.fragment_bytes);
    item = {};
}

static ip4::FragmentPiece submit(Output& item, const NetInfo& info) {
    auto packet = item.bytes + ethernet_header;
    if (ip4::get16(item.bytes + 12) != 0x0800)
        return {net_send(item.index, item.bytes, item.length), 0, 0, true};
    auto limit = item.use_path_mtu ? path_mtu.lookup({item.path_source, ip4::get32(packet + 16),
                                                      item.next_hop, item.index, item.path_owner},
                                                     info.mtu, ticks)
                                   : ip4::PathMtu{info.mtu};
    if (item.want_df && limit.locked && (ip4::get16(packet + 6) & 0x4000)) {
        ip4::put16(packet + 6, ip4::get16(packet + 6) & ~uint16_t(0x4000));
        ip4::put16(packet + 10, 0);
        ip4::put16(packet + 10, ip4::checksum(packet, size_t(packet[0] & 15) * 4));
    }
    if (!item.fragment_offset && ip4::get16(packet + 2) <= limit.mtu)
        return {net_send(item.index, item.bytes, item.length), 0, 0, true};
    if (!item.fragmentable)
        return {-90};
    size_t capacity = ethernet_header + limit.mtu;
    if (item.fragment_capacity < capacity) {
        auto bytes = static_cast<uint8_t*>(alloc(capacity));
        if (!bytes)
            return {-12};
        release(item.fragment_bytes);
        item.fragment_bytes = bytes;
        item.fragment_capacity = capacity;
    }
    // WANT permits local fragmentation even though small packets carry DF.
    // The policy was captured when accepted; later socket changes cannot alter it.
    if (ip4::get16(packet + 6) & 0x4000) {
        ip4::put16(packet + 6, ip4::get16(packet + 6) & ~uint16_t(0x4000));
        ip4::put16(packet + 10, 0);
        ip4::put16(packet + 10, ip4::checksum(packet, size_t(packet[0] & 15) * 4));
    }
    auto part = ip4::fragment_packet(packet, item.length - ethernet_header, limit.mtu,
                                     item.fragment_offset, item.fragment_bytes + ethernet_header,
                                     item.fragment_capacity - ethernet_header);
    if (part.error)
        return part;
    size_t wire_length = max(size_t(60), ethernet_header + part.length);
    memcpy(item.fragment_bytes, item.bytes, ethernet_header);
    memset(item.fragment_bytes + ethernet_header + part.length, 0,
           wire_length - ethernet_header - part.length);
    part.error = net_send(item.index, item.fragment_bytes, wire_length);
    return part;
}

static Output* vacant_output() {
    for (auto& item : output)
        if (!item.bytes)
            return &item;
    return nullptr;
}

static Neighbor* find_neighbor(unsigned index, uint32_t address) {
    for (auto& entry : neighbors)
        if (entry.state != NeighborState::free && entry.index == index && entry.address == address)
            return &entry;
    return nullptr;
}

static bool neighbor_pending(const Neighbor& neighbor) {
    for (const auto& item : output)
        if (item.bytes && !item.local && !item.ethernet_ready && item.index == neighbor.index &&
            item.next_hop == neighbor.address && item.expires > ticks)
            return true;
    return false;
}

static Neighbor* prepare_neighbor(unsigned index, uint32_t address) {
    auto entry = find_neighbor(index, address);
    if (entry && entry->expires > ticks)
        return entry;
    if (!entry) {
        for (auto& candidate : neighbors) {
            if (candidate.state == NeighborState::free) {
                entry = &candidate;
                break;
            }
            if (!neighbor_pending(candidate) && (!entry || candidate.touched < entry->touched))
                entry = &candidate;
        }
    }
    if (!entry)
        return nullptr;
    *entry = {};
    entry->index = index;
    entry->address = address;
    entry->state = NeighborState::resolving;
    entry->expires = ticks + retry_interval * 4;
    entry->touched = ticks;
    return entry;
}

static void learn(unsigned index, uint32_t address, const uint8_t* mac, bool insert) {
    auto entry = find_neighbor(index, address);
    if (!entry && insert)
        entry = prepare_neighbor(index, address);
    if (!entry)
        return;
    memcpy(entry->mac, mac, 6);
    entry->state = NeighborState::reachable;
    entry->expires = ticks + neighbor_lifetime;
    entry->touched = ticks;
}

static void arp_frame(uint8_t* frame, const NetInfo& info, uint16_t operation,
                      const uint8_t* target_mac, uint32_t sender, uint32_t target) {
    memset(frame, 0, 60);
    if (operation == 1)
        memset(frame, 0xff, 6);
    else
        memcpy(frame, target_mac, 6);
    memcpy(frame + 6, info.mac, 6);
    ip4::put16(frame + 12, 0x0806);
    ip4::put16(frame + 14, 1);
    ip4::put16(frame + 16, 0x0800);
    frame[18] = 6;
    frame[19] = 4;
    ip4::put16(frame + 20, operation);
    memcpy(frame + 22, info.mac, 6);
    ip4::put32(frame + 28, sender);
    if (operation == 2)
        memcpy(frame + 32, target_mac, 6);
    ip4::put32(frame + 38, target);
}

static bool pending_arp_reply(unsigned index, uint32_t sender, uint32_t target) {
    auto neighbor = find_neighbor(index, sender);
    if (!neighbor || neighbor->state != NeighborState::resolving || !neighbor->attempts ||
        neighbor->expires <= ticks || target != neighbor->request_source)
        return false;
    for (const auto& item : output)
        if (item.bytes && !item.local && !item.ethernet_ready && item.index == index &&
            item.next_hop == sender && item.expires > ticks)
            return true;
    return false;
}

static void arp_receive(const NetInfo& info, const uint8_t* frame, size_t length) {
    if (length < 42 || ip4::get16(frame + 14) != 1 || ip4::get16(frame + 16) != 0x0800 ||
        frame[18] != 6 || frame[19] != 4)
        return;
    uint16_t operation = ip4::get16(frame + 20);
    uint32_t sender = ip4::get32(frame + 28), target = ip4::get32(frame + 38);
    const uint8_t* mac = frame + 22;
    bool nonzero = false;
    for (unsigned i = 0; i < 6; i++)
        nonzero |= mac[i] != 0;
    if ((operation != 1 && operation != 2) || !nonzero || (mac[0] & 1) ||
        memcmp(mac, frame + 6, 6) || (sender && (!ip4::unicast(sender) || is_loopback(sender))))
        return;
    bool owned_reply = operation == 2 && pending_arp_reply(info.index, sender, target);
    if ((!addresses.preferred(info.index) && !owned_reply) || ipv4_local(sender) ||
        directed_broadcast(info.index, sender))
        return;
    bool ours = assigned(info.index, target);
    if (operation == 2 && (memcmp(frame, info.mac, 6) || memcmp(frame + 32, info.mac, 6)))
        return;
    if (sender)
        learn(info.index, sender, mac, ours);
    if (!ours || operation != 1)
        return;
    auto slot = vacant_output();
    if (!slot)
        return;
    auto bytes = static_cast<uint8_t*>(alloc(60));
    if (!bytes)
        return;
    arp_frame(bytes, info, 2, mac, target, sender);
    *slot = {nullptr, bytes, 60, info.index, 0, ticks + 100, true, false};
}

static uint32_t preferred_source(unsigned index, uint32_t destination) {
    if (auto preferred = addresses.preferred(index, destination))
        return preferred->config.address;
    for (unsigned candidate = 1; candidate <= max_net_devices; candidate++)
        if (auto preferred = addresses.preferred(candidate))
            return preferred->config.address;
    return 0;
}

static int select(Ipv4Source requested, uint32_t destination, unsigned bound, Selection& result) {
    uint32_t source = requested.address;
    bool multicast = ip4::multicast(destination);
    if (destination && !ip4::unicast(destination) && !multicast && destination != UINT32_MAX)
        return -101;
    if (source && !ipv4_local(source))
        return -99;
    if (bound && bound != ipv4_loopback && !net_info(bound))
        return -19;
    if (!destination) {
        if (!requested.selected)
            source = bound && bound != ipv4_loopback ? preferred_source(bound, 0) : 0;
        if (!source)
            source = loopback.address;
        result = {source, source, ipv4_loopback, 32, 0, true, false, true};
        return 0;
    }
    if (bound == ipv4_loopback || (is_loopback(destination) && !bound)) {
        if (!requested.selected) {
            source = is_loopback(destination) ? loopback.address : preferred_source(0, destination);
            if (!source)
                source = loopback.address;
        }
        result = {source, destination, ipv4_loopback, 8, 0, true, false, true};
        return 0;
    }
    if (bound && !ipv4_config(bound))
        return -19;
    for (unsigned n = 0; auto entry = addresses.at(n); n++) {
        unsigned index = entry->index;
        const auto config = &entry->config;
        if (bound && bound != index)
            continue;
        if (destination == config->address) {
            result = {requested.selected ? source : config->address,
                      destination,
                      index,
                      32,
                      0,
                      true,
                      false,
                      true};
            return 0;
        }
        if (destination == UINT32_MAX || directed_broadcast(*config, destination)) {
            result = {requested.selected ? source : config->address,
                      destination,
                      index,
                      32,
                      0,
                      false,
                      true,
                      true};
            break;
        }
    }
    for (unsigned n = 0; auto route = routes.at(n); n++) {
        const auto& value = route->value;
        if ((bound && bound != value.index) || (destination & value.mask) != value.destination)
            continue;
        auto preferred = addresses.preferred(value.index, value.gateway);
        if (!preferred)
            continue;
        const auto config = &preferred->config;
        unsigned prefix = prefix_length(value.mask);
        if (!result.found || prefix > result.prefix ||
            (prefix == result.prefix && value.metric < result.metric)) {
            result = {requested.selected        ? source
                      : route->preferred_source ? route->preferred_source
                                                : config->address,
                      value.gateway ? value.gateway : destination,
                      value.index,
                      prefix,
                      value.metric,
                      false,
                      false,
                      true,
                      route->owner};
            result.path_source =
                route->preferred_source ? route->preferred_source : config->address;
        }
    }
    if (!result.found && bound && bound != ipv4_loopback) {
        auto preferred = addresses.preferred(bound);
        uint32_t fallback = preferred_source(bound, 0);
        result = {
            requested.selected ? source : fallback, destination, bound, 0, 0, false, false, true};
        // Shared exceptions belong to an address on the output device.
        result.path_source = preferred ? preferred->config.address : 0;
    }
    if (!result.found && multicast)
        for (unsigned n = 0; auto entry = addresses.at(n); n++) {
            if (bound && bound != entry->index)
                continue;
            auto info = net_info(entry->index);
            if (!info || !info->live || !info->administrative || !info->carrier)
                continue;
            result = {requested.selected ? source : entry->config.address,
                      destination,
                      entry->index,
                      0,
                      0,
                      false,
                      false,
                      true};
            result.path_source = entry->config.address;
            break;
        }
    if (result.found && is_loopback(source) && !result.local)
        return -22;
    if (!result.found)
        return -101;
    if (multicast)
        result.next_hop = destination;
    auto info = net_info(result.index);
    if (!info || !info->live)
        return -5;
    if (!info->administrative)
        return -101;
    if (!info->carrier)
        return -100;
    return 0;
}

static void protocol_error(unsigned index, uint32_t source, uint32_t destination,
                           const uint8_t* bytes, size_t length, uint8_t code = 2,
                           uint8_t type = 3) {
    if (ticks < next_icmp_error[index])
        return;
    size_t header = size_t(bytes[0] & 15) * 4;
    // Never answer an ICMP error with another error, including a fragmented one.
    if (bytes[9] == 1 && length > header &&
        (bytes[header] == 3 || bytes[header] == 4 || bytes[header] == 5 || bytes[header] == 11 ||
         bytes[header] == 12))
        return;
    // IPv4 header plus the first eight original payload bytes, bounded by RX length.
    uint8_t error[76]{};
    error[0] = type;
    error[1] = code;
    size_t quoted = min(length, header + 8);
    memcpy(error + 8, bytes, quoted);
    ip4::put16(error + 2, ip4::checksum(error, 8 + quoted));
    if (!ipv4_send(nullptr, destination, source, index, 1, 64, false, error, 8 + quoted))
        next_icmp_error[index] = ticks + 100;
}

static void reassembly_timeout(unsigned index, const uint8_t* bytes, size_t length,
                               bool link_broadcast) {
    uint32_t source = ip4::get32(bytes + 12), destination = ip4::get32(bytes + 16);
    if (!link_broadcast && ipv4_local(destination) && ip4::unicast(source))
        protocol_error(index, source, destination, bytes, length, 1, 11);
}

static void quoted_error(unsigned index, const uint8_t* payload, size_t length) {
    if (length < 36)
        return;
    const auto quote = payload + 8;
    if (quote[9] == 6) {
        tcp_icmp_error(index, payload, length);
        return;
    }
    if (quote[0] != 0x45 || ip4::get16(quote + 2) < 28 || ip4::checksum(quote, 20) ||
        (ip4::get16(quote + 6) & ~uint16_t(0x4000)) || (quote[9] != 1 && quote[9] != 17) ||
        !ipv4_local(ip4::get32(quote + 12)) || !ip4::unicast(ip4::get32(quote + 16)))
        return;
    if (quote[9] == 17 &&
        (ip4::get16(quote + 24) < 8 || ip4::get16(quote + 24) > ip4::get16(quote + 2) - 20))
        return;
    int error = 0;
    if (payload[0] == 12 && !payload[1])
        error = 71; // EPROTO: parameter problem
    else if (payload[0] == 3) {
        if (payload[1] == 2)
            error = 92; // ENOPROTOOPT: protocol unreachable
        else if (payload[1] == 3)
            error = 111; // ECONNREFUSED: port unreachable
        else if (payload[1] == 4)
            error = 90; // EMSGSIZE: fragmentation needed
    }
    if (error)
        inet_icmp_error(index, quote, error, error == 90 ? ip4::get16(payload + 6) : 0);
}

static void input(unsigned index, const uint8_t* bytes, size_t length, bool link_broadcast = false,
                  bool looped = false) {
    size_t header = length ? size_t(bytes[0] & 15) * 4 : 0;
    if (length < 20 || (bytes[0] >> 4) != 4 || header < 20 || header > length ||
        (header != 20 && bytes[9] != 2) || ip4::get16(bytes + 2) < header ||
        ip4::get16(bytes + 2) > length || ip4::checksum(bytes, header) || (!bytes[8] && !looped) ||
        (ip4::get16(bytes + 6) & 0x8000))
        return;
    length = ip4::get16(bytes + 2);
    uint32_t source = ip4::get32(bytes + 12), destination = ip4::get32(bytes + 16);
    auto config = ipv4_config(index);
    bool local = ipv4_local(destination);
    bool broadcast = destination == UINT32_MAX || directed_broadcast(index, destination);
    bool multicast = ip4::multicast(destination) &&
                     (bytes[9] == 2 ? ipv4_multicast_member(index, destination)
                                    : ipv4_multicast_source_allowed(index, destination, source));
    if (!config || !ip4::unicast(source) || (!local && !broadcast && !multicast) ||
        (index != ipv4_loopback &&
         (is_loopback(source) || is_loopback(destination) || directed_broadcast(index, source))))
        return;
    if (bytes[9] == 2) {
        ipv4_multicast_input(index, bytes, length);
        return;
    }
    auto assembled =
        looped ? ip4::Reassembled{ip4::FragmentStatus::whole}
               : ip4::reassemble(index, bytes, length, ticks, link_broadcast, reassembly_timeout);
    if (assembled.status == ip4::FragmentStatus::complete) {
        input(index, assembled.bytes, assembled.length, assembled.link_broadcast);
        release(assembled.bytes);
        return;
    }
    if (assembled.status != ip4::FragmentStatus::whole)
        return;
    // Raw listeners receive the complete reassembled IPv4 datagram before
    // transport validation, including malformed UDP payloads.
    uint32_t specific = destination;
    if (broadcast || multicast) {
        Selection reverse;
        if (!select({}, source, 0, reverse))
            specific = reverse.source;
        else if (index == ipv4_loopback)
            specific = loopback.address;
        else {
            auto preferred = addresses.preferred(index, source);
            specific = preferred ? preferred->config.address : 0;
        }
    }
    Ipv4ReceiveMetadata metadata{index,    source,   destination, specific,
                                 bytes[9], bytes[8], bytes[1]};
    inet_deliver(metadata, bytes, length);
    if (bytes[9] == 17) {
        if (udp_receive(metadata, broadcast, bytes + 20, length - 20) == UdpInput::unbound &&
            local && !broadcast && !link_broadcast)
            protocol_error(index, source, destination, bytes, length, 3);
        return;
    }
    if (bytes[9] == 6) {
        if (local && !broadcast && !link_broadcast)
            tcp_receive(index, source, destination, bytes + 20, length - 20);
        return;
    }
    if (bytes[9] != 1) {
        if (local && !broadcast && !link_broadcast)
            protocol_error(index, source, destination, bytes, length);
        return;
    }
    auto payload = bytes + 20;
    size_t payload_length = length - 20;
    if (payload_length < 8)
        return;
    if (ip4::checksum(payload, payload_length))
        return;
    if (local && !broadcast && !link_broadcast &&
        (payload[0] == 3 || payload[0] == 11 || payload[0] == 12))
        quoted_error(index, payload, payload_length);
    if (!local || broadcast || link_broadcast || payload[0] != 8 || payload[1])
        return;
    // Responses are queued, never transmitted recursively from a NIC RX poll.
    auto reply = static_cast<uint8_t*>(alloc(payload_length));
    if (!reply)
        return;
    memcpy(reply, payload, payload_length);
    reply[0] = 0;
    ip4::put16(reply + 2, 0);
    ip4::put16(reply + 2, ip4::checksum(reply, payload_length));
    ipv4_send(nullptr, destination, source, index, 1, 64, false, reply, payload_length);
    release(reply);
}
} // namespace

const Ipv4Config* ipv4_config(unsigned index) {
    if (index == ipv4_loopback)
        return &loopback;
    if (!net_info(index))
        return nullptr;
    auto preferred = addresses.preferred(index);
    static const Ipv4Config empty;
    return preferred ? &preferred->config : &empty;
}

const Ipv4Address* ipv4_address(unsigned position) {
    if (auto entry = addresses.at(position))
        return entry;
    if (position && !addresses.at(position - 1))
        return nullptr;
    static const Ipv4Address lo{{0x7f000001, 0xff000000, 0}, ipv4_loopback, "lo", false};
    return &lo;
}

const Ipv4Config* ipv4_label(unsigned index, const char* label, uint32_t hint) {
    if (index == ipv4_loopback)
        return !strcmp(label, "lo") ? &loopback : nullptr;
    auto entry = addresses.label(index, label, hint);
    return entry ? &entry->config : nullptr;
}

static int address_label(unsigned index, const char* label) {
    if (index == ipv4_loopback)
        return -95;
    auto info = net_info(index);
    if (!info)
        return -19;
    if (!label)
        return -22;
    unsigned size = 0;
    while (size < 16 && label[size])
        size++;
    size_t base = strlen(info->name);
    if (size == 16 || size < base || memcmp(label, info->name, base) ||
        (label[base] && label[base] != ':'))
        return -22;
    return 0;
}

static uint16_t active_interfaces() {
    uint16_t active = 0;
    for (unsigned index = 1; index <= max_net_devices; index++)
        if (auto info = net_info(index); info && info->administrative)
            active |= 1u << (index - 1);
    return active;
}

static int addresses_changed(const ip4::AddressBook& before, unsigned index) {
    if (int error = routes.synchronize(addresses, active_interfaces())) {
        addresses = before;
        return error;
    }
    if (before.preferred(index) && !addresses.preferred(index)) {
        routes.withdraw(index);
        path_mtu.discard(index);
    }
    for (unsigned n = 0; n < ipv4_address_capacity; n++) {
        auto old = before.at(n), current = addresses.at(n);
        if (!old && !current)
            break;
        if (!old || !current || old->index != current->index ||
            old->config.address != current->config.address ||
            old->config.mask != current->config.mask ||
            old->config.broadcast != current->config.broadcast ||
            old->secondary != current->secondary || strcmp(old->label, current->label)) {
            retire_destinations();
            break;
        }
    }
    bool retained = false;
    for (unsigned n = 0; auto old = before.at(n); n++) {
        if (old->index != index)
            continue;
        bool unchanged = false;
        for (unsigned m = 0; auto current = addresses.at(m); m++)
            unchanged |= current->index == index &&
                         current->config.address == old->config.address &&
                         current->config.mask == old->config.mask &&
                         current->config.broadcast == old->config.broadcast;
        retained |= unchanged;
        if (unchanged)
            continue;
        if (!old->secondary)
            path_mtu.discard_source(index, old->config.address);
        if (assigned(index, old->config.address))
            continue;
        ip4::reassembly_discard(old->config.address);
        for (auto& item : output) {
            if (!item.bytes || item.index != index)
                continue;
            bool ip = item.local || ip4::get16(item.bytes + 12) == 0x0800;
            bool owned =
                ip ? ip4::get32(item.bytes + ethernet_header + 12) == old->config.address ||
                         (item.local &&
                          ip4::get32(item.bytes + ethernet_header + 16) == old->config.address)
                   : ip4::get32(item.bytes + 28) == old->config.address;
            if (owned)
                clear(item, 100);
        }
    }
    if (!retained)
        for (auto& neighbor : neighbors)
            if (neighbor.index == index)
                neighbor = {};
    return 0;
}

int ipv4_configure_label(unsigned index, const char* label, const Ipv4Config& config) {
    if (int error = address_label(index, label))
        return error;
    auto before = addresses;
    int error = addresses.set(index, label, config);
    int changed = addresses_changed(before, index);
    return changed ? changed : error;
}

int ipv4_configure(unsigned index, const Ipv4Config& config) {
    auto changed = config;
    if (!changed.address || changed.mask >= 0xfffffffe)
        changed.broadcast = 0;
    else if (!changed.broadcast)
        changed.broadcast = changed.address | ~changed.mask;
    auto info = net_info(index);
    return info                     ? ipv4_configure_label(index, info->name, changed)
           : index == ipv4_loopback ? -95
                                    : -19;
}

int ipv4_address_add(unsigned index, const char* label, const Ipv4Config& config) {
    if (!net_info(index))
        return -19;
    auto before = addresses;
    int error = addresses.add(index, label, config);
    return error ? error : addresses_changed(before, index);
}

int ipv4_address_remove(unsigned index, uint32_t address, uint32_t mask) {
    if (!net_info(index))
        return -19;
    auto before = addresses;
    int error = addresses.remove(index, address, mask);
    return error ? error : addresses_changed(before, index);
}

void ipv4_mtu_changed(unsigned index, uint32_t previous_mtu) {
    if (auto info = net_info(index); info && previous_mtu != info->mtu) {
        path_mtu.update_mtu(index, previous_mtu, info->mtu);
        retire_destinations();
    }
}

int ipv4_administrative_changed(unsigned index) {
    auto info = net_info(index);
    if (!info)
        return -19;
    if (info->administrative) {
        if (int error = routes.synchronize(addresses, active_interfaces()))
            return error;
    } else {
        routes.withdraw(index);
        path_mtu.discard(index);
        for (auto& neighbor : neighbors)
            if (neighbor.index == index)
                neighbor = {};
        for (auto& item : output)
            if (item.bytes && item.index == index && !item.local)
                clear(item, 100);
    }
    retire_destinations();
    return 0;
}

static int change_route(const Ipv4Route& input, bool remove, bool control, bool exclusive) {
    auto value = input;
    if (!ip4::mask_valid(value.mask) || (value.destination & value.mask) != value.destination)
        return -22;
    if (remove) {
        uint64_t owner = 0;
        int error = routes.erase(value, control, owner);
        if (!error) {
            if (!routes.owns(owner))
                path_mtu.discard_route(owner);
            retire_destinations();
        }
        return error;
    }
    if (!value.index) {
        unsigned best = 0;
        const uint32_t target = value.gateway ? value.gateway : value.destination;
        for (unsigned n = 0; auto entry = addresses.at(n); n++) {
            const auto config = &entry->config;
            if (!entry->secondary && (target & config->mask) == (config->address & config->mask) &&
                (!value.index || prefix_length(config->mask) > best)) {
                value.index = entry->index;
                best = prefix_length(config->mask);
            }
        }
        if (!value.index)
            return -101;
    }
    if (!net_info(value.index) || value.index == ipv4_loopback)
        return -19;
    if (!net_info(value.index)->administrative)
        return -100;
    auto preferred = addresses.preferred(value.index, value.gateway);
    const auto config = preferred ? &preferred->config : nullptr;
    if (value.gateway &&
        (!config || !ip4::unicast(value.gateway) || is_loopback(value.gateway) ||
         directed_broadcast(value.index, value.gateway) || ipv4_local(value.gateway) ||
         (value.gateway & config->mask) != (config->address & config->mask)))
        return -101;
    if (value.scope == 255)
        value.scope = value.gateway ? 0 : 253;
    int error = routes.insert(value, exclusive);
    if (!error)
        retire_destinations();
    return error;
}

int ipv4_route(const Ipv4Route& value, bool remove) {
    return change_route(value, remove, false, false);
}

int ipv4_route_control(const Ipv4Route& value, bool remove, bool exclusive) {
    return change_route(value, remove, true, exclusive);
}

size_t ipv4_routes(Ipv4Route* output, size_t capacity) {
    size_t count = 0;
    auto append = [&](const ip4::RouteTable::Entry& entry) {
        if (count < capacity) {
            output[count] = entry.value;
            output[count++].preferred_source = entry.preferred_source;
        }
    };
    for (unsigned n = 0; auto route = routes.at(n); n++)
        if (route->automatic)
            append(*route);
    if (count < capacity)
        output[count++] = {loopback.address & loopback.mask,
                           loopback.mask,
                           0,
                           ipv4_loopback,
                           0,
                           2,
                           253,
                           loopback.address};
    for (unsigned n = 0; auto route = routes.at(n); n++)
        if (!route->automatic)
            append(*route);
    return count;
}

bool ipv4_local(uint32_t address) {
    if (is_loopback(address))
        return true;
    for (unsigned n = 0; auto entry = addresses.at(n); n++)
        if (address && entry->config.address == address)
            return true;
    return false;
}

bool ipv4_output_ready() {
    return vacant_output() != nullptr;
}

int ipv4_source(Ipv4Source source, uint32_t destination, unsigned bound_index, uint32_t& selected) {
    Selection route;
    int error = select(source, destination, bound_index, route);
    if (!error)
        selected = route.source;
    return error;
}

static ip4::PathMtu selection_limit(const Selection& route, uint32_t destination) {
    uint32_t device = route.local ? 65535u : net_info(route.index)->mtu;
    if (!route.local && !route.broadcast && !ip4::multicast(destination))
        return path_mtu.lookup(
            {route.path_source, destination, route.next_hop, route.index, route.path_owner}, device,
            ticks);
    return {device};
}

int ipv4_path(Ipv4Source source, uint32_t destination, unsigned bound_index, Ipv4Path& path) {
    Selection route;
    int error = select(source, destination, bound_index, route);
    if (!error)
        path = {route.source, selection_limit(route, destination).mtu, route.index};
    return error;
}

static Ipv4Destination retain_selection(const Selection& route, uint32_t destination,
                                        unsigned bound_index, Ipv4Source source) {
    auto limit = selection_limit(route, destination);
    Ipv4Destination retained;
    retained.path = {route.source, limit.mtu, route.index};
    retained.address = destination;
    retained.bound_index = bound_index;
    retained.generation = destination_generation;
    retained.expires = limit.expires;
    retained.local = route.local;
    retained.gateway = route.next_hop != destination;
    retained.locked = limit.locked;
    retained.source = source.address;
    return retained;
}

int ipv4_destination(Ipv4Destination& retained, Ipv4Source source, uint32_t destination,
                     unsigned bound_index) {
    Selection route;
    int error = select(source, destination, bound_index, route);
    retained =
        error ? Ipv4Destination{} : retain_selection(route, destination, bound_index, source);
    return error;
}

bool ipv4_destination_current(const Ipv4Destination& retained) {
    return retained.path.index && retained.generation == destination_generation &&
           destination_generation != UINT64_MAX && (!retained.expires || ticks < retained.expires);
}

int ipv4_destination_mtu(Ipv4Destination& retained, bool refresh_route) {
    if (!retained.path.index)
        return -107;
    bool expired = retained.expires && ticks >= retained.expires;
    auto info = net_info(retained.path.index);
    uint32_t mtu = retained.local ? 65535u : info ? info->mtu : retained.path.mtu;
    if (retained.expires && !expired)
        mtu = retained.path.mtu;
    else if (retained.locked && retained.gateway && mtu > 576)
        mtu = 576;
    // The syscall returns this value even when its release callback loses the route.
    if (refresh_route)
        ipv4_destination_release(retained);
    return int(mtu);
}

void ipv4_destination_release(Ipv4Destination& retained) {
    if (retained.path.index && !ipv4_destination_current(retained))
        ipv4_destination(retained, retained.source, retained.address, retained.bound_index);
}

uint32_t ipv4_learn_pmtu(uint32_t source, uint32_t destination, unsigned index,
                         uint16_t announced_mtu, uint16_t quoted_length) {
    Selection route;
    if (select(source, destination, index, route) || route.local || route.broadcast ||
        ip4::multicast(destination))
        return 0;
    bool updated;
    auto learned = path_mtu.learn(
        {route.path_source, destination, route.next_hop, route.index, route.path_owner},
        net_info(route.index)->mtu, announced_mtu, quoted_length, ticks, &updated);
    if (updated)
        retire_destinations();
    return learned.mtu;
}

static int prepare_output(InetSocket* owner, Ipv4Source source, uint32_t destination,
                          unsigned bound_index, uint8_t ttl, bool broadcast, size_t length,
                          bool cache_destination, Selection& route, ip4::PathMtu& limit) {
    bool multicast = ip4::multicast(destination);
    if (!ttl && !multicast)
        return -22;
    int error = select(source, destination, bound_index, route);
    auto retained =
        cache_destination ? inet_output_destination(owner, destination, error != 0) : nullptr;
    if (error) {
        if (retained)
            *retained = {};
        return owner && error == -99 ? -101 : error;
    }
    if (retained)
        *retained = retain_selection(route, destination, bound_index, source);
    if (route.broadcast && !broadcast)
        return -13;
    bool fragmentable = inet_fragmentation_allowed(owner);
    uint32_t mtu = route.local ? 65535u : net_info(route.index)->mtu;
    limit = {mtu};
    bool use_path_mtu = inet_use_path_mtu(owner);
    if (use_path_mtu)
        limit = selection_limit(route, destination);
    if (length > 65535 - 20 || (!route.local && length + 20 > limit.mtu && !fragmentable))
        return -90;
    return 0;
}

int ipv4_send_admit(InetSocket* owner, Ipv4Source source, uint32_t destination,
                    unsigned bound_index, uint8_t ttl, bool broadcast, size_t length,
                    bool cache_destination, Ipv4SendRoute* selected) {
    Selection route;
    ip4::PathMtu limit;
    int error = prepare_output(owner, source, destination, bound_index, ttl, broadcast, length,
                               cache_destination, route, limit);
    if (!error && selected)
        *selected = {{route.source, limit.mtu, route.index},
                     destination,
                     route.next_hop,
                     route.path_source,
                     route.path_owner,
                     route.local,
                     route.broadcast,
                     limit.locked};
    return error;
}

int ipv4_send(InetSocket* owner, Ipv4Source source, uint32_t destination, unsigned bound_index,
              uint8_t protocol, uint8_t ttl, bool broadcast, const void* payload, size_t length,
              bool cache_destination, int traffic_class, const Ipv4SendRoute* selected) {
    Selection route;
    ip4::PathMtu limit;
    if (selected) {
        if (!selected->path.index || selected->destination != destination)
            return -22;
        if (selected->path_owner && !routes.owns(selected->path_owner))
            return ipv4_output_discarded;
        route = {selected->path.source,
                 selected->next_hop,
                 selected->path.index,
                 0,
                 0,
                 selected->local,
                 selected->broadcast,
                 true,
                 selected->path_owner,
                 selected->path_source};
        limit = {selected->path.mtu, selected->locked};
        if (!route.local) {
            auto info = net_info(route.index);
            if (!info || !info->live)
                return -5;
            if (!info->administrative || !info->carrier)
                return ipv4_output_discarded;
        }
    } else if (int error = prepare_output(owner, source, destination, bound_index, ttl, broadcast,
                                          length, cache_destination, route, limit))
        return error;
    bool multicast = ip4::multicast(destination);
    bool fragmentable = inet_fragmentation_allowed(owner);
    bool use_path_mtu = inet_use_path_mtu(owner);
    auto slot = vacant_output();
    if (!slot)
        return -11;
    if (!route.local && !route.broadcast && !multicast &&
        !prepare_neighbor(route.index, route.next_hop))
        return -105;
    size_t total = max(size_t(60), ethernet_header + 20 + length);
    auto bytes = static_cast<uint8_t*>(alloc(total));
    if (!bytes)
        return -12;
    memset(bytes, 0, total);
    auto ip = bytes + ethernet_header;
    ip[0] = 0x45;
    ip[1] = traffic_class < 0 ? inet_traffic_class(owner) : uint8_t(traffic_class);
    ip4::put16(ip + 2, 20 + length);
    ip4::put16(ip + 4, ++identifier);
    ip4::put16(ip + 6, inet_dont_fragment(owner, limit.locked) ? 0x4000 : 0);
    ip[8] = ttl;
    ip[9] = protocol;
    ip4::put32(ip + 12, route.source);
    ip4::put32(ip + 16, destination);
    ip4::put16(ip + 10, ip4::checksum(ip, 20));
    memcpy(ip + 20, payload, length);
    bool ready = false;
    if (!route.local) {
        const auto info = net_info(route.index);
        memcpy(bytes + 6, info->mac, 6);
        ip4::put16(bytes + 12, 0x0800);
        if (route.broadcast) {
            memset(bytes, 0xff, 6);
            ready = true;
        } else if (multicast) {
            bytes[0] = 1;
            bytes[1] = 0;
            bytes[2] = 0x5e;
            bytes[3] = (destination >> 16) & 0x7f;
            bytes[4] = destination >> 8;
            bytes[5] = destination;
            ready = true;
        }
    }
    *slot = {owner, bytes,      total, route.index, route.next_hop, ticks + retry_interval * 4,
             ready, route.local};
    slot->multicast_loop = multicast && inet_multicast_loop(owner);
    slot->fragmentable = fragmentable;
    slot->use_path_mtu = use_path_mtu;
    slot->want_df = fragmentable && inet_dont_fragment(owner);
    slot->path_owner = route.path_owner;
    slot->path_source = route.path_source;
    return 0;
}

bool ipv4_multicast_report(unsigned index, uint32_t destination, const uint8_t* payload,
                           size_t length) {
    auto info = net_info(index);
    auto config = ipv4_config(index);
    auto slot = vacant_output();
    if (!info || !config || !config->address || !slot || !info->live || !info->administrative ||
        !info->carrier || length + 24 > info->mtu)
        return false;
    size_t total = max(size_t(60), ethernet_header + 24 + length);
    auto bytes = static_cast<uint8_t*>(alloc(total));
    if (!bytes)
        return false;
    memset(bytes, 0, total);
    bytes[0] = 1;
    bytes[2] = 0x5e;
    bytes[3] = (destination >> 16) & 0x7f;
    bytes[4] = destination >> 8;
    bytes[5] = destination;
    memcpy(bytes + 6, info->mac, 6);
    ip4::put16(bytes + 12, 0x0800);
    auto ip = bytes + ethernet_header;
    ip[0] = 0x46;
    ip[1] = 0xc0;
    ip4::put16(ip + 2, 24 + length);
    ip4::put16(ip + 4, ++identifier);
    ip[8] = 1;
    ip[9] = 2;
    ip4::put32(ip + 12, config->address);
    ip4::put32(ip + 16, destination);
    ip[20] = 0x94;
    ip[21] = 4;
    ip4::put16(ip + 10, ip4::checksum(ip, 24));
    memcpy(ip + 24, payload, length);
    *slot = {nullptr, bytes, total, index, destination, ticks + retry_interval * 4, true, false};
    slot->use_path_mtu = false;
    return true;
}

void ipv4_detach_owner(InetSocket* owner) {
    for (auto& item : output)
        if (item.owner == owner)
            item.owner = nullptr;
}

void ipv4_discard_oversized(InetSocket* owner, uint16_t mtu) {
    if (!owner || mtu < 68)
        return;
    for (auto& item : output)
        if (item.owner == owner && item.bytes && ip4::get16(item.bytes + ethernet_header + 2) > mtu)
            clear(item);
}

void ipv4_receive(const NetInfo& info, const void* data, size_t length) {
    const auto frame = static_cast<const uint8_t*>(data);
    if (!info.administrative || !info.live || length < ethernet_header)
        return;
    bool broadcast = true;
    for (unsigned i = 0; i < 6; i++)
        broadcast &= frame[i] == 0xff;
    bool multicast = false;
    if (length >= ethernet_header + 20 && ip4::get16(frame + 12) == 0x0800) {
        uint32_t group = ip4::get32(frame + ethernet_header + 16);
        uint8_t mac[6]{
            1, 0, 0x5e, uint8_t((group >> 16) & 0x7f), uint8_t(group >> 8), uint8_t(group)};
        multicast = ip4::multicast(group) && !memcmp(frame, mac, 6) &&
                    ipv4_multicast_member(info.index, group);
    }
    if (!broadcast && !multicast && memcmp(frame, info.mac, 6))
        return;
    auto type = ip4::get16(frame + 12);
    if (type == 0x0806)
        arp_receive(info, frame, length);
    else if (type == 0x0800)
        input(info.index, frame + ethernet_header, length - ethernet_header, broadcast);
}

void ipv4_poll() {
    if (polling)
        return;
    polling = true;
    ipv4_multicast_poll();
    ip4::reassembly_expire(ticks, reassembly_timeout);
    for (auto& neighbor : neighbors) {
        if (neighbor.state != NeighborState::resolving || !neighbor_pending(neighbor) ||
            ticks < neighbor.next)
            continue;
        if (neighbor.attempts == 3) {
            neighbor.state = NeighborState::failed;
            neighbor.expires = ticks + retry_interval;
            continue;
        }
        auto info = net_info(neighbor.index);
        auto config = ipv4_config(neighbor.index);
        if (!info || !config || !info->live || !info->administrative || !info->carrier)
            continue;
        uint8_t frame[60];
        uint32_t source = config->address;
        for (const auto& item : output)
            if (item.bytes && !item.local && !item.ethernet_ready && item.index == neighbor.index &&
                item.next_hop == neighbor.address && item.expires > ticks) {
                source = ip4::get32(item.bytes + ethernet_header + 12);
                break;
            }
        if (!source)
            source = preferred_source(neighbor.index, neighbor.address);
        arp_frame(frame, *info, 1, nullptr, source, neighbor.address);
        int error = net_send(neighbor.index, frame, sizeof(frame));
        if (!error) {
            neighbor.request_source = source;
            neighbor.attempts++;
            neighbor.next = ticks + retry_interval;
        }
    }
    for (auto& item : output) {
        if (!item.bytes)
            continue;
        auto packet = item.bytes + ethernet_header;
        bool multicast = ip4::multicast(ip4::get32(packet + 16));
        if (item.local || (multicast && item.multicast_loop && !item.looped)) {
            item.looped = true;
            item.submitting = true;
            if (!multicast || item.multicast_loop)
                input(item.index, packet, item.length - ethernet_header, false, multicast);
            item.submitting = false;
            if (item.local || item.discard_pending) {
                clear(item, item.deferred_error);
                continue;
            }
        }
        if (multicast && !packet[8]) {
            clear(item);
            continue;
        }
        auto info = net_info(item.index);
        if (!info || !info->live || !info->administrative || !info->carrier) {
            clear(item, !info || !info->live ? 5 : 100);
            continue;
        }
        if (ticks >= item.expires) {
            clear(item, item.ethernet_ready ? 105 : 113);
            continue;
        }
        if (!item.ethernet_ready) {
            auto neighbor = find_neighbor(item.index, item.next_hop);
            if (!neighbor || neighbor->state == NeighborState::failed) {
                clear(item, 113);
                continue;
            }
            if (neighbor->state != NeighborState::reachable)
                continue;
            memcpy(item.bytes, neighbor->mac, 6);
            item.ethernet_ready = true;
            neighbor->touched = ticks;
        }
        // Bound work per datagram without consuming one output slot per fragment.
        // Cursor progress follows accepted frames, so EAGAIN retries the same bytes.
        for (unsigned budget = 0; budget < 8; budget++) {
            item.submitting = true;
            auto submitted = submit(item, *info);
            int error = submitted.error;
            item.submitting = false;
            if (item.discard_pending) {
                int failure = item.deferred_error;
                // Obsolete packet size and queue pressure do not fail a recovered TCP
                // stream. Preserve independent device or route failures.
                if (!failure && error < 0 && error != -11 && error != -90)
                    failure = -error;
                clear(item, failure);
                break;
            }
            if (error == -11)
                break;
            if (error || submitted.complete) {
                clear(item, error < 0 ? -error : 0);
                break;
            }
            item.fragment_offset += submitted.consumed;
        }
    }
    polling = false;
    tcp_poll();
}

void ipv4_shutdown() {
    ip4::reassembly_discard();
    path_mtu.discard();
    retire_destinations();
    for (auto& item : output)
        if (item.bytes)
            clear(item);
    for (auto& entry : neighbors)
        entry = {};
}
} // namespace ax
