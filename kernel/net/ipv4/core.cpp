// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4.hpp"
#include "net/inet.hpp"
#include "process/task.hpp"
#include "wire.hpp"

namespace ax {
namespace {
constexpr unsigned route_count = 32, neighbor_count = 128, output_count = 32;
constexpr uint64_t neighbor_lifetime = 30000, retry_interval = 100;

struct Route {
    Ipv4Route value;
    bool used = false;
};

enum class NeighborState : uint8_t { free, resolving, reachable, failed };

struct Neighbor {
    uint32_t address = 0;
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
};

struct Selection {
    uint32_t source = 0, next_hop = 0;
    unsigned index = 0, prefix = 0, metric = UINT32_MAX;
    bool local = false, broadcast = false, found = false;
};

static Ipv4Config interfaces[max_net_devices + 1];
static Ipv4Config loopback{0x7f000001, 0xff000000, 0};
static Route routes[route_count];
static Neighbor neighbors[neighbor_count];
static Output output[output_count];
static uint16_t identifier;
static bool polling;
static uint64_t next_icmp_error[max_net_devices + 2];

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

static void clear(Output& item, int error = 0) {
    if (item.owner) {
        inet_reclaim(item.owner, ip4::get16(item.bytes + ethernet_header + 2));
        if (error)
            inet_failed(item.owner, error);
    }
    release(item.bytes);
    item = {};
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
            item.next_hop == neighbor.address)
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
    auto config = ipv4_config(info.index);
    if (!config || !config->address || sender == config->address ||
        directed_broadcast(*config, sender))
        return;
    bool ours = target == config->address;
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
    arp_frame(bytes, info, 2, mac, config->address, sender);
    *slot = {nullptr, bytes, 60, info.index, 0, ticks + 100, true, false};
}

static int select(uint32_t source, uint32_t destination, unsigned bound, Selection& result) {
    if (!destination || (!ip4::unicast(destination) && destination != UINT32_MAX))
        return -101;
    if (source && !ipv4_local(source))
        return -99;
    if (is_loopback(source) && !is_loopback(destination))
        return -99;
    if (is_loopback(destination)) {
        if (bound && bound != ipv4_loopback)
            return -101;
        result = {source ? source : loopback.address,
                  destination,
                  ipv4_loopback,
                  8,
                  0,
                  true,
                  false,
                  true};
        return 0;
    }
    if (bound && !ipv4_config(bound))
        return -19;
    for (unsigned index = 1; index <= max_net_devices; index++) {
        auto config = ipv4_config(index);
        if (!config || !config->address || (bound && bound != index))
            continue;
        if (destination == config->address) {
            result = {
                source ? source : config->address, destination, index, 32, 0, true, false, true};
            return 0;
        }
        if (destination == UINT32_MAX || directed_broadcast(*config, destination)) {
            result = {
                source ? source : config->address, destination, index, 32, 0, false, true, true};
            break;
        }
        if ((destination & config->mask) == (config->address & config->mask)) {
            unsigned prefix = prefix_length(config->mask);
            if (!result.found || prefix > result.prefix) {
                result = {
                    source ? source : config->address,        destination, index, prefix, 0, false,
                    directed_broadcast(*config, destination), true};
            }
        }
    }
    for (const auto& route : routes) {
        const auto& value = route.value;
        if (!route.used || (bound && bound != value.index) ||
            (destination & value.mask) != value.destination)
            continue;
        auto config = ipv4_config(value.index);
        if (!config || !config->address)
            continue;
        unsigned prefix = prefix_length(value.mask);
        if (!result.found || prefix > result.prefix ||
            (prefix == result.prefix && value.metric < result.metric))
            result = {source ? source : config->address,
                      value.gateway ? value.gateway : destination,
                      value.index,
                      prefix,
                      value.metric,
                      false,
                      false,
                      true};
    }
    if (!result.found)
        return -101;
    auto info = net_info(result.index);
    if (!info || !info->live)
        return -5;
    if (!info->administrative || !info->carrier)
        return -100;
    return 0;
}

static void protocol_error(unsigned index, uint32_t source, uint32_t destination,
                           const uint8_t* bytes, size_t length) {
    if (ticks < next_icmp_error[index])
        return;
    // IPv4 header plus the first eight original payload bytes, bounded by RX length.
    uint8_t error[36]{};
    error[0] = 3;
    error[1] = 2;
    size_t quoted = min(length, size_t(28));
    memcpy(error + 8, bytes, quoted);
    ip4::put16(error + 2, ip4::checksum(error, 8 + quoted));
    if (!ipv4_send(nullptr, destination, source, index, 1, 64, false, error, 8 + quoted))
        next_icmp_error[index] = ticks + 100;
}

static void quoted_error(unsigned index, const uint8_t* payload, size_t length) {
    if (length < 36)
        return;
    const auto quote = payload + 8;
    if (quote[0] != 0x45 || ip4::get16(quote + 2) < 28 || ip4::checksum(quote, 20) ||
        (ip4::get16(quote + 6) & ~uint16_t(0x4000)) || quote[9] != 1 ||
        !ipv4_local(ip4::get32(quote + 12)) || !ip4::unicast(ip4::get32(quote + 16)))
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
        inet_icmp_error(index, ip4::get32(quote + 12), ip4::get32(quote + 16), error);
}

static void input(unsigned index, const uint8_t* bytes, size_t length,
                  bool link_broadcast = false) {
    if (length < 20 || bytes[0] != 0x45 || ip4::get16(bytes + 2) < 20 ||
        ip4::get16(bytes + 2) > length || ip4::checksum(bytes, 20) || !bytes[8] ||
        (ip4::get16(bytes + 6) & ~uint16_t(0x4000)))
        return;
    length = ip4::get16(bytes + 2);
    uint32_t source = ip4::get32(bytes + 12), destination = ip4::get32(bytes + 16);
    auto config = ipv4_config(index);
    bool local = ipv4_local(destination);
    bool broadcast =
        destination == UINT32_MAX || (config && directed_broadcast(*config, destination));
    if (!config || !ip4::unicast(source) || (!local && !broadcast) ||
        (index != ipv4_loopback &&
         (is_loopback(source) || is_loopback(destination) || directed_broadcast(*config, source))))
        return;
    if (bytes[9] != 1) {
        if (local && !broadcast && !link_broadcast)
            protocol_error(index, source, destination, bytes, length);
        return;
    }
    auto payload = bytes + 20;
    size_t payload_length = length - 20;
    if (payload_length < 8)
        return;
    inet_deliver(index, source, destination, 1, bytes, length);
    if (ip4::checksum(payload, payload_length))
        return;
    if (local && !broadcast && !link_broadcast && (payload[0] == 3 || payload[0] == 12))
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
    return net_info(index) ? &interfaces[index] : nullptr;
}

int ipv4_configure(unsigned index, const Ipv4Config& config) {
    if (!ipv4_config(index))
        return -19;
    if (index == ipv4_loopback)
        return -95;
    if (!ip4::mask_valid(config.mask) ||
        (config.address && (!ip4::unicast(config.address) || is_loopback(config.address))))
        return -22;
    auto changed = config;
    if (!changed.address || changed.mask >= 0xfffffffe)
        changed.broadcast = 0;
    else if (!changed.broadcast)
        changed.broadcast = changed.address | ~changed.mask;
    interfaces[index] = changed;
    for (auto& neighbor : neighbors)
        if (neighbor.index == index)
            neighbor = {};
    for (auto& item : output)
        if (item.bytes && item.index == index)
            clear(item, 100);
    return 0;
}

int ipv4_route(const Ipv4Route& input, bool remove) {
    auto value = input;
    if (!ip4::mask_valid(value.mask) || (value.destination & value.mask) != value.destination)
        return -22;
    if (remove) {
        for (auto& route : routes)
            if (route.used && (!value.index || route.value.index == value.index) &&
                route.value.destination == value.destination && route.value.mask == value.mask &&
                (!value.gateway || route.value.gateway == value.gateway) &&
                (!value.metric || route.value.metric == value.metric)) {
                route = {};
                return 0;
            }
        return -3;
    }
    if (!value.index) {
        unsigned best = 0;
        const uint32_t target = value.gateway ? value.gateway : value.destination;
        for (unsigned index = 1; index <= max_net_devices; index++) {
            const auto config = ipv4_config(index);
            if (config && config->address &&
                (target & config->mask) == (config->address & config->mask) &&
                (!value.index || prefix_length(config->mask) > best)) {
                value.index = index;
                best = prefix_length(config->mask);
            }
        }
        if (!value.index)
            return -101;
    }
    auto config = ipv4_config(value.index);
    if (!config || value.index == ipv4_loopback)
        return -19;
    if (!config->address ||
        (value.gateway &&
         (!ip4::unicast(value.gateway) || is_loopback(value.gateway) ||
          directed_broadcast(*config, value.gateway) || value.gateway == config->address ||
          (value.gateway & config->mask) != (config->address & config->mask))))
        return -101;
    Route* empty = nullptr;
    for (auto& route : routes) {
        if (route.used && route.value.index == value.index &&
            route.value.destination == value.destination && route.value.mask == value.mask &&
            route.value.gateway == value.gateway && route.value.metric == value.metric) {
            return -17;
        }
        if (!route.used && !empty)
            empty = &route;
    }
    if (!empty)
        return -105;
    *empty = {value, true};
    return 0;
}

bool ipv4_local(uint32_t address) {
    if (is_loopback(address))
        return true;
    for (unsigned i = 1; i <= max_net_devices; i++)
        if (net_info(i) && address && interfaces[i].address == address)
            return true;
    return false;
}

bool ipv4_output_ready() {
    return vacant_output() != nullptr;
}

int ipv4_source(uint32_t source, uint32_t destination, unsigned bound_index, uint32_t& selected) {
    Selection route;
    int error = select(source, destination, bound_index, route);
    if (!error)
        selected = route.source;
    return error;
}

int ipv4_send(InetSocket* owner, uint32_t source, uint32_t destination, unsigned bound_index,
              uint8_t protocol, uint8_t ttl, bool broadcast, const void* payload, size_t length) {
    if (!ttl)
        return -22;
    Selection route;
    int error = select(source, destination, bound_index, route);
    if (error)
        return error;
    if (route.broadcast && !broadcast)
        return -13;
    if (length > 65535 - 20 || (!route.local && length + 20 > net_info(route.index)->mtu))
        return -90;
    auto slot = vacant_output();
    if (!slot)
        return -11;
    if (!route.local && !route.broadcast && !prepare_neighbor(route.index, route.next_hop))
        return -105;
    size_t total = max(size_t(60), ethernet_header + 20 + length);
    auto bytes = static_cast<uint8_t*>(alloc(total));
    if (!bytes)
        return -12;
    memset(bytes, 0, total);
    auto ip = bytes + ethernet_header;
    ip[0] = 0x45;
    ip4::put16(ip + 2, 20 + length);
    ip4::put16(ip + 4, ++identifier);
    ip4::put16(ip + 6, 0x4000);
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
        }
    }
    *slot = {owner, bytes,      total, route.index, route.next_hop, ticks + retry_interval * 4,
             ready, route.local};
    return 0;
}

void ipv4_detach_owner(InetSocket* owner) {
    for (auto& item : output)
        if (item.owner == owner)
            item.owner = nullptr;
}

void ipv4_receive(const NetInfo& info, const void* data, size_t length) {
    const auto frame = static_cast<const uint8_t*>(data);
    if (!info.administrative || !info.live || length < ethernet_header)
        return;
    bool broadcast = true;
    for (unsigned i = 0; i < 6; i++)
        broadcast &= frame[i] == 0xff;
    if (!broadcast && memcmp(frame, info.mac, 6))
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
        if (!info || !config || !config->address || !info->live || !info->administrative ||
            !info->carrier)
            continue;
        uint8_t frame[60];
        arp_frame(frame, *info, 1, nullptr, config->address, neighbor.address);
        int error = net_send(neighbor.index, frame, sizeof(frame));
        if (!error) {
            neighbor.attempts++;
            neighbor.next = ticks + retry_interval;
        }
    }
    for (auto& item : output) {
        if (!item.bytes)
            continue;
        if (item.local) {
            input(item.index, item.bytes + ethernet_header, item.length - ethernet_header);
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
        int error = net_send(item.index, item.bytes, item.length);
        if (error != -11)
            clear(item, error < 0 ? -error : 0);
    }
    polling = false;
}

void ipv4_shutdown() {
    for (auto& item : output)
        if (item.bytes)
            clear(item);
    for (auto& entry : neighbors)
        entry = {};
}
} // namespace ax
