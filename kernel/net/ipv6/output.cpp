// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/destination.hpp"
#include "net/ipv6/fragmentation.hpp"
#include "net/inet6.hpp"
#include "core/random.hpp"
#include "net/ipv6/router.hpp"

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
    Ipv6OutputOwner owner;
    uint8_t* fragment_bytes = nullptr;
    size_t fragment_capacity = 0, fragment_offset = 0;
    uint32_t identification = 0, socket_mtu = 0;
    bool fragmentable = true, submitting = false, discard_pending = false;
    bool interface_mtu = false;
    int deferred_error = 0;
    Ipv6SourcePolicy source_policy = Ipv6SourcePolicy::assigned;
    unsigned output_index = 0;
};

Output outputs[32];
size_t queued_bytes;

void clear(Output& item, int error = 0) {
    // Device submission can poll callbacks that cancel the borrowed packet.
    if (item.submitting) {
        item.discard_pending = true;
        if (!item.deferred_error)
            item.deferred_error = error;
        return;
    }
    auto owner = item.owner;
    size_t cost = item.length - ethernet_header;
    unsigned index = item.output_index;
    queued_bytes -= item.length + item.fragment_capacity;
    release(item.bytes);
    release(item.fragment_bytes);
    item = {};
    if (owner.complete)
        owner.complete(owner.identity, cost, error, index);
}

int queue(const ip6::Address& source, const ip6::Address& destination, unsigned index,
          uint8_t protocol, uint8_t hop_limit, const void* data, size_t length, bool direct = false,
          Ipv6OutputOwner owner = {}, bool fragmentable = true, uint32_t socket_mtu = 0,
          bool interface_mtu = false, uint8_t traffic_class = 0,
          const ip6::OutputExtensions* extensions = nullptr,
          const ip6::Address* final_destination = nullptr,
          Ipv6SourcePolicy source_policy = Ipv6SourcePolicy::assigned, unsigned output_index = 0) {
    const ip6::OutputExtensions empty;
    const auto& options = extensions ? *extensions : empty;
    int extra = ip6::output_extension_size(options);
    if (extra < 0)
        return extra;
    if (length > 65535 - size_t(extra))
        return -90;
    Output* selected = nullptr;
    for (auto& entry : outputs)
        if (!entry.bytes) {
            selected = &entry;
            break;
        }
    size_t needed = ethernet_header + ip6::header_size + extra + length;
    if (!selected || needed > 262144 - queued_bytes)
        return -11;
    auto bytes = static_cast<uint8_t*>(alloc(needed));
    if (!bytes)
        return -12;
    memset(bytes, 0, ethernet_header);
    bytes[12] = 0x86;
    bytes[13] = 0xdd;
    uint8_t next = ip6::output_next_header(protocol, options);
    ip6::Header header{source,        destination, 0,        uint16_t(extra + length),
                       traffic_class, next,        hop_limit};
    ip6::encode(bytes + ethernet_header, ip6::header_size, header);
    if (!ip6::encode_output_extensions(bytes + ethernet_header + ip6::header_size, extra, protocol,
                                       options, final_destination)) {
        release(bytes);
        return -22;
    }
    if (length)
        memcpy(bytes + ethernet_header + ip6::header_size + extra, data, length);
    *selected = {source, destination, bytes, needed, index, {}, ticks + 400, direct, owner};
    selected->output_index = output_index;
    selected->fragmentable = fragmentable;
    selected->socket_mtu = socket_mtu;
    selected->interface_mtu = interface_mtu;
    selected->source_policy = source_policy;
    queued_bytes += needed;
    return 0;
}

struct Submission {
    Output& item;
    const Ipv6Path& path;
    size_t length;
    bool fragmented;
};

int validate_submission(void* context) {
    const auto& submission = *static_cast<Submission*>(context);
    const auto& item = submission.item;
    if (item.discard_pending)
        return item.deferred_error ? item.deferred_error : -125;
    if (item.control)
        return ip6::usable(item.index) && ipv6_owned(item.index, item.source) ? 0 : -100;
    Ipv6Path current;
    if (int error = ipv6_path(item.source, item.destination, item.index, current,
                              item.interface_mtu, item.source_policy))
        return error;
    if (item.socket_mtu && (!item.fragmentable || submission.fragmented))
        current.mtu = min(current.mtu, item.socket_mtu);
    if (current.index != submission.path.index || !(current.next_hop == submission.path.next_hop))
        return -11;
    if (submission.length - ethernet_header > current.mtu)
        return item.fragmentable ? -11 : -90;
    return 0;
}

ip6::FragmentPiece submit(Output& item, const Ipv6Path& path) {
    const uint8_t* bytes = item.bytes;
    size_t length = item.length;
    ip6::FragmentPiece part{0, 0, 0, true};
    if (!item.control && (item.fragment_offset || length - ethernet_header > path.mtu)) {
        if (!item.fragmentable)
            return {-90};
        if (!item.identification) {
            for (unsigned attempt = 0; attempt < 8; attempt++) {
                uint32_t candidate;
                if (int error = random_read(&candidate, sizeof(candidate)))
                    return {error};
                if (!candidate)
                    continue;
                bool collision = false;
                for (const auto& other : outputs)
                    collision |= other.bytes && &other != &item &&
                                 other.identification == candidate && other.source == item.source &&
                                 other.destination == item.destination;
                if (!collision) {
                    item.identification = candidate;
                    break;
                }
            }
            if (!item.identification)
                return {-11};
        }
        uint32_t fragment_mtu = item.socket_mtu ? min(path.mtu, item.socket_mtu) : path.mtu;
        size_t needed = ethernet_header + min(size_t(fragment_mtu), size_t(65575));
        if (item.fragment_capacity < needed) {
            queued_bytes -= item.fragment_capacity;
            release(item.fragment_bytes);
            item.fragment_bytes = nullptr;
            item.fragment_capacity = 0;
            if (needed > 262144 - queued_bytes)
                return {-11};
            item.fragment_bytes = static_cast<uint8_t*>(alloc(needed));
            if (!item.fragment_bytes)
                return {-12};
            item.fragment_capacity = needed;
            queued_bytes += needed;
        }
        part = ip6::fragment_packet(
            item.bytes + ethernet_header, item.length - ethernet_header, fragment_mtu,
            item.fragment_offset, item.identification, item.fragment_bytes + ethernet_header,
            item.fragment_capacity - ethernet_header, ip6::FragmentLayout::linux_socket);
        if (part.error)
            return part;
        memcpy(item.fragment_bytes, item.bytes, ethernet_header);
        bytes = item.fragment_bytes;
        length = ethernet_header + part.length;
    }
    item.submitting = true;
    if (path.index == ipv6_loopback) {
        NetInfo loopback;
        loopback.index = ipv6_loopback;
        ipv6_receive(loopback, bytes, length);
    } else {
        Submission submission{item, path, length, bytes != item.bytes};
        part.error = net_send_checked(path.index, bytes, length, validate_submission, &submission);
    }
    item.submitting = false;
    return part;
}

} // namespace

static int send_owned(const ip6::Address& source, const ip6::Address& destination, unsigned bound,
                      uint8_t protocol, int16_t hop_limit, const void* data, size_t length,
                      Ipv6OutputOwner owner, bool fragmentable, uint32_t socket_mtu,
                      bool interface_mtu, uint8_t traffic_class,
                      const ip6::OutputExtensions* extensions, Ipv6SourcePolicy source_policy,
                      Ipv6Destination* retained = nullptr) {
    if (hop_limit < -1 || hop_limit > 255 || bool(owner.identity) != bool(owner.complete))
        return -22;
    const ip6::OutputExtensions empty;
    const auto& options = extensions ? *extensions : empty;
    int extra = ip6::output_extension_size(options);
    ip6::Address first;
    if (extra < 0 || !ip6::output_extension_destination(options, destination, first))
        return -22;
    Ipv6Path path;
    int error = ipv6_path(source, first, bound, path, interface_mtu, source_policy);
    if (error)
        return error;
    if (retained)
        ipv6_destination_store(*retained, path, first);
    if (socket_mtu && !fragmentable)
        path.mtu = min(path.mtu, socket_mtu);
    if (length > 65535 - size_t(extra) ||
        (!fragmentable && length + extra + ip6::header_size > path.mtu))
        return -90;
    uint8_t hops = hop_limit < 0 ? ip6::link_hop_limit(path.index) : hop_limit;
    return queue(path.source, first, bound, protocol, hops, data, length, false, owner,
                 fragmentable, socket_mtu, interface_mtu, traffic_class, extensions, &destination,
                 source_policy, path.index);
}

int ipv6_send(const ip6::Address& source, const ip6::Address& destination, unsigned bound,
              uint8_t protocol, int16_t hop_limit, const void* data, size_t length,
              Inet6Socket* owner, bool fragmentable, uint32_t socket_mtu, bool interface_mtu,
              uint8_t traffic_class, const ip6::OutputExtensions* extensions,
              Ipv6SourcePolicy source_policy) {
    Ipv6OutputOwner completion;
    if (owner)
        completion = {owner, [](void* identity, size_t bytes, int error, unsigned) {
                          inet6_complete(static_cast<Inet6Socket*>(identity), bytes, error);
                      }};
    return send_owned(source, destination, bound, protocol, hop_limit, data, length, completion,
                      fragmentable, socket_mtu, interface_mtu, traffic_class, extensions,
                      source_policy);
}

int ipv6_send_owned(Ipv6OutputOwner owner, const ip6::Address& source,
                    const ip6::Address& destination, unsigned bound, uint8_t protocol,
                    int16_t hop_limit, const void* data, size_t length,
                    Ipv6SourcePolicy source_policy, uint8_t traffic_class,
                    Ipv6Destination* retained) {
    return send_owned(source, destination, bound, protocol, hop_limit, data, length, owner, false,
                      0, false, traffic_class, nullptr, source_policy, retained);
}

bool ipv6_output_ready() {
    for (const auto& item : outputs)
        if (!item.bytes && queued_bytes < 262144 - ethernet_header - ip6::header_size)
            return true;
    return false;
}

void ipv6_discard_oversized(void* identity, uint32_t mtu) {
    if (!identity || mtu < ip6::minimum_mtu)
        return;
    for (auto& item : outputs)
        if (item.bytes && item.owner.identity == identity && item.length - ethernet_header > mtu)
            clear(item, -125);
}

void ipv6_detach_output(void* identity) {
    if (!identity)
        return;
    for (auto& item : outputs)
        if (item.owner.identity == identity)
            item.owner = {};
}

void ipv6_detach_owner(Inet6Socket* owner) {
    ipv6_detach_output(owner);
}

namespace ip6 {
int queue_control(unsigned index, const Address& source, const Address& destination,
                  const void* data, size_t length) {
    return queue(source, destination, index, 58, 255, data, length, true);
}

void output_poll() {
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
            int error = ipv6_path(item.source, item.destination, item.index, path,
                                  item.interface_mtu, item.source_policy);
            if (error) {
                clear(item, error);
                continue;
            }
            if (item.socket_mtu && !item.fragmentable)
                path.mtu = min(path.mtu, item.socket_mtu);
        }
        item.output_index = path.index;
        // RFC 4291 keeps loopback addresses inside the node. Consume admitted
        // bytes before neighbor work, including cached paths and detached owners.
        if (path.index != ipv6_loopback &&
            (path.source.loopback() || item.destination.loopback())) {
            // Preserve deferred EMSGSIZE if the MTU changed after admission.
            clear(item, !item.fragmentable && item.length - ethernet_header > path.mtu ? -90 : 0);
            continue;
        }
        if (path.index == ipv6_loopback) {
            memset(item.mac, 0, sizeof(item.mac));
        } else if (item.destination.multicast())
            ip6::multicast_mac(item.destination, item.mac);
        else if (!ip6::neighbor_resolve(path.index, path.source, path.next_hop, item.mac))
            continue;
        memcpy(item.bytes, item.mac, 6);
        if (path.index != ipv6_loopback)
            memcpy(item.bytes + 6, net_info(path.index)->mac, 6);
        // Bound each datagram's work while filling an available device queue.
        for (unsigned batch = 0; batch < 8; batch++) {
            auto part = submit(item, path);
            if (item.discard_pending) {
                clear(item, item.deferred_error);
                break;
            }
            if (!part.error) {
                item.fragment_offset += part.consumed;
                if (part.complete) {
                    clear(item);
                    break;
                }
            } else {
                if (part.error != -11 && part.error != -100)
                    clear(item, part.error);
                break;
            }
        }
    }
}

void output_shutdown() {
    for (auto& item : outputs)
        if (item.bytes)
            clear(item, -5);
}
} // namespace ip6
} // namespace ax
