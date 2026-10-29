// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../net/ipv4/socket.hpp"
#include "net/ipv4_wire.hpp"
#include <cassert>
#include <cstdio>
#include <initializer_list>
#include <vector>

using namespace ax;

namespace {
size_t append(uint8_t* bytes, size_t at, unsigned level, unsigned type, const void* value,
              size_t length) {
    struct Header {
        uint64_t length;
        uint32_t level, type;
    } header{16 + length, level, type};

    static_assert(sizeof(header) == 16);
    memcpy(bytes + at, &header, sizeof(header));
    memcpy(bytes + at + sizeof(header), value, length);
    return at + ((sizeof(header) + length + 7) & ~size_t(7));
}

InetAddress target() {
    return {2, __builtin_bswap16(uint16_t(45019)), __builtin_bswap32(uint32_t(0x7f000001)), {}};
}

void immutable_packet(InetSocket* sender, InetSocket* observer, InetSocket* receiver) {
    uint8_t control[128]{};
    int ttl = 37, tos = 184;
    uint32_t info[] = {ipv4_loopback, __builtin_bswap32(uint32_t(0x7f000002)), 0xdeadbeef};
    size_t length = append(control, 0, 0, 2, &ttl, sizeof(ttl));
    length = append(control, length, 0, 1, &tos, sizeof(tos));
    length = append(control, length, 0, 8, info, sizeof(info));
    auto address = target();
    InetSendControl selected;
    assert(inet_prepare_send(sender, address, true, sizeof(address), 8, control, length,
                             selected) == 0);
    assert(sender->local_port && sender->local == 0 && sender->index == 0 && sender->ttl == 63 &&
           sender->tos == 34);
    assert(selected.source.address == 0x7f000002 && selected.source.selected &&
           selected.index == ipv4_loopback && selected.ttl == 37 && selected.tos == 184 &&
           !selected.cache_destination);
    const uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    assert(inet_send_admit(sender, address, sizeof(payload), selected) == 0);
    sender->ttl = 11;
    sender->tos = 8;
    sender->transmitted = sender->send_limit;
    assert(inet_send_ready(sender, sizeof(payload)) == -11);
    assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) == -11);
    assert(!inet_front(observer) && !inet_front(receiver));
    inet_reclaim(sender, sender->send_limit);
    assert(inet_send_ready(sender, sizeof(payload)) == 0);
    assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) ==
           sizeof(payload));
    sender->ttl = 99;
    sender->tos = 252;
    ipv4_poll();
    const auto* packet = inet_front(observer);
    assert(packet && packet->length == 36);
    const auto* ip = inet_bytes(packet);
    assert(ip[0] == 0x45 && ip[1] == 184 && ip[8] == 37 && ip[9] == 17 &&
           ip4::get32(ip + 12) == 0x7f000002 && ip4::get32(ip + 16) == 0x7f000001 &&
           !ip4::checksum(ip, 20));
    assert(ip4::get16(ip + 20) == sender->local_port && ip4::get16(ip + 22) == 45019 &&
           !memcmp(ip + 28, payload, sizeof(payload)));
    const auto* delivered = inet_front(receiver);
    assert(delivered && delivered->length == sizeof(payload) &&
           !memcmp(inet_bytes(delivered), payload, sizeof(payload)));
    inet_consume(observer);
    inet_consume(receiver);
    address = target();
    InetSendControl defaults;
    assert(inet_prepare_send(sender, address, true, sizeof(address), 8, nullptr, 0, defaults) == 0);
    assert(defaults.ttl == 99 && defaults.tos == 252 && defaults.index == 0 &&
           !defaults.source.selected);
}

void scalar_and_route_controls(InetSocket* sender) {
    unsigned checked = 0;
    for (unsigned option : {1u, 2u})
        for (int value : {-1, 0, 1, 255, 256})
            for (size_t width : {size_t(1), size_t(3), size_t(4), size_t(5)}) {
                uint8_t bytes[32]{};
                int64_t payload = value;
                size_t length = append(bytes, 0, 0, option, &payload, width);
                auto address = target();
                InetSendControl output;
                bool accepted = width == 4 && value >= (option == 2 ? 1 : 0) && value <= 255;
                if (option == 1 && width == 1)
                    accepted = true; // An unsigned byte carries its complete scalar value.
                int error = inet_prepare_send(sender, address, true, sizeof(address), 8, bytes,
                                              length, output);
                assert(error == (accepted ? 0 : -22));
                if (accepted) {
                    int expected = width == 1 ? uint8_t(value) : value;
                    assert((option == 1 ? output.tos : output.ttl) == expected);
                }
                checked++;
            }
    for (unsigned row = 0; row < 5; row++) {
        uint8_t bytes[64]{};
        uint32_t info[] = {
            row == 0 ? 999999u : ipv4_loopback,
            __builtin_bswap32(row == 1 || row == 2 ? uint32_t(0xcb007108) : uint32_t(0x7f000002)),
            0};
        if (row == 2)
            info[0] = 999999;
        size_t length = append(bytes, 0, 0, 8, info, sizeof(info));
        if (row == 3) {
            info[0] = info[1] = 0;
            length = append(bytes, length, 0, 8, info, sizeof(info));
        }
        auto address = target();
        InetSendControl output;
        assert(inet_prepare_send(sender, address, true, sizeof(address), 8, bytes, length,
                                 output) == 0);
        int admitted = inet_send_admit(sender, address, 8, output);
        assert(admitted == (row == 0 ? -19 : row == 1 || row == 2 ? -101 : 0));
        if (row == 3)
            assert(output.index == ipv4_loopback && !output.source.selected);
        if (row == 4) {
            assert(inet_send_admit(sender, address, 65508, output) == -90);
            address.address = 0;
            assert(inet_prepare_send(sender, address, true, sizeof(address), 8, bytes, length,
                                     output) == 0);
            assert(inet_send_admit(sender, address, 8, output) == 0);
            assert(__builtin_bswap32(address.address) == 0x7f000002);
        }
    }
    std::printf("IPV4_SEND_CONTROL_POLICY_PASS scalar_cases=%u route_cases=5 immutable=checked\n",
                checked);
}

void retained_route(std::vector<std::vector<uint8_t>>& frames) {
    constexpr uint32_t first = 0xc0000202, second = 0xc6120002, peer = 0xcb007109;
    assert(ipv4_configure(1, {first, 0xffffff00, 0}) == 0);
    assert(ipv4_configure(2, {second, 0xffffff00, 0}) == 0);
    // Keep the device's FIB owner alive while withdrawing the selected source.
    // Removing the final address is a separate retirement case below.
    assert(ipv4_address_add(1, "eth0:survivor", {first + 256, 0xffffff00, 0}) == 0);
    Ipv4Route first_route{peer, 0xffffffff, 0, 1, 10};
    Ipv4Route second_route{peer, 0xffffffff, 0, 2, 20};
    assert(ipv4_route(first_route, false) == 0 && ipv4_route(second_route, false) == 0);
    auto sender = inet_allocate(2);
    assert(sender);
    sender->ttl = 63;
    sender->tos = 34;
    InetAddress address{2, __builtin_bswap16(uint16_t(49157)), __builtin_bswap32(peer), {}};
    uint8_t bytes[64]{};
    int ttl = 37, tos = 184;
    size_t length = append(bytes, 0, 0, 2, &ttl, sizeof(ttl));
    length = append(bytes, length, 0, 1, &tos, sizeof(tos));
    InetSendControl selected;
    const uint8_t payload[8] = {'R', 'O', 'U', 'T', 'E', 1, 2, 3};
    assert(inet_prepare_send(sender, address, true, sizeof(address), sizeof(payload), bytes, length,
                             selected) == 0);
    assert(inet_send_admit(sender, address, sizeof(payload), selected) == 0);
    assert(selected.route.path.index == 1 && selected.route.path.source == first);
    sender->transmitted = sender->send_limit;
    assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) == -11);
    assert(ipv4_route(second_route, true) == 0);
    second_route.metric = 1;
    assert(ipv4_route(second_route, false) == 0);
    assert(ipv4_address_remove(1, first, 0xffffff00) == 0);
    sender->ttl = 11;
    sender->tos = 8;
    inet_reclaim(sender, sender->send_limit);
    assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) ==
           sizeof(payload));

    auto deliver = [&](unsigned index, uint32_t source, uint8_t hops, uint8_t traffic) {
        size_t began = frames.size();
        ipv4_poll();
        const std::vector<uint8_t>* request = nullptr;
        for (size_t at = began; at < frames.size(); at++) {
            const auto& frame = frames[at];
            if (ip4::get16(frame.data() + 12) == 0x0806 && frame[11] == index &&
                ip4::get32(frame.data() + 28) == source && ip4::get32(frame.data() + 38) == peer)
                request = &frame;
        }
        assert(request);
        auto reply = *request;
        const uint8_t hardware[6] = {2, 0x66, 0x77, 0x88, 0x99, uint8_t(index)};
        const auto info = net_info(index);
        memcpy(reply.data(), info->mac, 6);
        memcpy(reply.data() + 6, hardware, 6);
        ip4::put16(reply.data() + 20, 2);
        memcpy(reply.data() + 22, hardware, 6);
        ip4::put32(reply.data() + 28, peer);
        memcpy(reply.data() + 32, info->mac, 6);
        ip4::put32(reply.data() + 38, source);
        ipv4_receive(*info, reply.data(), reply.size());
        ipv4_poll();
        bool found = false;
        for (size_t at = began; at < frames.size(); at++) {
            const auto& frame = frames[at];
            if (ip4::get16(frame.data() + 12) != 0x0800 || frame[11] != index || frame[23] != 17 ||
                ip4::get16(frame.data() + 16) != 36 ||
                memcmp(frame.data() + 42, payload, sizeof(payload)))
                continue;
            assert(ip4::get32(frame.data() + 26) == source &&
                   ip4::get32(frame.data() + 30) == peer && frame[22] == hops &&
                   frame[15] == traffic && !ip4::checksum(frame.data() + 14, 20));
            found = true;
        }
        assert(found);
    };
    deliver(1, first, 37, 184);
    InetSendControl later;
    assert(inet_prepare_send(sender, address, true, sizeof(address), sizeof(payload), nullptr, 0,
                             later) == 0);
    assert(inet_send_admit(sender, address, sizeof(payload), later) == 0);
    assert(later.route.path.index == 2 && later.route.path.source == second);
    assert(inet_send(sender, address, payload, sizeof(payload), true, &later) == sizeof(payload));
    deliver(2, second, 11, 8);
    assert(ipv4_route(first_route, true) == 0);
    assert(ipv4_route(second_route, true) == 0);
    assert(ipv4_address_remove(1, first + 256, 0xffffff00) == 0);
    inet_dispose(sender);
    std::puts(
        "IPV4_SEND_RETAINED_ROUTE_PASS pressure route-preference source-removal later-selection");
}

void retired_route(std::vector<std::vector<uint8_t>>& frames) {
    constexpr uint32_t source = 0xc0000202, peer = 0xcb007109;
    assert(ipv4_configure(1, {source, 0xffffff00, 0}) == 0);
    Ipv4Route original{peer, 0xffffffff, 0, 1, 10};
    Ipv4Route sibling{peer + 1, 0xffffffff, 0, 1, 10};
    assert(ipv4_route(original, false) == 0 && ipv4_route(sibling, false) == 0);
    for (unsigned kind : {2u, 3u}) {
        auto sender = inet_allocate(kind);
        assert(sender);
        sender->protocol = 17;
        InetAddress address{2, __builtin_bswap16(uint16_t(49157)), __builtin_bswap32(peer), {}};
        const uint8_t payload[8] = {'R', 'E', 'T', 'I', 'R', 'E', 1, 2};
        InetSendControl selected;
        assert(inet_prepare_send(sender, address, true, sizeof(address), sizeof(payload), nullptr,
                                 0, selected) == 0);
        assert(inet_send_admit(sender, address, sizeof(payload), selected) == 0);
        assert(selected.route.path_owner);
        assert(ipv4_route(original, true) == 0);
        // Removing one prefix does not retire the shared next-hop owner.
        size_t queued = frames.size();
        assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) ==
               sizeof(payload));
        assert(sender->transmitted == sizeof(payload) + (kind == 2 ? 28 : 20));
        ipv4_poll();
        if (sender->transmitted) {
            const std::vector<uint8_t>* request = nullptr;
            for (size_t at = queued; at < frames.size(); at++) {
                const auto& frame = frames[at];
                if (ip4::get16(frame.data() + 12) == 0x0806 && frame[11] == 1 &&
                    ip4::get32(frame.data() + 38) == peer)
                    request = &frame;
            }
            assert(request);
            auto reply = *request;
            const uint8_t hardware[6] = {2, 0x66, 0x77, 0x88, 0x99, 1};
            const auto info = net_info(1);
            memcpy(reply.data(), info->mac, 6);
            memcpy(reply.data() + 6, hardware, 6);
            ip4::put16(reply.data() + 20, 2);
            memcpy(reply.data() + 22, hardware, 6);
            ip4::put32(reply.data() + 28, peer);
            memcpy(reply.data() + 32, info->mac, 6);
            ip4::put32(reply.data() + 38, source);
            ipv4_receive(*info, reply.data(), reply.size());
            ipv4_poll();
        }
        assert(sender->transmitted == 0);
        unsigned delivered = 0;
        for (size_t at = queued; at < frames.size(); at++) {
            const auto& frame = frames[at];
            if (ip4::get16(frame.data() + 12) == 0x0800 && frame[11] == 1 &&
                ip4::get32(frame.data() + 30) == peer)
                delivered++;
        }
        assert(delivered == 1);
        inet_dispose(sender);
        sender = inet_allocate(kind);
        assert(sender);
        sender->protocol = 17;
        assert(ipv4_route(sibling, true) == 0);
        assert(ipv4_route(original, false) == 0);
        // Recreating an identical route must not revive the retired owner.
        size_t before = frames.size();
        for (unsigned attempt = 0; attempt < 128; attempt++) {
            assert(inet_send(sender, address, payload, sizeof(payload), true, &selected) ==
                   sizeof(payload));
            assert(sender->transmitted == 0);
            ipv4_poll();
        }
        assert(frames.size() == before && ipv4_output_ready());
        inet_dispose(sender);
        assert(ipv4_route(sibling, false) == 0);
    }
    assert(ipv4_route(original, true) == 0 && ipv4_route(sibling, true) == 0);
    std::puts("IPV4_SEND_RETIRED_ROUTE_PASS shared-owner final-removal no-revival no-quota-leak");
}

void global_output_pressure() {
    auto socket = inet_allocate(3);
    assert(socket);
    socket->protocol = 17;
    const uint8_t payload[8] = {};
    auto address = target();
    unsigned accepted = 0;
    while (ipv4_output_ready() && accepted < 32) {
        assert(inet_send(socket, address, payload, sizeof(payload), true) == sizeof(payload));
        accepted++;
    }
    assert(accepted && !ipv4_output_ready());
    // Socket memory permits importing bytes even when the bounded output table
    // is full. That later wait owns the already copied payload.
    assert(inet_send_ready(socket, sizeof(payload)) == 0);
    assert(inet_send(socket, address, payload, sizeof(payload), true) == -11);
    ipv4_poll();
    assert(ipv4_output_ready());
    inet_dispose(socket);
    std::puts("IPV4_SEND_GLOBAL_PRESSURE_PASS socket-memory-before-owned-output-wait");
}

void automatic_prefix() {
    constexpr uint32_t source = 0xc0000202, peer = 0xc0000209, mask = 0xffffff00;
    assert(ipv4_configure(1, {source, mask, 0}) == 0);
    Ipv4Route entries[65];
    size_t count = ipv4_routes(entries, 65);
    bool preferred = false;
    for (size_t n = 0; n < count; n++)
        preferred |= entries[n].index == 1 && entries[n].mask == mask &&
                     entries[n].preferred_source == source;
    assert(preferred);
    auto socket = inet_allocate(2);
    assert(socket);
    InetAddress address{2, __builtin_bswap16(uint16_t(49157)), __builtin_bswap32(peer), {}};
    InetSendControl selected;
    assert(inet_prepare_send(socket, address, true, sizeof(address), 8, nullptr, 0, selected) == 0);
    assert(inet_send_admit(socket, address, 8, selected) == 0);
    Ipv4Route prefix{source & mask, mask, 0, 1, 0, 2, 253};
    assert(ipv4_route_control(prefix, true, false) == 0);
    assert(ipv4_local(source));
    Ipv4Path path{};
    assert(ipv4_path(0, peer, 0, path) == -101);
    const uint8_t payload[8] = {'P', 'R', 'E', 'F', 'I', 'X', 1, 2};
    assert(inet_send(socket, address, payload, sizeof(payload), true, &selected) ==
           sizeof(payload));
    assert(socket->transmitted == 0);
    // A no-op configuration and secondary edits must not resurrect a deleted
    // prefix while its original primary address remains assigned.
    assert(ipv4_configure(1, {source, mask, 0}) == 0);
    assert(ipv4_address_add(1, "eth0:held", {source + 40, mask, 0}) == 0);
    assert(ipv4_address_remove(1, source + 40, mask) == 0);
    assert(ipv4_path(0, peer, 0, path) == -101);
    assert(ipv4_route_control(prefix, false, true) == 0);
    InetSendControl recreated;
    assert(inet_prepare_send(socket, address, true, sizeof(address), 8, nullptr, 0, recreated) ==
           0);
    assert(inet_send_admit(socket, address, 8, recreated) == 0);
    assert(recreated.route.path.index == 1 && recreated.route.path.source == source &&
           recreated.route.path_owner != selected.route.path_owner);
    assert(inet_send(socket, address, payload, sizeof(payload), true, &selected) ==
           sizeof(payload));
    assert(socket->transmitted == 0);
    assert(ipv4_route_control(prefix, true, false) == 0);
    assert(ipv4_address_remove(1, source, mask) == 0);
    assert(ipv4_configure(1, {source, mask, 0}) == 0);
    assert(ipv4_path(0, peer, 0, path) == 0 && path.index == 1 && path.source == source);
    inet_dispose(socket);
    std::puts("IPV4_SEND_AUTOMATIC_PREFIX_PASS deletion tombstone recreation address-cycle");
}

void device_lifecycle() {
    constexpr uint32_t source = 0xc0000202, mask = 0xffffff00;
    const uint8_t payload[8] = {8, 0, 0, 0, 0x71, 0x19, 0, 1};
    for (unsigned type : {2u, 3u})
        for (unsigned basis = 0; basis < 3; basis++) {
            assert(ipv4_configure(1, {source, mask, 0}) == 0);
            uint32_t peer = basis ? 0xcb007109 : 0xc0000209;
            Ipv4Route direct{peer, 0xffffffff, 0, 1, 10, 4, 253};
            if (basis == 1)
                assert(ipv4_route_control(direct, false, true) == 0);
            auto socket = inet_allocate(type);
            assert(socket);
            if (type == 3)
                socket->protocol = 1;
            if (basis == 2)
                socket->index = 1;
            InetAddress address{
                2, __builtin_bswap16(uint16_t(type == 2 ? 49157 : 0)), __builtin_bswap32(peer), {}};
            InetSendControl selected;
            assert(inet_prepare_send(socket, address, true, sizeof(address), sizeof(payload),
                                     nullptr, 0, selected) == 0);
            assert(inet_send_admit(socket, address, sizeof(payload), selected) == 0);
            assert(bool(selected.route.path_owner) == (basis != 2));
            const uint32_t mtu = net_info(1)->mtu;
            assert(net_configure(1, false, mtu) == 0);
            Ipv4Route inventory[65];
            size_t count = ipv4_routes(inventory, 65);
            for (size_t n = 0; n < count; n++)
                assert(inventory[n].index != 1);
            assert(inet_send(socket, address, payload, sizeof(payload), true, &selected) ==
                   sizeof(payload));
            assert(socket->transmitted == 0 && socket->error == 0);
            assert(net_configure(1, true, mtu) == 0);
            assert(inet_send(socket, address, payload, sizeof(payload), true, &selected) ==
                   sizeof(payload));
            assert(socket->transmitted ==
                   (basis == 2 ? sizeof(payload) + (type == 2 ? 28 : 20) : 0));
            // Local output loss releases queued socket memory without becoming
            // an asynchronous UDP/raw error, including the retained fallback.
            assert(net_configure(1, false, mtu) == 0);
            assert(socket->transmitted == 0 && socket->error == 0);
            assert(net_configure(1, true, mtu) == 0);
            inet_dispose(socket);
        }

    assert(ipv4_configure(1, {source, mask, 0}) == 0);
    Ipv4Route direct{0xcb007109, 0xffffffff, 0, 1, 10, 4, 253};
    assert(ipv4_route_control(direct, false, true) == 0);
    auto socket = inet_allocate(2);
    assert(socket);
    InetAddress address{
        2, __builtin_bswap16(uint16_t(49157)), __builtin_bswap32(direct.destination), {}};
    InetSendControl selected;
    assert(inet_prepare_send(socket, address, true, sizeof(address), sizeof(payload), nullptr, 0,
                             selected) == 0);
    assert(inet_send_admit(socket, address, sizeof(payload), selected) == 0);
    Ipv4Route preferred{direct.destination, direct.mask, 0, 2, 1, 4, 253};
    assert(ipv4_route_control(preferred, false, true) == 0);
    assert(ipv4_address_remove(1, source, mask) == 0);
    assert(ipv4_configure(1, {source, mask, 0}) == 0);
    assert(inet_send(socket, address, payload, sizeof(payload), true, &selected) ==
           sizeof(payload));
    assert(socket->transmitted == 0 && socket->error == 0);
    assert(ipv4_route_control(direct, true, false) == -3);
    InetSendControl later;
    assert(inet_prepare_send(socket, address, true, sizeof(address), sizeof(payload), nullptr, 0,
                             later) == 0);
    assert(inet_send_admit(socket, address, sizeof(payload), later) == 0 &&
           later.route.path.index == 2);
    assert(ipv4_route_control(preferred, true, false) == 0);
    inet_dispose(socket);
    std::puts("IPV4_SEND_DEVICE_LIFETIME_PASS fib-retirement retained-fallback silent-local-loss "
              "last-address");
}
} // namespace

void ipv4_send_control_cases(std::vector<std::vector<uint8_t>>& frames) {
    auto sender = inet_allocate(2);
    auto observer = inet_allocate(3);
    auto receiver = inet_allocate(2);
    assert(sender && observer && receiver);
    sender->ttl = 63;
    sender->tos = 34;
    observer->protocol = 17;
    observer->index = receiver->index = ipv4_loopback;
    receiver->local = 0x7f000001;
    receiver->local_port = 45019;
    assert(inet_send_prefix(sender) == 0 && inet_send_prefix(observer) == 0);
    immutable_packet(sender, observer, receiver);
    scalar_and_route_controls(sender);
    observer->protocol = 1;
    assert(inet_send_prefix(observer) == 2);
    observer->transmitted = observer->send_limit;
    assert(inet_send_ready(observer, 8) == -105);
    assert(inet_send(observer, target(), nullptr, 8, true) == -105);
    inet_reclaim(observer, observer->send_limit);
    for (auto socket : {sender, observer, receiver})
        inet_dispose(socket);
    retained_route(frames);
    retired_route(frames);
    global_output_pressure();
    automatic_prefix();
    device_lifecycle();
}
