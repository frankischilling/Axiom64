// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "core/time.hpp"
#include "net/tcp/connection.hpp"
#include "../../net/ipv4/socket.hpp"
#include <cassert>
#include <cstdio>

void tcp_ipv6_socket_tests() {
    using namespace ax;
    ip6::Address loop;
    loop.bytes[15] = 1;
    auto listener = inet_allocate(1);
    assert(listener);
    listener->ipv6 = listener->wire6 = listener->v6only = true;
    listener->local6 = loop;
    listener->bound = true;
    assert(!inet_bind_port(listener, 0, 49200));
    assert(!tcp_listen(listener, 4));
    auto client = inet_allocate(1);
    assert(client);
    client->ipv6 = client->wire6 = true;
    Inet6Address destination;
    destination.address = loop;
    destination.port = __builtin_bswap16(uint16_t(49200));
    assert(tcp6_connect(client, destination) == -115);
    for (unsigned n = 0; n < 8; n++) {
        ipv6_poll();
        tcp_poll();
    }
    assert(!tcp_connect_result(client));
    assert(listener->accept_count == 1);
    auto child = listener->accepted[0];
    assert(child->ipv6 && child->wire6 && child->local6 == loop && child->peer6 == loop);
    unsigned char sent[513], received[513];
    for (unsigned n = 0; n < sizeof(sent); n++)
        sent[n] = uint8_t(n * 29);
    assert(tcp_write(client, sent, 127, false) == 127);
    assert(tcp_write(client, sent + 127, 386, false) == 386);
    tcp_poll();
    ipv6_poll();
    auto count = tcp_read(child, received, sizeof(received), true);
    printf("TCP6_VECTOR_OBSERVED actual=%lld expected=513\n", static_cast<long long>(count));
    fflush(stdout);
    assert(count == sizeof(received));
    assert(!memcmp(sent, received, sizeof(sent)));
    assert(tcp_read(child, received, sizeof(received)) == sizeof(received));
    assert(!tcp_shutdown(client, 1));
    for (unsigned n = 0; n < 8; n++) {
        ipv6_poll();
        tcp_poll();
    }
    assert(tcp_read(child, received, sizeof(received)) == 0);
    assert(tcp_write(child, sent, 21) == 21);
    assert(!tcp_shutdown(child, 1));
    for (unsigned n = 0; n < 8; n++) {
        ipv6_poll();
        tcp_poll();
    }
    assert(tcp_read(client, received, sizeof(received)) == 21);
    assert(!memcmp(sent, received, 21));
    assert(tcp_read(client, received, sizeof(received)) == 0);
    assert(client->stream->state() == tcp::State::time_wait);
    uint16_t port = client->local_port;
    uint64_t deadline = client->stream->time_wait_state().deadline;
    inet_close(client);
    tcp_poll();
    ipv6_poll();
    tcp_poll();
    assert(!client->used);
    assert(tcp_port_busy({tcp::Address::ipv6(loop), 0, false}, port, false));
    assert(!tcp_port_busy(0x7f000001, port, 0, false));
    auto other = loop;
    other.bytes[0] = 0x20;
    assert(!tcp_port_busy({tcp::Address::ipv6(other), 0, false}, port, false));
    assert(tcp_port_busy({tcp::Address::ipv6({}), 0, true}, port, false));
    ticks = deadline / 10 + 1;
    assert(!tcp_port_busy({tcp::Address::ipv6(loop), 0, false}, port, false));
    // Retire the unaccepted peer only after the timer check: listener close
    // deliberately resets that child and would invalidate the peer TIME_WAIT.
    inet_close(listener);
    tcp_poll();
    ipv6_poll();
    tcp_poll();

    // Socket domains share the IPv4 wire identity, while V6ONLY wildcards only
    // overlap IPv6. Addresses with equal low words remain distinct IPv6 owners.
    for (unsigned only = 0; only < 2; only++) {
        auto six = inet_allocate(1), four = inet_allocate(1);
        assert(six && four);
        six->ipv6 = six->wire6 = true;
        six->v6only = only;
        assert(!inet_bind_port(six, 0, 49300));
        assert(inet_bind_port(four, 0, 49300) == (only ? 0 : -98));
        inet_close(four);
        inet_close(six);
    }
    auto six = inet_allocate(1), four = inet_allocate(1), different = inet_allocate(1);
    assert(six && four && different);
    six->ipv6 = true;
    six->wire6 = false;
    six->local = 0x7f000001;
    assert(!inet_bind_port(six, six->local, 49300));
    assert(inet_bind_port(four, 0x7f000001, 49300) == -98);
    different->ipv6 = different->wire6 = true;
    different->local6 = other;
    assert(!inet_bind_port(different, 0, 49300));
    inet_close(different);
    inet_close(four);
    inet_close(six);
    // A wildcard listener captures the incoming link's scope in its child.
    ip6::Address local{{0xfe, 0x80}}, remote{{0xfe, 0x80}};
    local.bytes[15] = 2;
    remote.bytes[15] = 1;
    assert(!ipv6_address_add({local, 1, 0x82, 64}));
    auto scoped = inet_allocate(1);
    assert(scoped);
    scoped->ipv6 = scoped->wire6 = scoped->v6only = true;
    assert(!inet_bind_port(scoped, 0, 49400));
    assert(!tcp_listen(scoped, 4));
    uint8_t frame[14 + 40 + 20]{};
    auto info = net_info(1);
    assert(info);
    memcpy(frame, info->mac, 6);
    frame[6] = 2;
    frame[11] = 0x51;
    frame[12] = 0x86;
    frame[13] = 0xdd;
    tcp::Segment syn;
    syn.source = 49500;
    syn.destination = 49400;
    syn.sequence = 0x12345678;
    syn.flags = tcp::syn;
    syn.window = 65535;
    assert(tcp::encode(remote, local, syn, frame + 54, 20) == 20);
    ip6::Header header;
    header.source = remote;
    header.destination = local;
    header.payload_length = 20;
    header.next_header = 6;
    assert(ip6::encode(frame + 14, 40, header));
    frame[70] ^= 1;
    ipv6_receive(*info, frame, sizeof(frame));
    assert(!scoped->children);
    frame[70] ^= 1;
    ipv6_receive(*info, frame, sizeof(frame));
    assert(scoped->children == 1);
    InetSocket* admitted = nullptr;
    for (auto& candidate : inet_sockets)
        if (candidate.used && candidate.listener == scoped)
            admitted = &candidate;
    assert(admitted && admitted->wire6 && admitted->index == 1);
    assert(admitted->local6 == local && admitted->peer6 == remote);
    inet_close(scoped);
    tcp_poll();
    ipv6_shutdown();
    tcp_poll();
    assert(!ipv6_owned(1, local));
    puts("TCP6_SOCKET_SCOPED_INPUT_PASS ethernet bad_checksum wildcard_scope exact_tuple retire");
    puts("TCP6_SOCKET_LOOPBACK_PASS handshake full_tuple copied_vector_prefix half_close "
         "compact_time_wait separate_family expiry dual_stack_port mapped_identity");
}
