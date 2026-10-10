// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/connection.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <deque>
#include <vector>

using namespace ax::tcp;

// Packets cross the real production encoder/checksum/decoder. Each queued packet owns bytes.
struct Packet {
    std::vector<uint8_t> bytes;
    bool from_client;

    Segment segment() const {
        Segment result;
        assert(decode(from_client ? 0xc0000201 : 0xc6336402, from_client ? 0xc6336402 : 0xc0000201,
                      bytes.data(), bytes.size(), result));
        assert(result.source == (from_client ? 49152 : 80));
        assert(result.destination == (from_client ? 80 : 49152));
        return result;
    }
};

static bool output(Connection& endpoint, uint64_t now, bool client, Packet& packet,
                   bool enqueue = true) {
    Segment segment;
    if (!endpoint.next(now, segment))
        return false;
    segment.source = client ? 49152 : 80;
    segment.destination = client ? 80 : 49152;
    packet = {std::vector<uint8_t>(60 + segment.length), client};
    size_t length = encode(client ? 0xc0000201 : 0xc6336402, client ? 0xc6336402 : 0xc0000201,
                           segment, packet.bytes.data(), packet.bytes.size());
    assert(length);
    packet.bytes.resize(length);
    if (enqueue)
        endpoint.emitted(now);
    return true;
}

static Packet require_output(Connection& endpoint, uint64_t now, bool client = true) {
    Packet packet;
    assert(output(endpoint, now, client, packet));
    return packet;
}

static void no_output(Connection& endpoint, uint64_t now) {
    Packet packet;
    assert(!output(endpoint, now, true, packet));
}

static void establish(Connection& client, Connection& server, uint32_t client_seq = 100,
                      uint32_t server_seq = 500, uint16_t mss = 1460) {
    client.active(client_seq, 0, mss);
    Packet candidate;
    assert(output(client, 0, true, candidate, false));
    assert(client.next_send() == client_seq); // Failed enqueue consumes no sequence space.
    assert(output(client, 0, true, candidate, false));
    assert(client.next_send() == client_seq);
    client.emitted(0);
    auto request = candidate.segment();
    assert(request.flags == syn && request.sequence == client_seq &&
           request.maximum_segment == mss);
    assert(server.passive(server_seq, request, 5, mss));
    Packet reply_packet = require_output(server, 5, false);
    auto reply = reply_packet.segment();
    assert(reply.flags == (syn | ack) && reply.sequence == server_seq &&
           reply.acknowledgment == client_seq + 1);
    client.input(reply, 10);
    assert(client.state() == State::established);
    auto acknowledgment = require_output(client, 10).segment();
    assert(acknowledgment.flags == ack && acknowledgment.acknowledgment == server_seq + 1);
    server.input(acknowledgment, 15);
    assert(server.state() == State::established && server.next_receive() == client_seq + 1);
    assert(client.next_receive() == server_seq + 1);
    no_output(client, 15);
    no_output(server, 15);
}

static Segment inbound(const Connection& endpoint, uint32_t sequence, const char* data = nullptr,
                       uint8_t flags = ack) {
    Segment result{};
    result.sequence = sequence;
    result.acknowledgment = endpoint.next_send();
    result.window = stream_capacity;
    result.flags = flags;
    result.payload = reinterpret_cast<const uint8_t*>(data);
    result.length = data ? std::strlen(data) : 0;
    return result;
}

static void handshakes() {
    Connection lost;
    lost.active(0xfffffff0, 0);
    auto original = require_output(lost, 0).segment();
    no_output(lost, 999);
    auto retransmitted = require_output(lost, 1000).segment();
    assert(retransmitted.flags == syn && retransmitted.sequence == original.sequence);
    no_output(lost, 2999);
    retransmitted = require_output(lost, 3000).segment();
    assert(retransmitted.sequence == original.sequence);
    no_output(lost, 60000);
    assert(lost.state() == State::closed && lost.error() == 110);

    Connection refused;
    refused.active(10, 0);
    require_output(refused, 0);
    Segment reset{};
    reset.flags = rst;
    refused.input(reset, 10);
    assert(refused.state() == State::syn_sent);
    Segment invalid_ack{};
    invalid_ack.flags = ack;
    invalid_ack.acknowledgment = 12;
    refused.input(invalid_ack, 15); // Queue a rejection, then receive the valid reset first.
    reset.flags = rst | ack;
    reset.acknowledgment = 11;
    refused.input(reset, 20);
    assert(refused.state() == State::closed && refused.error() == 111);
    no_output(refused, 20); // An abort cancels a stale pending rejection.

    Connection a, b;
    a.active(1, 0);
    b.active(77, 0);
    Packet pa = require_output(a, 0), pb = require_output(b, 0, false);
    a.input(pb.segment(), 10);
    b.input(pa.segment(), 10);
    assert(a.state() == State::syn_received && b.state() == State::syn_received);
    pa = require_output(a, 10);
    pb = require_output(b, 10, false);
    a.input(pb.segment(), 20);
    b.input(pa.segment(), 20);
    // SYN/ACKs are answered by challenge ACKs; their ACK is then validated at RCV.NXT.
    assert(a.state() == State::syn_received && b.state() == State::syn_received);
    pa = require_output(a, 20);
    pb = require_output(b, 20, false);
    a.input(pb.segment(), 30);
    b.input(pa.segment(), 30);
    assert(a.state() == State::established && b.state() == State::established);

    Connection client, server;
    establish(client, server, 0xfffffff0, 0xffffffff);
    assert(client.next_receive() == 0);
}

static void reassembly() {
    Connection client, server;
    establish(client, server, 0xfffffff0, 0xfffffff8);
    uint32_t first = client.next_receive();
    client.input(inbound(client, first + 6, "GHI"), 30);
    assert(client.available() == 0 && client.next_receive() == first);
    auto gap_ack = require_output(client, 30).segment();
    assert(gap_ack.acknowledgment == first);
    client.input(inbound(client, first + 3, "DEFghi"), 40);
    require_output(client, 40);
    client.input(inbound(client, first - 2, "xxABC"), 50);
    assert(client.available() == 9 && client.next_receive() == first + 9);
    auto ending = inbound(client, first + 12, "MNO", ack | fin);
    client.input(ending, 60);
    assert(!client.eof() && client.available() == 9);
    client.input(inbound(client, first + 9, "JKL"), 70);
    assert(client.eof() && client.available() == 15 && client.next_receive() == first + 16);
    assert(client.state() == State::close_wait);
    char bytes[32]{};
    assert(client.read(bytes, 3, true, 2) == 3 && !std::memcmp(bytes, "CDE", 3));
    assert(client.available() == 15);
    assert(client.read(bytes, 4) == 4 && !std::memcmp(bytes, "ABCD", 4));
    assert(client.read(bytes, sizeof(bytes)) == 11 && !std::memcmp(bytes, "EFGHIJKLMNO", 11));
    client.input(inbound(client, first + 16, "afterEOF"), 80);
    assert(client.available() == 0 && client.next_receive() == first + 16);
    assert(client.read(nullptr, 10) == 0);
    client.close_read();
    assert(client.eof());
}

static void validation() {
    Connection client, server;
    establish(client, server);
    assert(client.write("queued", 6, 20) == 6);
    Packet data = require_output(client, 20);
    uint32_t first = client.next_receive();
    Segment future = inbound(client, first);
    future.acknowledgment = client.next_send() + 1;
    client.input(future, 30);
    assert(client.queued() == 6);
    require_output(client, 30);
    auto stale = inbound(client, first);
    stale.acknowledgment = 100;
    stale.window = 0;
    client.input(stale, 31);
    uint8_t more[1460]{};
    assert(client.write(more, sizeof(more), 31) == sizeof(more));
    assert(require_output(client, 31).segment().length == sizeof(more));
    assert(client.queued() ==
           sizeof(more) + 6); // A stale ACK neither frees data nor closes the window.
    auto reset = inbound(client, first + 1, nullptr, rst);
    client.input(reset, 40);
    assert(client.state() == State::established && !client.error());
    no_output(client, 40); // The future ACK at 30 already consumed this connection's interval.
    reset.sequence = first + stream_capacity;
    client.input(reset, 50);
    no_output(client, 50);
    reset.sequence = first;
    client.input(reset, 60);
    assert(client.state() == State::closed && client.error() == 104);
    no_output(client, 60);
}

static void sizing() {
    Connection client, server;
    establish(client, server);
    assert(client.write("abc", 3, 20) == 3);
    Packet first = require_output(client, 20);
    assert(client.write("de", 2, 30) == 2);
    no_output(client, 30); // Default Nagle coalesces a small write until existing data is ACKed.
    client.nodelay(true);
    Packet second = require_output(client, 30);
    assert(second.segment().length == 2 &&
           second.segment().sequence == first.segment().sequence + 3);
    server.input(first.segment(), 40);
    server.input(second.segment(), 40);
    assert(server.available() == 5);

    Connection limited, peer;
    establish(limited, peer);
    auto update = inbound(limited, limited.next_receive());
    update.window = 1;
    limited.input(update, 20);
    std::vector<uint8_t> bytes(stream_capacity + 1, 'x');
    assert(limited.write(bytes.data(), bytes.size(), 20) == stream_capacity);
    assert(limited.writable() == 0 && limited.write("x", 1, 20) == 0);
    no_output(limited, 199); // A tiny window does not cause immediate one-byte segmentation.
    assert(require_output(limited, 200).segment().length == 1); // Bounded SWS override timer.
    limited.input(inbound(limited, limited.next_receive() + 100, "discarded"), 210);
    assert(limited.available() == 0);
    limited.close_read();
    limited.input(inbound(limited, limited.next_receive(), "read_shutdown"), 220);
    assert(limited.available() == 0 && limited.eof());
}

static void loss() {
    Connection client, server;
    establish(client, server, 100, 500, 4);
    assert(client.write("ABCDEFGHIJKLMNOPQRSTUVWX", 24, 20) == 24);
    Packet lost = require_output(client, 20);
    assert(lost.segment().length == 4);
    for (unsigned at = 0; at < 3; at++) {
        Packet packet = require_output(client, 20);
        server.input(packet.segment(), 30 + at);
        client.input(require_output(server, 30 + at, false).segment(), 40 + at);
    }
    Packet fast = require_output(client, 50);
    assert(fast.segment().sequence == lost.segment().sequence && fast.segment().length == 4);
    Packet extra = require_output(client, 999); // Recovery permits one additional MSS here.
    assert(extra.segment().sequence == lost.segment().sequence + 16);
    no_output(client, 1019); // Fast retransmission did not restart the oldest packet's RTO.
    Packet timed = require_output(client, 1020);
    assert(timed.segment().sequence == lost.segment().sequence);
    no_output(client, 1020); // Congestion collapsed to one MSS, with 16 bytes still outstanding.
    server.input(timed.segment(), 1030);
    assert(server.available() == 16);
    server.input(extra.segment(), 1030);
    assert(server.available() == 20);
    client.input(require_output(server, 1030, false).segment(), 1040);
    assert(client.queued() == 4);
    char bytes[32]{};
    assert(server.read(bytes, sizeof(bytes)) == 20 &&
           !std::memcmp(bytes, "ABCDEFGHIJKLMNOPQRST", 20));
    assert(require_output(client, 1040).segment().length == 4);
}

static void persist() {
    Connection client, server;
    server.limits(0, stream_capacity);
    establish(client, server);
    assert(client.write("hello", 5, 50) == 5);
    no_output(client, 1049);
    Packet probe = require_output(client, 1050);
    assert(probe.segment().length == 1);
    server.input(probe.segment(), 1060);
    client.input(require_output(server, 1060, false).segment(), 1070);
    no_output(client, 3049);
    probe = require_output(client, 3050);
    server.input(probe.segment(), 3060);
    client.input(require_output(server, 3060, false).segment(), 3070);
    assert(!client.error() && client.queued() == 5);
    server.limits(1, stream_capacity);
    client.input(require_output(server, 3080, false).segment(), 3090);
    char bytes[8]{};
    for (unsigned at = 0; at < 5; at++) {
        Packet packet = require_output(client, 3100 + at);
        assert(packet.segment().length == 1);
        server.input(packet.segment(), 3100 + at);
        client.input(require_output(server, 3100 + at, false).segment(), 3100 + at);
        assert(server.read(bytes + at, 1) == 1);
        client.input(require_output(server, 3100 + at, false).segment(), 3100 + at);
    }
    assert(!std::memcmp(bytes, "hello", 5) && client.queued() == 0);
    Connection finite, shut;
    shut.limits(0, stream_capacity);
    establish(finite, shut);
    finite.user_timeout(2500);
    assert(finite.write("x", 1, 50) == 1);
    no_output(finite, 2550);
    assert(finite.state() == State::closed && finite.error() == 110);
}

static void persist_transition() {
    for (bool lose : {false, true}) {
        Connection client, server;
        server.limits(4, stream_capacity);
        establish(client, server, 100, 500, 4);
        assert(client.write("abcdefgh", 8, 50) == 8);
        Packet original = require_output(client, 50);
        assert(original.segment().length == 4);
        uint64_t received = 60;
        if (lose) {
            no_output(client, 1049);
            original = require_output(client, 1050);
            received = 1060;
        }
        server.input(original.segment(), received);
        Packet closed = require_output(server, received, false);
        assert(closed.segment().window == 0);
        uint64_t changed = received + 10, interval = lose ? 2000 : 1000;
        client.input(closed.segment(), changed);
        no_output(client, changed);
        client.input(closed.segment(), changed + 5); // A repeated zero ACK preserves the timer.
        no_output(client, changed + interval - 1);
        Packet probe = require_output(client, changed + interval);
        assert(probe.segment().length == 1 && probe.segment().sequence == 105);
        server.input(probe.segment(), changed + interval + 10);
        client.input(require_output(server, changed + interval + 10, false).segment(),
                     changed + interval + 20);
        no_output(client, changed + 3 * interval - 1);
        probe = require_output(client, changed + 3 * interval);
        assert(probe.segment().length == 1 && probe.segment().sequence == 105);
        assert(client.queued() == 4 && client.error() == 0);
        server.limits(8, stream_capacity);
        client.input(require_output(server, changed + 3 * interval + 10, false).segment(),
                     changed + 3 * interval + 20);
        for (unsigned at = 0; at < 4 && client.queued(); at++) {
            uint64_t sent = changed + 3 * interval + 20 + at * 30;
            Packet remaining = require_output(client, sent);
            server.input(remaining.segment(), sent + 10);
            client.input(require_output(server, sent + 10, false).segment(), sent + 20);
        }
        char bytes[8];
        assert(server.read(bytes, sizeof(bytes)) == 8 && !std::memcmp(bytes, "abcdefgh", 8));
        assert(client.queued() == 0 && client.error() == 0);
    }
    Connection late, shut;
    shut.limits(0, stream_capacity);
    late.active(100, 0);
    require_output(late, 0); // A lost SYN leaves the established RTO at three seconds.
    assert(shut.passive(500, require_output(late, 1000).segment(), 1005));
    late.input(require_output(shut, 1005, false).segment(), 1010);
    shut.input(require_output(late, 1010).segment(), 1015);
    assert(late.write("x", 1, 1050) == 1);
    no_output(late, 4049);
    assert(require_output(late, 4050).segment().length == 1);
}

static void closing() {
    Connection client, server;
    establish(client, server);
    assert(client.write("abc", 3, 20) == 3);
    client.close_write();
    Packet text = require_output(client, 20), end = require_output(client, 20);
    assert(end.segment().flags == (ack | fin));
    server.input(end.segment(), 30); // FIN arrives before data and must wait for the gap.
    assert(!server.eof());
    server.input(text.segment(), 40);
    assert(server.eof() && server.available() == 3 && server.state() == State::close_wait);
    client.input(require_output(server, 40, false).segment(), 50);
    assert(client.state() == State::fin_wait_2);
    char bytes[3];
    assert(server.read(bytes, 3) == 3 && !std::memcmp(bytes, "abc", 3));
    server.close_write();
    Packet finish = require_output(server, 60, false);
    assert(server.state() == State::last_ack);
    client.input(finish.segment(), 70);
    assert(client.state() == State::time_wait && client.eof());
    auto compact = client.time_wait_state();
    assert(compact.send == client.next_send() && compact.receive == client.next_receive() &&
           compact.window == client.window() && compact.deadline == 120070);
    server.input(require_output(client, 70).segment(), 80);
    assert(server.state() == State::closed);
    client.input(finish.segment(),
                 1000); // A lost final ACK restarts TIME-WAIT on retransmitted FIN.
    assert(time_wait_input(compact, finish.segment(), 1000) == TimeWaitAction::acknowledge &&
           compact.deadline == client.time_wait_state().deadline);
    require_output(client, 1000);
    no_output(client, 120999);
    assert(client.state() == State::time_wait);
    no_output(client, 121000);
    assert(client.state() == State::closed);

    Connection a, b;
    establish(a, b);
    a.close_write();
    b.close_write();
    Packet fa = require_output(a, 20), fb = require_output(b, 20, false);
    a.input(fb.segment(), 30);
    b.input(fa.segment(), 30);
    assert(a.state() == State::closing && b.state() == State::closing);
    Packet aa = require_output(a, 30), ab = require_output(b, 30, false);
    a.input(ab.segment(), 40);
    b.input(aa.segment(), 40);
    assert(a.state() == State::time_wait && b.state() == State::time_wait);

    Connection detached, peer;
    establish(detached, peer);
    detached.detach(20);
    peer.input(require_output(detached, 20).segment(), 30);
    detached.input(require_output(peer, 30, false).segment(), 40);
    assert(detached.state() == State::fin_wait_2);
    no_output(detached, 60040);
    assert(detached.state() == State::closed);
}

static void bounded_transfer() {
    Connection client, server;
    establish(client, server, 0xfffffff0, 12345);
    std::vector<uint8_t> original(300000), actual;
    for (size_t at = 0; at < original.size(); at++)
        original[at] = uint8_t((at * 37) ^ (at >> 8));
    size_t written = 0, packets = 0;
    std::deque<Packet> network;
    uint8_t read[1024];
    for (uint64_t now = 20; now < 1000000 && actual.size() < original.size(); now += 10) {
        written += client.write(original.data() + written, original.size() - written, now);
        for (unsigned at = 0; at < 4; at++) {
            Packet packet;
            if (output(client, now, true, packet)) {
                packets++;
                if (packets % 17)
                    network.push_back(packet);
                if (packets % 13 == 0)
                    network.push_back(packet);
            }
            if (output(server, now, false, packet)) {
                packets++;
                if (packets % 11)
                    network.push_back(packet);
            }
        }
        if (!network.empty()) {
            Packet packet = packets % 5 ? network.front() : network.back();
            if (packets % 5)
                network.pop_front();
            else
                network.pop_back();
            (packet.from_client ? server : client).input(packet.segment(), now);
        }
        if (now % 30 == 0) {
            size_t count = server.read(read, sizeof(read));
            actual.insert(actual.end(), read, read + count);
        }
        assert(!client.error() && !server.error());
        assert(client.queued() <= stream_capacity && server.available() <= stream_capacity);
        assert(network.size() < 1000);
    }
    assert(written == original.size() && actual == original);
    std::printf(
        "TCP_TRANSFER_PASS bytes=%zu packets=%zu loss_duplicate_reorder wrap bounded_queues\n",
        actual.size(), packets);
}

static Packet injection(Segment segment) {
    segment.source = 80;
    segment.destination = 49152;
    Packet packet{std::vector<uint8_t>(60 + segment.length), false};
    size_t size = encode(0xc6336402, 0xc0000201, segment, packet.bytes.data(), packet.bytes.size());
    assert(size);
    packet.bytes.resize(size);
    return packet;
}

static uint64_t acknowledge_history(Connection& client, Connection& server, size_t bytes) {
    client.nodelay(true);
    char payload[4096], received[4096];
    std::memset(payload, 'h', sizeof(payload));
    uint64_t now = 20;
    for (size_t total = 0; total < bytes; total += sizeof(payload)) {
        assert(client.write(payload, sizeof(payload), now) == sizeof(payload));
        size_t sent = 0;
        while (sent < sizeof(payload)) {
            Packet packet = require_output(client, now);
            auto segment = packet.segment();
            assert(segment.length && sent + segment.length <= sizeof(payload));
            server.input(segment, now + 1);
            assert(server.read(received, sizeof(received)) == segment.length);
            assert(std::memcmp(received, payload, segment.length) == 0);
            client.input(require_output(server, now + 2, false).segment(), now + 3);
            sent += segment.length;
            now += 10;
        }
    }
    return now;
}

static void stale_acknowledgments() {
    for (bool wrapped : {false, true}) {
        for (size_t history : {size_t(0), size_t(4096), size_t(65536)}) {
            for (bool grown : {false, true}) {
                for (int boundary : {-1, 0, 1}) {
                    for (bool finish : {false, true}) {
                        Connection client, server;
                        establish(client, server, wrapped ? 0xfffffff0 : 100,
                                  wrapped ? 0xffffffd0 : 500);
                        uint64_t now = acknowledge_history(client, server, history);
                        if (grown) {
                            auto update = inbound(client, client.next_receive());
                            update.window = 65535;
                            client.input(injection(update).segment(), now);
                            update.window = 0;
                            client.input(injection(update).segment(), now + 1);
                        }
                        uint32_t distance = std::min(uint32_t(grown ? 65535 : stream_capacity),
                                                     uint32_t(history + 1));
                        uint32_t receive = client.next_receive();
                        auto segment = inbound(client, receive, "bad", ack | (finish ? fin : 0));
                        segment.acknowledgment = client.next_send() - distance + boundary;
                        segment.window = 65535;
                        client.input(injection(segment).segment(), now + 2);
                        char bytes[4]{};
                        if (boundary < 0) {
                            assert(client.read(bytes, sizeof(bytes)) == 0);
                            assert(client.next_receive() == receive && !client.eof());
                            assert(client.state() == State::established && client.error() == 0);
                            auto challenge = require_output(client, now + 2).segment();
                            assert(challenge.flags == ack &&
                                   challenge.sequence == client.next_send() &&
                                   challenge.acknowledgment == receive && !challenge.length);
                            auto recovery = inbound(client, receive, "ok");
                            client.input(injection(recovery).segment(), now + 3);
                            assert(client.read(bytes, sizeof(bytes)) == 2 &&
                                   std::memcmp(bytes, "ok", 2) == 0 && !client.eof());
                        } else {
                            assert(client.read(bytes, sizeof(bytes)) == 3 &&
                                   std::memcmp(bytes, "bad", 3) == 0);
                            assert(client.next_receive() == receive + 3 + unsigned(finish));
                            assert(client.eof() == finish && client.error() == 0);
                        }
                    }
                }
            }
        }
    }
    Connection client, server;
    establish(client, server);
    client.user_timeout(2500);
    assert(client.write("wait", 4, 20) == 4);
    auto sent = require_output(client, 20).segment();
    assert(sent.length == 4);
    auto attack = inbound(client, client.next_receive(), "bad", ack | fin);
    attack.acknowledgment = sent.sequence - 2;
    attack.window = 65535;
    client.input(injection(attack).segment(), 2000);
    assert(client.available() == 0 && !client.eof() && client.queued() == 4 && !client.error());
    Segment pending;
    client.next(2520, pending);
    assert(client.state() == State::closed && client.error() == 110);
    std::puts("TCP_OLD_ACK_BOUNDS_PASS cases=73 history window_growth wrap payload fin recovery "
              "deadline");
}

static Segment invalid_challenge(const Connection& endpoint, unsigned kind) {
    auto segment = inbound(endpoint, endpoint.next_receive(), "bad", ack | fin);
    switch (kind) {
    case 0:
        segment.acknowledgment = endpoint.next_send() - 2;
        break;
    case 1:
        segment.acknowledgment = endpoint.next_send() + 1;
        break;
    case 2:
        segment.flags = syn | ack;
        break;
    case 3:
        segment.flags = syn | ack;
        segment.sequence += stream_capacity;
        break;
    case 4:
        segment.flags = rst;
        segment.sequence++;
        break;
    case 5:
        segment.sequence += stream_capacity;
        segment.payload = nullptr;
        segment.length = 0;
        segment.flags = ack;
        break;
    case 6:
    case 7:
        segment.payload = nullptr;
        segment.length = 0;
        segment.flags = kind == 6 ? syn : rst;
        segment.sequence++;
        break;
    }
    return segment;
}

static void challenge_intervals() {
    unsigned cases = 0;
    for (bool wrapped : {false, true}) {
        for (uint64_t start : {uint64_t(0), uint64_t(20), UINT64_MAX - 1000}) {
            for (unsigned kind = 0; kind < 8; kind++) {
                Connection client, server, independent, other;
                establish(client, server, wrapped ? 0xfffffff0 : 100, wrapped ? 0xfffffff0 : 500);
                establish(independent, other);
                uint32_t receive = client.next_receive(), send = client.next_send();
                auto challenge = invalid_challenge(client, kind);
                client.input(injection(challenge).segment(), start);
                auto reply = require_output(client, start).segment();
                assert(reply.flags == ack && !reply.length && reply.sequence == send &&
                       reply.acknowledgment == receive);
                for (uint64_t offset : {uint64_t(1), uint64_t(249), uint64_t(499)}) {
                    // All invalid kinds consume the same connection-local interval.
                    client.input(injection(invalid_challenge(client, (kind + 1) % 8)).segment(),
                                 start + offset);
                    no_output(client, start + offset);
                    assert(client.state() == State::established && client.error() == 0 &&
                           client.next_receive() == receive && client.next_send() == send &&
                           client.available() == 0 && !client.eof());
                }
                independent.input(injection(invalid_challenge(independent, kind)).segment(),
                                  start + 499);
                require_output(independent, start + 499);
                client.input(injection(challenge).segment(), start + 500);
                require_output(client, start + 500);
                client.input(injection(challenge).segment(), start + 999);
                no_output(client, start + 999);
                no_output(client, start + 1000); // Suppressed input does not schedule a late ACK.
                client.input(injection(challenge).segment(), start + 1000);
                require_output(client, start + 1000);
                cases++;
            }
        }
    }

    Connection client, server;
    establish(client, server);
    auto challenge = invalid_challenge(client, 0);
    client.input(injection(challenge).segment(), 20);
    Packet pending;
    assert(output(client, 20, true, pending, false));
    client.input(injection(challenge).segment(), 21);
    assert(output(client, 21, true, pending, false));
    client.emitted(21); // Failed enqueue keeps one owned candidate; it does not admit a new ACK.
    client.input(injection(challenge).segment(), 22);
    no_output(client, 22);
    client.input(injection(challenge).segment(), 19); // A backward clock cannot reopen the quota.
    no_output(client, 19);

    auto valid = inbound(client, client.next_receive(), "ok");
    client.input(injection(valid).segment(), 23);
    char bytes[4]{};
    assert(client.read(bytes, sizeof(bytes)) == 2 && std::memcmp(bytes, "ok", 2) == 0);
    require_output(client, 23); // Valid data and receive-window updates are never throttled.
    auto duplicate = inbound(client, client.next_receive() - 2, "ok");
    for (uint64_t now : {uint64_t(24), uint64_t(25)}) {
        client.input(injection(duplicate).segment(), now);
        require_output(client, now); // Out-of-window data retransmissions need immediate ACKs.
    }
    auto finish = inbound(client, client.next_receive() + stream_capacity, nullptr, ack | fin);
    client.input(injection(finish).segment(), 26);
    require_output(client, 26); // FIN retransmissions also consume sequence space.
    auto reset = inbound(client, client.next_receive(), nullptr, rst);
    client.input(injection(reset).segment(), 27);
    assert(client.state() == State::closed && client.error() == 104);
    no_output(client, 27);

    Connection timed, peer;
    establish(timed, peer);
    timed.user_timeout(2500);
    assert(timed.write("wait", 4, 20) == 4);
    require_output(timed, 20);
    for (uint64_t now = 30; now < 2500; now += 100) {
        auto attack = invalid_challenge(timed, 0);
        attack.acknowledgment =
            99; // Below SND.UNA - acknowledged history, even with data in flight.
        timed.input(injection(attack).segment(), now);
        Packet packet;
        output(timed, now, true, packet);
    }
    timed.input(injection(invalid_challenge(timed, 0)).segment(), 2520);
    assert(timed.state() == State::closed && timed.error() == 110);
    no_output(timed, 2520);
    std::printf("TCP_CHALLENGE_INTERVAL_PASS cases=%u first shared_kinds independent zero limit "
                "wrap boundary silence ownership data retransmit reset deadline\n",
                cases + 2);
}

int main() {
    challenge_intervals();
    handshakes();
    reassembly();
    validation();
    sizing();
    loss();
    persist();
    persist_transition();
    closing();
    bounded_transfer();
    stale_acknowledgments();
    std::puts("TCP_CONNECTION_PASS handshake refusal simultaneous overlap gaps fin ack_validation "
              "reset loss persist deadlines close ownership");
}
