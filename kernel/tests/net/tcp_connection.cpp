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

static void default_lifetimes() {
    // The pinned Linux default retry model gives 924600 ms. These policy clocks
    // complement, rather than replace, the complete actual NIC observations.
    constexpr uint64_t lifetime = 924600;
    unsigned cases = 0;
    for (bool wrapped : {false, true}) {
        for (bool finish : {false, true}) {
            for (uint64_t start : {uint64_t(0), uint64_t(20), UINT64_MAX - lifetime}) {
                Connection client, server;
                establish(client, server, wrapped ? 0xfffffff0 : 100);
                if (finish)
                    client.close_write();
                else
                    assert(client.write("x", 1, start) == 1);
                Packet owned = require_output(client, start);
                assert(finish ? bool(owned.segment().flags & fin) : owned.segment().length == 1);
                // Repeated failed retries cannot refresh the original owned period.
                for (unsigned at = 0; at < 3; at++) {
                    Packet pending;
                    assert(output(client, start + lifetime - 1, true, pending, false));
                }
                assert(client.error() == 0);
                no_output(client, start + lifetime);
                assert(client.state() == State::closed && client.error() == 110);
                cases++;
            }
        }
    }

    Connection delayed, receiver;
    establish(delayed, receiver);
    assert(delayed.write("x", 1, 20) == 1);
    for (uint64_t now : {uint64_t(20), lifetime + 21, 2 * lifetime + 22}) {
        Packet pending;
        assert(output(delayed, now, true, pending, false));
        assert(delayed.next_send() == 101 && delayed.error() == 0);
    }
    uint64_t committed = 2 * lifetime + 22;
    delayed.emitted(committed);
    Packet retry;
    assert(output(delayed, committed + lifetime - 1, true, retry, false));
    no_output(delayed, committed + lifetime);
    assert(delayed.error() == 110);
    cases++;

    Connection partial, other;
    establish(partial, other);
    assert(partial.write("xy", 2, 20) == 2);
    require_output(partial, 20);
    auto progress = inbound(partial, partial.next_receive());
    progress.acknowledgment = 102;
    partial.input(injection(progress).segment(), lifetime + 19);
    assert(partial.queued() == 1 && partial.error() == 0);
    assert(output(partial, 2 * lifetime + 18, true, retry, false));
    no_output(partial, 2 * lifetime + 19);
    assert(partial.error() == 110);
    cases++;

    Connection renewed, peer;
    establish(renewed, peer);
    assert(renewed.write("x", 1, 20) == 1);
    require_output(renewed, 20);
    renewed.input(injection(inbound(renewed, renewed.next_receive())).segment(), lifetime + 19);
    assert(renewed.queued() == 0);
    no_output(renewed, 2 * lifetime);
    assert(renewed.write("y", 1, 2 * lifetime + 20) == 1);
    require_output(renewed, 2 * lifetime + 20);
    assert(output(renewed, 3 * lifetime + 19, true, retry, false));
    no_output(renewed, 3 * lifetime + 20);
    assert(renewed.error() == 110);
    cases++;

    Connection finite, limit;
    establish(finite, limit);
    finite.user_timeout(lifetime + 2000);
    assert(finite.write("x", 1, 20) == 1);
    require_output(finite, 20);
    assert(output(finite, lifetime + 20, true, retry, false));
    assert(finite.error() == 0);
    no_output(finite, lifetime + 2020);
    assert(finite.error() == 110);
    cases++;

    Connection duplicate, ignored;
    establish(duplicate, ignored);
    assert(duplicate.write("x", 1, 20) == 1);
    require_output(duplicate, 20);
    auto unchanged = inbound(duplicate, duplicate.next_receive());
    unchanged.acknowledgment = 101;
    for (uint64_t now : {lifetime - 100, lifetime - 50, lifetime - 25})
        duplicate.input(injection(unchanged).segment(), now);
    auto invalid = invalid_challenge(duplicate, 1);
    duplicate.input(injection(invalid).segment(), lifetime);
    no_output(duplicate, lifetime + 20);
    assert(duplicate.error() == 110);
    cases++;

    for (bool responsive : {false, true}) {
        Connection stopped, closed;
        closed.limits(0, stream_capacity);
        establish(stopped, closed);
        assert(stopped.write("hello", 5, 50) == 5);
        no_output(stopped, 1049);
        Packet probe = require_output(stopped, 1050);
        uint64_t last = 1050;
        if (responsive) {
            for (uint64_t now = 1050; now < 2 * lifetime; now += 60000) {
                if (now != 1050)
                    probe = require_output(stopped, now);
                closed.input(probe.segment(), now + 1);
                stopped.input(require_output(closed, now + 1, false).segment(), now + 2);
                assert(stopped.queued() == 5 && stopped.error() == 0);
                last = now + 10;
            }
            closed.limits(stream_capacity, stream_capacity);
            stopped.input(require_output(closed, last, false).segment(), last + 1);
            for (unsigned at = 0; at < 4 && stopped.queued(); at++) {
                Packet packet = require_output(stopped, last + 2 + at * 10);
                closed.input(packet.segment(), last + 3 + at * 10);
                stopped.input(require_output(closed, last + 3 + at * 10, false).segment(),
                              last + 4 + at * 10);
            }
            char bytes[8]{};
            assert(stopped.queued() == 0 && closed.read(bytes, sizeof(bytes)) == 5 &&
                   !std::memcmp(bytes, "hello", 5));
            no_output(stopped, last + lifetime);
            assert(stopped.state() == State::established && stopped.error() == 0);
        } else {
            assert(output(stopped, 1050 + lifetime - 1, true, retry, false));
            no_output(stopped, 1050 + lifetime);
            assert(stopped.error() == 110);
        }
        cases++;
    }
    Connection independent, waiting, live, live_peer;
    establish(independent, waiting);
    establish(live, live_peer);
    assert(independent.write("x", 1, 20) == 1);
    require_output(independent, 20);
    assert(live.write("y", 1, lifetime) == 1);
    require_output(live, lifetime);
    no_output(independent, lifetime + 20);
    no_output(live, lifetime + 20);
    assert(independent.error() == 110 && live.error() == 0);
    cases++;

    Connection backward, zero;
    zero.limits(0, stream_capacity);
    establish(backward, zero);
    assert(backward.write("x", 1, 50) == 1);
    Packet probe = require_output(backward, 1050);
    zero.input(probe.segment(), 1060);
    Packet answer = require_output(zero, 1060, false);
    backward.input(answer.segment(), 1100);
    backward.input(answer.segment(), 1000); // A regressed reading cannot shorten the live period.
    assert(output(backward, 1100 + lifetime - 1, true, retry, false));
    no_output(backward, 1100 + lifetime);
    assert(backward.error() == 110);
    cases++;

    for (uint32_t timeout : {uint32_t(0), uint32_t(2500)}) {
        Connection finish, closed;
        closed.limits(0, stream_capacity);
        establish(finish, closed);
        finish.user_timeout(timeout);
        finish.close_write();
        Packet owned = require_output(finish, 1010);
        assert(owned.segment().length == 0 && !(owned.segment().flags & fin));
        uint64_t interval = timeout ? timeout : lifetime;
        assert(output(finish, 1010 + interval - 1, true, retry, false));
        no_output(finish, 1010 + interval);
        assert(finish.error() == 110);
        cases++;
    }
    for (bool wrapped : {false, true}) {
        for (bool future : {false, true}) {
            Connection poisoned, stopped;
            stopped.limits(0, stream_capacity);
            establish(poisoned, stopped, wrapped ? 0xfffffff0 : 100);
            assert(poisoned.write("x", 1, 50) == 1);
            Packet first = require_output(poisoned, 1050);
            auto rejected = inbound(poisoned, poisoned.next_receive());
            rejected.window = 0;
            rejected.acknowledgment =
                future ? poisoned.next_send() + 1 : first.segment().sequence - 1;
            poisoned.input(injection(rejected).segment(), 1050 + lifetime - 1);
            no_output(poisoned, 1050 + lifetime);
            assert(poisoned.error() == 110);
            cases++;
        }
    }
    std::printf(
        "TCP_DEFAULT_LIFETIME_PASS cases=%u data fin zero ownership progress custom duplicate "
        "persist responsive recovery independent backward empty_fin wrap limit\n",
        cases);
}

static void reconnect_sequences() {
    struct Fixture {
        uint32_t initial;
        uint16_t window;
        uint32_t queued, closed, enlarged;
    };

    const Fixture fixtures[] = {
        {100, 8192, 8312, 8313, 65656},    {0xfffffff0, 8192, 8196, 8197, 65540},
        {0xffffdfec, 8192, 1, 1, 57344},   {0xffffdfeb, 8192, 0xffffffff, 1, 57343},
        {100, 65535, 65655, 65656, 65656}, {0xfffffff0, 65535, 65539, 65540, 65540},
        {0xfffeffed, 65535, 1, 1, 1},      {0xfffeffec, 65535, 0xffffffff, 1, 1},
    };
    for (auto fixture : fixtures) {
        Connection client;
        client.active(fixture.initial, 0);
        assert(require_output(client, 0).segment().flags == syn);
        auto response = inbound(client, 0xfffffff0, nullptr, syn | ack);
        response.window = fixture.window;
        response.maximum_segment = 1460;
        client.input(injection(response).segment(), 10);
        assert(require_output(client, 10).segment().flags == ack);
        const char bytes[17] = "queued old bytes";
        assert(client.write(bytes, sizeof(bytes), 20) == sizeof(bytes));
        assert(client.next_send() == fixture.initial + 1);
        assert(client.reconnect_sequence() == fixture.queued);
        assert(require_output(client, 20).segment().length == sizeof(bytes));
        assert(client.reconnect_sequence() == fixture.queued);
        response = inbound(client, client.next_receive());
        response.window = 0;
        client.input(injection(response).segment(), 30);
        assert(client.queued() == 0 && client.reconnect_sequence() == fixture.queued);
        client.close_write();
        assert(client.reconnect_sequence() == fixture.closed);
        no_output(client, 31);
        response.window = 65535;
        client.input(injection(response).segment(), 40);
        assert(client.reconnect_sequence() == fixture.enlarged);
        auto finish = require_output(client, 40).segment();
        assert(finish.flags == (fin | ack));
        assert(client.reconnect_sequence() == fixture.enlarged);
        response.acknowledgment = finish.sequence + 1;
        client.input(injection(response).segment(), 50);
        assert(client.reconnect_sequence() == fixture.enlarged);
    }
    std::puts("TCP_RECONNECT_SEQUENCE_MODEL_PASS cases=8 pending_bytes maximum_window queued_FIN "
              "acknowledged_FIN wrap nonzero");
}

static void local_output_retries() {
    constexpr uint64_t lifetime = 924600;
    unsigned cases = 0;
    for (bool finish : {false, true}) {
        for (uint32_t timeout : {uint32_t(0), uint32_t(2500)}) {
            for (uint64_t start : {uint64_t(20), UINT64_MAX - lifetime}) {
                Connection blocked, peer;
                establish(blocked, peer, 0xfffffff0);
                blocked.user_timeout(timeout);
                if (finish)
                    blocked.close_write();
                else
                    assert(blocked.write("x", 1, start) == 1);
                uint32_t sequence = blocked.next_send();
                Packet packet;
                assert(output(blocked, start, true, packet, false));
                blocked.output_blocked(start);
                blocked.emitted(start); // The rejected offer cannot later acquire ownership.
                assert(blocked.next_send() == sequence && blocked.state() == State::established);
                no_output(blocked, start - 1); // A regressed reading cannot end the local delay.
                no_output(blocked, start + 199);
                assert(output(blocked, start + 200, true, packet, false));
                assert(packet.segment().sequence == sequence);
                blocked.output_blocked(start + 200);
                uint64_t bound = start + (timeout ? timeout : lifetime);
                assert(output(blocked, bound - 1, true, packet, false));
                blocked.output_blocked(bound - 1);
                // The delivery deadline expires inside the most recent local retry delay.
                no_output(blocked, bound);
                assert(blocked.state() == State::closed && blocked.error() == 110 &&
                       blocked.next_send() == sequence);
                cases++;
            }
        }
    }

    for (bool zero_window : {false, true}) {
        Connection finish, peer;
        if (zero_window)
            peer.limits(0, stream_capacity);
        establish(finish, peer);
        finish.user_timeout(2500);
        finish.close_write();
        uint64_t start = zero_window ? 1010 : 20;
        Packet packet;
        assert(output(finish, start, true, packet, false));
        finish.output_blocked(start);
        if (zero_window) {
            peer.limits(stream_capacity, stream_capacity);
            finish.input(require_output(peer, start + 100, false).segment(), start + 101);
        }
        packet = require_output(finish, start + 200);
        assert(packet.segment().flags & fin);
        no_output(finish, start + 2500);
        assert(finish.error() == 110); // Successful enqueue cannot renew an already waiting FIN.
        cases++;
    }

    Connection delayed, waiting;
    establish(delayed, waiting);
    delayed.user_timeout(2500);
    assert(delayed.write("x", 1, 20) == 1);
    Packet packet;
    assert(output(delayed, 2400, true, packet, false));
    delayed.output_blocked(2400);
    no_output(delayed, 2520);
    assert(delayed.error() == 110); // The explicit data deadline still starts at write progress.
    cases++;

    Connection recovering, receiver, live, live_peer;
    establish(recovering, receiver, 0xfffffff0);
    establish(live, live_peer);
    char bytes[512], actual[512];
    for (unsigned at = 0; at < sizeof(bytes); at++)
        bytes[at] = char(at * 29 ^ at >> 3);
    assert(recovering.write(bytes, sizeof(bytes), 20) == sizeof(bytes));
    for (uint64_t now : {uint64_t(20), uint64_t(220), uint64_t(420)}) {
        assert(output(recovering, now, true, packet, false));
        auto offer = packet.segment();
        assert(offer.sequence == 0xfffffff1 && offer.length == sizeof(bytes) &&
               !std::memcmp(offer.payload, bytes, sizeof(bytes)));
        recovering.output_blocked(now);
    }
    assert(live.write("ok", 2, 430) == 2);
    live_peer.input(require_output(live, 430).segment(), 431);
    live.input(require_output(live_peer, 432, false).segment(), 433);
    assert(live.queued() == 0 && live_peer.read(actual, sizeof(actual)) == 2 &&
           !std::memcmp(actual, "ok", 2));
    receiver.input(require_output(recovering, 620).segment(), 621);
    assert(receiver.read(actual, sizeof(actual)) == sizeof(bytes) &&
           !std::memcmp(actual, bytes, sizeof(bytes)));
    recovering.input(require_output(receiver, 622, false).segment(), 623);
    assert(recovering.queued() == 0 &&
           recovering.next_send() == uint32_t(0xfffffff1 + sizeof(bytes)));
    no_output(recovering, lifetime + 20);
    assert(recovering.state() == State::established && recovering.error() == 0);
    cases++;

    Connection retransmitting, absent;
    establish(retransmitting, absent);
    assert(retransmitting.write("x", 1, 20) == 1);
    Packet first = require_output(retransmitting, 20);
    no_output(retransmitting, 1019);
    for (uint64_t now : {uint64_t(1020), uint64_t(1220)}) {
        assert(output(retransmitting, now, true, packet, false));
        assert(packet.bytes == first.bytes);
        retransmitting.output_blocked(now);
    }
    assert(require_output(retransmitting, 1420).bytes == first.bytes);
    no_output(retransmitting, 3419);
    assert(require_output(retransmitting, 3420).bytes == first.bytes);
    cases++;

    Connection acknowledger, sender;
    establish(acknowledger, sender);
    assert(sender.write("x", 1, 20) == 1);
    acknowledger.input(require_output(sender, 20, false).segment(), 21);
    assert(output(acknowledger, 21, true, packet, false));
    assert(packet.segment().length == 0 && packet.segment().flags == ack);
    acknowledger.output_blocked(21);
    no_output(acknowledger, 220);
    assert(output(acknowledger, lifetime + 21, true, packet, false));
    acknowledger.output_blocked(lifetime + 21);
    assert(acknowledger.state() == State::established && acknowledger.error() == 0);
    auto answer = require_output(acknowledger, lifetime + 221).segment();
    assert(answer.flags == ack && answer.length == 0 &&
           answer.acknowledgment == sender.next_send());
    cases++;

    Connection opening;
    opening.active(100, 0);
    assert(output(opening, 0, true, packet, false));
    opening.output_blocked(0);
    no_output(opening, 199);
    assert(output(opening, 59999, true, packet, false));
    opening.output_blocked(59999);
    no_output(opening, 60000);
    assert(opening.state() == State::closed && opening.error() == 110 &&
           opening.next_send() == 100);
    cases++;

    Connection saturated, peer;
    establish(saturated, peer);
    saturated.output_blocked(20); // No live offer means no delay and no delivery period.
    assert(saturated.write("x", 1, UINT64_MAX - 100) == 1);
    assert(output(saturated, UINT64_MAX - 100, true, packet, false));
    saturated.output_blocked(UINT64_MAX - 100);
    no_output(saturated, UINT64_MAX - 1);
    assert(require_output(saturated, UINT64_MAX).segment().length == 1);
    assert(saturated.error() == 0 && saturated.next_send() == 102);
    cases++;

    Connection completed, last_peer;
    establish(completed, last_peer);
    completed.close_write();
    last_peer.input(require_output(completed, 20).segment(), 21);
    completed.input(require_output(last_peer, 22, false).segment(), 23);
    last_peer.close_write();
    completed.input(require_output(last_peer, 24, false).segment(), 25);
    assert(completed.state() == State::time_wait);
    assert(output(completed, 25, true, packet, false));
    completed.output_blocked(25);
    // The adapter compacts TIME-WAIT only after next() has no pending final ACK.
    assert(output(completed, 26, true, packet, false));
    assert(packet.segment().flags == ack && packet.segment().length == 0 &&
           packet.segment().acknowledgment == last_peer.next_send());
    completed.emitted(26);
    no_output(completed, 27);
    no_output(completed, 120025);
    assert(completed.state() == State::closed && completed.error() == 0);
    cases++;

    Connection transitioning, final_peer;
    establish(transitioning, final_peer);
    transitioning.detach(20);
    final_peer.input(require_output(transitioning, 20).segment(), 21);
    transitioning.input(require_output(final_peer, 22, false).segment(), 23);
    auto future = inbound(transitioning, transitioning.next_receive());
    future.acknowledgment = transitioning.next_send() + 1;
    transitioning.input(injection(future).segment(), 24);
    assert(output(transitioning, 25, true, packet, false));
    transitioning.output_blocked(25);
    final_peer.close_write();
    transitioning.input(require_output(final_peer, 26, false).segment(), 27);
    assert(transitioning.state() == State::time_wait);
    // A live-state delay must not hide a final ACK after entering TIME-WAIT either.
    assert(output(transitioning, 28, true, packet, false));
    assert(packet.segment().flags == ack &&
           packet.segment().acknowledgment == final_peer.next_send());
    transitioning.emitted(28);
    no_output(transitioning, 29);
    cases++;
    std::printf("TCP_LOCAL_OUTPUT_PASS cases=%u data fin user default sequence retry rto recovery "
                "independent ack syn backward saturation time_wait\n",
                cases);
}

static void family_segment_defaults() {
    unsigned cases = 0;
    for (auto family : {Family::ipv4, Family::ipv6})
        for (bool passive : {false, true})
            for (uint16_t local : {uint16_t(1460), uint16_t(900)})
                for (uint16_t offered : {uint16_t(0), uint16_t(300), uint16_t(1400)}) {
                    Connection endpoint(family);
                    assert(endpoint.segment_size() == (family == Family::ipv6 ? 1220 : 536));
                    Segment peer;
                    peer.sequence = 800;
                    peer.flags = syn;
                    peer.window = 32768;
                    peer.maximum_segment = offered;
                    Segment packet;
                    if (passive) {
                        assert(endpoint.passive(100, peer, 0, local));
                        assert(endpoint.next(0, packet));
                        assert(packet.flags == (syn | ack) && packet.maximum_segment == local);
                        endpoint.emitted(0);
                        peer.flags = ack;
                        peer.sequence++;
                        peer.acknowledgment = 101;
                    } else {
                        endpoint.active(100, 0, local);
                        assert(endpoint.next(0, packet));
                        assert(packet.flags == syn && packet.maximum_segment == local);
                        endpoint.emitted(0);
                        peer.flags |= ack;
                        peer.acknowledgment = 101;
                    }
                    endpoint.input(peer, 10);
                    assert(endpoint.state() == State::established);
                    uint16_t fallback = family == Family::ipv6 ? 1220 : 536;
                    uint16_t expected = std::min(local, offered ? offered : fallback);
                    assert(endpoint.segment_size() == expected);
                    if (!passive) {
                        assert(endpoint.next(10, packet) && packet.flags == ack);
                        endpoint.emitted(10);
                    }
                    uint8_t bytes[2000];
                    for (unsigned at = 0; at < sizeof(bytes); at++)
                        bytes[at] = uint8_t(at * 31);
                    assert(endpoint.write(bytes, sizeof(bytes), 20) == sizeof(bytes));
                    assert(endpoint.next(20, packet) && packet.length == expected);
                    assert(!std::memcmp(packet.payload, bytes, expected));
                    endpoint.emitted(20);
                    // MSS negotiation must feed the actual sender and its original loss clock.
                    assert(endpoint.next(1020, packet) && packet.length == expected);
                    assert(!std::memcmp(packet.payload, bytes, expected));
                    endpoint.emitted(1020);
                    cases++;
                }
    std::printf("TCP_FAMILY_MSS_PASS cases=%u active passive ipv4_536 ipv6_1220 "
                "peer_override local_limit real_sender retransmission\n",
                cases);
}

static void option_payload_limits() {
    unsigned cases = 0;
    for (uint16_t local : {uint16_t(536), uint16_t(1460)})
        for (uint16_t offered : {uint16_t(0), uint16_t(256), uint16_t(536), uint16_t(1460)})
            for (uint8_t initial_options : {uint8_t(4), uint8_t(40)}) {
                Connection endpoint;
                endpoint.ip_options(initial_options);
                endpoint.active(100, 0, local);
                Segment packet;
                assert(endpoint.next(0, packet) && packet.flags == syn &&
                       packet.maximum_segment == local);
                endpoint.emitted(0);
                Segment peer;
                peer.sequence = 800;
                peer.acknowledgment = 101;
                peer.flags = syn | ack;
                peer.window = 32768;
                peer.maximum_segment = offered;
                endpoint.input(peer, 10);
                uint16_t base = std::min(local, offered ? offered : uint16_t(536));
                assert(endpoint.state() == State::established &&
                       endpoint.segment_size() == base - initial_options);
                assert(endpoint.next(10, packet) && packet.flags == ack);
                endpoint.emitted(10);
                uint8_t bytes[1460];
                for (unsigned at = 0; at < sizeof(bytes); at++)
                    bytes[at] = uint8_t(at * 31);
                assert(endpoint.write(bytes, base, 20) == base);
                assert(endpoint.next(20, packet) &&
                       packet.length == size_t(base - initial_options) && packet.sequence == 101);
                // Changing the header invalidates an offer that has not entered IP output.
                endpoint.ip_options(0);
                assert(endpoint.next_send() == 101 && endpoint.segment_size() == base);
                assert(endpoint.next(20, packet) && packet.length == base &&
                       packet.sequence == 101 && !std::memcmp(packet.payload, bytes, base));
                endpoint.emitted(20);
                uint32_t end = endpoint.next_send();
                assert(end == 101u + base);
                endpoint.ip_options(40);
                no_output(endpoint, 1019);
                assert(endpoint.next(1020, packet) && packet.length == size_t(base - 40) &&
                       packet.sequence == 101 && !std::memcmp(packet.payload, bytes, base - 40));
                endpoint.emitted(1020);
                // Removing options restores only the learned path ceiling, and never a clock.
                uint16_t path = std::min(uint16_t(base - 1), uint16_t(208));
                assert(endpoint.path_mss(path) && endpoint.segment_size() == path - 40);
                endpoint.ip_options(0);
                assert(endpoint.segment_size() == path && endpoint.next_send() == end);
                no_output(endpoint, 3019);
                assert(endpoint.next(3020, packet) && packet.length == path &&
                       packet.sequence == 101 && !std::memcmp(packet.payload, bytes, path));
                endpoint.emitted(3020);
                cases++;
            }
    std::printf("TCP_IP_OPTIONS_MSS_PASS cases=%u advertised_mss offer_invalidation "
                "owned_sequence original_rto retained_path_ceiling\n",
                cases);
}

static void input_reply_ownership() {
    Connection opening;
    opening.active(100, 0);
    require_output(opening, 0);
    Segment invalid;
    invalid.sequence = 800;
    invalid.acknowledgment = 102;
    invalid.flags = ack;
    invalid.window = 32768;
    uint64_t revision = opening.reply_revision();
    opening.input(invalid, 5);
    assert(opening.reply_revision() != revision);
    Packet reply;
    assert(output(opening, 5, true, reply, false) && opening.input_reply() &&
           reply.segment().flags == rst && reply.segment().sequence == 102);
    opening.output_blocked(5);
    no_output(opening, 204);
    assert(output(opening, 205, true, reply, false) && opening.input_reply());
    opening.discard_input_reply();
    no_output(opening, 205);
    no_output(opening, 999);
    assert(output(opening, 1000, true, reply, false) && !opening.input_reply() &&
           reply.segment().flags == syn && opening.next_send() == 101);
    opening.emitted(1000);
    invalid.acknowledgment++;
    opening.input(invalid, 1001);
    assert(output(opening, 1001, true, reply, false) && opening.input_reply());
    opening.abort(0, true);
    assert(output(opening, 1001, true, reply, false) && !opening.input_reply() &&
           reply.segment().flags == rst && reply.segment().sequence == 101);
    opening.emitted(1001);

    Connection endpoint, peer;
    establish(endpoint, peer);
    endpoint.close_write();
    peer.input(require_output(endpoint, 20).segment(), 21);
    endpoint.input(require_output(peer, 22, false).segment(), 23);
    peer.close_write();
    Packet finish = require_output(peer, 24, false);
    endpoint.input(finish.segment(), 25);
    assert(endpoint.state() == State::time_wait);
    assert(output(endpoint, 25, true, reply, false) && !endpoint.input_reply());
    endpoint.emitted(25);
    uint32_t end = endpoint.next_send();
    revision = endpoint.reply_revision();
    endpoint.input(finish.segment(), 30);
    assert(endpoint.reply_revision() != revision);
    assert(output(endpoint, 30, true, reply, false) && endpoint.input_reply() &&
           reply.segment().flags == ack);
    endpoint.output_blocked(30);
    assert(output(endpoint, 31, true, reply, false) && endpoint.input_reply());
    endpoint.discard_input_reply();
    no_output(endpoint, 32);
    endpoint.input(finish.segment(), 33);
    assert(output(endpoint, 33, true, reply, false) && endpoint.input_reply());
    endpoint.emitted(33);
    no_output(endpoint, 34);
    assert(endpoint.next_send() == end);
    puts("TCP_INPUT_REPLY_PASS reset ownership local_abort cancellation original_rto time_wait");
}

int main() {
    input_reply_ownership();
    option_payload_limits();
    family_segment_defaults();
    local_output_retries();
    reconnect_sequences();
    default_lifetimes();
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
