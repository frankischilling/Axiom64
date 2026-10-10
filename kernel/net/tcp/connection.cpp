// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/connection.hpp"

namespace ax::tcp {
namespace {
// Elapsed threshold from the Linux default 15-retry, 200 ms/120 s model.
constexpr uint32_t default_delivery_timeout_ms = 924600;

template <class T> T minimum(T a, T b) {
    return a < b ? a : b;
}

bool elapsed(uint64_t now, uint64_t then, uint32_t interval) {
    return now >= then && now - then >= interval;
}

uint64_t after(uint64_t now, uint32_t interval) {
    return UINT64_MAX - now < interval ? UINT64_MAX : now + interval;
}
} // namespace

bool Connection::handshake() const {
    return status == State::syn_sent || status == State::syn_received;
}

void Connection::initialize(uint32_t initial, uint64_t now, uint16_t maximum_segment) {
    initialized = true;
    initial_send = send_unacknowledged = send_next = initial;
    send_base = initial + 1;
    local_mss = maximum_segment ? minimum(maximum_segment, uint16_t(1460)) : 1460;
    opened_at = progress_at = last_send = now;
    persist_at = after(now, persist_interval);
    syn_pending = true;
}

void Connection::active(uint32_t initial, uint64_t now, uint16_t maximum_segment) {
    if (status != State::closed || initialized)
        return;
    initialize(initial, now, maximum_segment);
    status = State::syn_sent;
}

void Connection::negotiate(const Segment& segment) {
    mss = minimum(local_mss, segment.maximum_segment ? segment.maximum_segment : uint16_t(536));
    congestion = Congestion(mss);
    peer_window = segment.window;
    maximum_peer_window = peer_window;
    window_sequence = segment.sequence;
    window_ack = segment.acknowledgment;
}

bool Connection::passive(uint32_t initial, const Segment& segment, uint64_t now,
                         uint16_t maximum_segment) {
    if (status != State::closed || initialized || !(segment.flags & syn) ||
        (segment.flags & (ack | rst | fin)))
        return false;
    initialize(initial, now, maximum_segment);
    initial_receive = segment.sequence;
    receive_next = segment.sequence + 1;
    negotiate(segment);
    status = State::syn_received;
    return true;
}

void Connection::synchronize(uint64_t now) {
    status = State::established;
    syn_pending = false;
    timer.established(syn_retransmitted);
    congestion.established(syn_retransmitted);
    retransmit_active = false;
    progress_at = now;
    persist_interval = timer.interval();
    persist_at = after(now, persist_interval);
}

size_t Connection::writable() const {
    if ((status != State::established && status != State::close_wait) || write_closed)
        return 0;
    return send_size < send_limit ? send_limit - send_size : 0;
}

uint16_t Connection::window() const {
    // Existing data remains readable when SO_RCVBUF is reduced below its occupancy.
    return receive_size < receive_limit ? receive_limit - receive_size : 0;
}

void Connection::limits(size_t receive_bytes, size_t send_bytes) {
    receive_limit = minimum(receive_bytes, stream_capacity);
    send_limit = minimum(send_bytes, stream_capacity);
    ack_pending = !handshake() && status != State::closed;
}

size_t Connection::write(const void* data, size_t length, uint64_t now) {
    candidate = Output::none;
    size_t count = minimum(length, writable());
    if (!data || !count)
        return 0;
    if (!send_size && !sent_fin) {
        progress_at = now;
        persist_interval = timer.interval();
        persist_at = after(now, persist_interval);
    }
    const auto bytes = static_cast<const uint8_t*>(data);
    for (size_t at = 0; at < count; at++)
        send_bytes[(send_head + send_size + at) % stream_capacity] = bytes[at];
    send_size += count;
    return count;
}

void Connection::discard(size_t count) {
    receive_head = (receive_head + count) % stream_capacity;
    receive_size -= count;
    if (count && status != State::closed)
        ack_pending = true;
}

size_t Connection::read(void* data, size_t length, bool peek, size_t offset) {
    candidate = Output::none;
    if (!data || offset >= receive_size)
        return 0;
    size_t count = minimum(length, receive_size - offset);
    auto bytes = static_cast<uint8_t*>(data);
    for (size_t at = 0; at < count; at++)
        bytes[at] = receive_bytes[(receive_head + offset + at) % stream_capacity];
    if (!peek && !offset)
        discard(count);
    return count;
}

void Connection::close_write() {
    candidate = Output::none;
    write_closed = true;
}

void Connection::close_read() {
    candidate = Output::none;
    read_closed = true;
    discard(receive_size);
}

void Connection::detach(uint64_t now) {
    detached = true;
    if (receive_size || handshake()) {
        abort(0, true);
        return;
    }
    close_write();
    if (status == State::fin_wait_2)
        expiration = after(now, 60000);
}

void Connection::abort(int error, bool send_reset) {
    candidate = Output::none;
    response_pending = false;
    if (send_reset && status != State::closed) {
        response = {};
        response.sequence = send_next;
        response.flags = rst;
        response_pending = true;
    }
    failure = error;
    status = State::closed;
    syn_pending = ack_pending = retransmit_pending = retransmit_active = false;
    delivery_active = false;
    sample_pending = false;
}

void Connection::reset_reply(const Segment& segment) {
    response = {};
    response.flags = rst;
    response.sequence = segment.acknowledgment;
    response_pending = true;
}

void Connection::challenge(uint64_t now) {
    // Invalid control segments share a per-connection interval. Ordinary data ACKs
    // remain independent, and a failed output enqueue leaves the permitted ACK pending.
    if (challenge_sent && !elapsed(now, challenge_at, 500))
        return;
    challenge_sent = true;
    challenge_at = now;
    ack_pending = true;
}

void Connection::wait(uint64_t now) {
    status = State::time_wait;
    expiration = after(now, 120000);
    retransmit_active = retransmit_pending = false;
    sample_pending = false;
}

void Connection::advance(uint64_t now) {
    if ((status == State::time_wait || (status == State::fin_wait_2 && detached)) &&
        now >= expiration)
        status = State::closed;
    if (handshake() && elapsed(now, opened_at, 60000))
        abort(110);
    if (!handshake() && status != State::closed && status != State::time_wait && timeout_ms &&
        (send_size || (sent_fin && send_unacknowledged != send_next) ||
         (write_closed && !sent_fin && delivery_active)) &&
        elapsed(now, progress_at, timeout_ms))
        abort(110);
    if (!handshake() && status != State::closed && status != State::time_wait && !timeout_ms &&
        delivery_active && elapsed(now, delivery_at, default_delivery_timeout_ms))
        abort(110);
}

void Connection::acknowledge(const Segment& segment, uint64_t now) {
    uint32_t acknowledged = segment.acknowledgment;
    if (before(acknowledged, send_unacknowledged))
        return;
    if (sample_pending && !before(acknowledged, sample_end)) {
        uint64_t duration = now >= sample_at ? now - sample_at : 0;
        timer.sample(duration > UINT32_MAX ? UINT32_MAX : duration, false);
        sample_pending = false;
    }
    uint16_t previous_window = peer_window;
    if (before(window_sequence, segment.sequence) ||
        (window_sequence == segment.sequence && !before(acknowledged, window_ack))) {
        peer_window = segment.window;
        if (peer_window > maximum_peer_window)
            maximum_peer_window = peer_window;
        window_sequence = segment.sequence;
        window_ack = acknowledged;
        if (peer_window && !previous_window && send_unacknowledged != send_next)
            retransmit_pending = true;
        if (peer_window && !previous_window && delivery_active) {
            // A responsive receiver can stay closed beyond the default period.
            // Reopening begins a fresh delivery period for already owned sequence.
            if (now > delivery_at)
                delivery_at = now;
            delivery_active = send_unacknowledged != send_next;
        }
        if (peer_window || previous_window) {
            // A newly closed window starts a fresh RTO-based persist period.
            // Repeated zero-window ACKs leave its exponential backoff intact.
            persist_interval = timer.interval();
            persist_at = after(now, persist_interval);
        }
    }
    if (acknowledged == send_unacknowledged) {
        // Default persist survives while a validated receiver answers probes.
        // Explicit user timeout still observes progress_at independently.
        if (!peer_window && delivery_active && now > delivery_at)
            delivery_at = now;
        if (send_unacknowledged != send_next && send_size && !segment.length &&
            !(segment.flags & (syn | fin)) && previous_window == segment.window && peer_window)
            retransmit_pending |= congestion.duplicate(send_next - send_unacknowledged);
        else
            congestion.acknowledged(0);
        return;
    }
    size_t bytes = minimum(size_t(acknowledged - send_base), send_size);
    // SYN/FIN sequence numbers are not bytes in the application send queue.
    if (before(acknowledged, send_base))
        bytes = 0;
    send_head = (send_head + bytes) % stream_capacity;
    send_size -= bytes;
    send_base += bytes;
    acknowledged_history += uint16_t(
        minimum(acknowledged - send_unacknowledged, uint32_t(UINT16_MAX - acknowledged_history)));
    send_unacknowledged = acknowledged;
    congestion.acknowledged(bytes);
    if (!before(acknowledged, timeout_end))
        repeated_timeout = false;
    retransmit_pending = false;
    progress_at = now;
    retransmit_active = send_unacknowledged != send_next;
    delivery_active = retransmit_active;
    if (delivery_active && now > delivery_at)
        delivery_at = now;
    if (retransmit_active)
        retransmit_at = after(now, timer.interval());
    if (sent_fin && acknowledged == finish_sequence + 1) {
        if (status == State::fin_wait_1) {
            status = State::fin_wait_2;
            if (detached)
                expiration = after(now, 60000);
        } else if (status == State::closing)
            wait(now);
        else if (status == State::last_ack)
            status = State::closed;
    }
}

bool Connection::present(size_t position) const {
    return receive_present[position / 8] & (1u << (position % 8));
}

void Connection::mark(size_t position, bool value) {
    uint8_t mask = 1u << (position % 8);
    if (value)
        receive_present[position / 8] |= mask;
    else
        receive_present[position / 8] &= ~mask;
}

void Connection::finish_received(uint64_t now) {
    received_fin = true;
    pending_fin = false;
    receive_next++;
    if (status == State::established)
        status = State::close_wait;
    else if (status == State::fin_wait_1)
        status = State::closing;
    else if (status == State::fin_wait_2)
        wait(now);
    ack_pending = true;
}

void Connection::receive(const Segment& segment, uint64_t now) {
    if (received_fin)
        return;
    if (detached && segment.length) {
        abort(0, true);
        return;
    }
    uint32_t window_end = receive_next + window();
    for (size_t at = 0; at < segment.length; at++) {
        uint32_t sequence = segment.sequence + at;
        if (before(sequence, receive_next) || !before(sequence, window_end) ||
            (pending_fin && !before(sequence, pending_fin_sequence)))
            continue;
        size_t position = (receive_head + receive_size + sequence - receive_next) % stream_capacity;
        if (!present(position)) { // First arrival owns overlapping bytes.
            receive_bytes[position] = segment.payload[at];
            mark(position, true);
        }
    }
    uint32_t fin_sequence = segment.sequence + segment.length;
    if ((segment.flags & fin) && !before(fin_sequence, receive_next) &&
        before(fin_sequence, window_end) &&
        (!pending_fin || before(fin_sequence, pending_fin_sequence))) {
        pending_fin = true;
        pending_fin_sequence = fin_sequence;
    }
    while (receive_size < receive_limit && (!pending_fin || receive_next != pending_fin_sequence)) {
        size_t position = (receive_head + receive_size) % stream_capacity;
        if (!present(position))
            break;
        mark(position, false);
        receive_size++;
        receive_next++;
    }
    if (pending_fin && receive_next == pending_fin_sequence)
        finish_received(now);
    if (read_closed)
        discard(receive_size);
    if (segment.length || (segment.flags & fin))
        ack_pending = true;
}

void Connection::input(const Segment& segment, uint64_t now) {
    candidate = Output::none;
    advance(now);
    if (status == State::closed || segment.length > maximum_segment_size ||
        (segment.length && !segment.payload))
        return;
    if (status == State::syn_sent) {
        bool valid_ack = (segment.flags & ack) && before(initial_send, segment.acknowledgment) &&
                         !before(send_next, segment.acknowledgment);
        if ((segment.flags & ack) && !valid_ack) {
            if (!(segment.flags & rst))
                reset_reply(segment);
            return;
        }
        if (segment.flags & rst) {
            if (valid_ack)
                abort(111);
            return;
        }
        if (!(segment.flags & syn) || (segment.flags & fin))
            return;
        initial_receive = segment.sequence;
        receive_next = segment.sequence + 1;
        negotiate(segment);
        if (valid_ack) {
            acknowledge(segment, now);
            synchronize(now);
            ack_pending = true;
            Segment text = segment;
            text.sequence++;
            text.flags &= ~syn;
            receive(text, now);
        } else {
            status = State::syn_received;
            syn_pending = true; // Simultaneous open resends our original SYN with an ACK.
        }
        return;
    }
    if (status == State::syn_received && (segment.flags & syn) &&
        !(segment.flags & (ack | rst | fin)) && segment.sequence == initial_receive) {
        syn_pending = true;
        return;
    }
    if (status == State::time_wait) {
        auto record = time_wait_state();
        auto action = time_wait_input(record, segment, now);
        expiration = record.deadline;
        if (action == TimeWaitAction::remove)
            abort(104);
        else if (action == TimeWaitAction::acknowledge)
            ack_pending = true;
        return;
    }
    if (!acceptable(segment.sequence, sequence_length(segment), receive_next, window())) {
        if (!(segment.flags & rst)) {
            if (!(segment.flags & syn) && sequence_length(segment))
                ack_pending = true;
            else
                challenge(now);
        }
        return;
    }
    if (segment.flags & rst) {
        auto decision = reset(segment.sequence, receive_next, window());
        if (decision == Reset::accept)
            abort(104);
        else if (decision == Reset::challenge)
            challenge(now);
        return;
    }
    if (segment.flags & syn) {
        challenge(now);
        return;
    }
    if (!(segment.flags & ack))
        return;
    uint32_t history = minimum(uint32_t(maximum_peer_window), uint32_t(acknowledged_history));
    if (before(send_next, segment.acknowledgment) ||
        (status != State::syn_received &&
         before(segment.acknowledgment, send_unacknowledged - history))) {
        if (status == State::syn_received)
            reset_reply(segment);
        else
            challenge(now);
        return;
    }
    if (status == State::syn_received) {
        if (segment.acknowledgment != initial_send + 1) {
            reset_reply(segment);
            return;
        }
        acknowledge(segment, now);
        synchronize(now);
    } else
        acknowledge(segment, now);
    if (status == State::established || status == State::fin_wait_1 || status == State::fin_wait_2)
        receive(segment, now);
    else if (segment.length || (segment.flags & fin))
        ack_pending = true;
}

void Connection::payload(Segment& segment, size_t offset, size_t length) {
    size_t position = (send_head + offset) % stream_capacity;
    segment.length = length;
    if (length <= stream_capacity - position)
        segment.payload = send_bytes + position;
    else {
        for (size_t at = 0; at < length; at++)
            packet_bytes[at] = send_bytes[(position + at) % stream_capacity];
        segment.payload = packet_bytes;
    }
}

bool Connection::oldest(Segment& segment) {
    if (handshake()) {
        segment.sequence = initial_send;
        segment.flags = syn | (status == State::syn_received ? ack : 0);
        segment.maximum_segment = local_mss;
    } else if (send_size && before(send_base, send_next)) {
        segment.sequence = send_base;
        size_t length = minimum(minimum(size_t(mss), send_size), size_t(send_next - send_base));
        payload(segment, 0, minimum(length, size_t(peer_window)));
        segment.flags = ack | psh;
    } else if (sent_fin && send_unacknowledged == finish_sequence) {
        segment.sequence = finish_sequence;
        segment.flags = ack | fin;
    } else
        return false;
    return true;
}

bool Connection::next(uint64_t now, Segment& result) {
    candidate = Output::none;
    advance(now);
    Segment segment{};
    segment.sequence = send_next;
    segment.acknowledgment = receive_next;
    segment.window = window();
    segment.flags = ack;
    timeout_candidate = false;
    if (response_pending) {
        segment = response;
        candidate = Output::response;
    } else if (status == State::closed)
        return false;
    else if (syn_pending) {
        segment.sequence = initial_send;
        segment.flags = syn | (status == State::syn_received ? ack : 0);
        segment.maximum_segment = local_mss;
        candidate = Output::handshake;
    } else if ((retransmit_pending || (retransmit_active && now >= retransmit_at)) &&
               (handshake() || peer_window)) {
        if (!oldest(segment))
            return false;
        candidate = Output::retransmit;
        timeout_candidate = !retransmit_pending;
    } else if (!handshake() && status != State::time_wait) {
        uint32_t flight = send_next - send_unacknowledged;
        if (!flight && elapsed(now, last_send, timer.interval()))
            congestion.idle();
        uint32_t allowance = minimum(uint32_t(peer_window), congestion.window());
        size_t unsent_offset = minimum(size_t(send_next - send_base), send_size);
        size_t unsent = send_size - unsent_offset;
        uint32_t space = flight < allowance ? allowance - flight : 0;
        bool full = unsent >= mss && space >= mss;
        bool nagle = no_delay || !flight || full;
        bool fits = unsent <= space && (no_delay || !flight);
        bool significant = space >= (uint32_t(maximum_peer_window) + 1) / 2;
        bool override = elapsed(now, last_send, 200);
        if (unsent && space && nagle && (full || fits || significant || override)) {
            payload(segment, unsent_offset, minimum(minimum(size_t(mss), unsent), size_t(space)));
            segment.flags |= psh;
            candidate = Output::data;
        } else if (write_closed && !sent_fin && unsent_offset == send_size && flight < allowance &&
                   (status == State::established || status == State::close_wait)) {
            segment.flags |= fin;
            candidate = Output::finish;
        } else if (!peer_window && (send_size || write_closed || flight) && now >= persist_at) {
            if (send_size) {
                segment.sequence = send_base;
                segment.payload = send_bytes + send_head;
                segment.length = 1;
            } else
                segment.sequence = send_unacknowledged - 1;
            candidate = Output::probe;
        }
    }
    if (candidate == Output::none && ack_pending) {
        candidate = Output::acknowledgment;
        segment.sequence = send_next;
    }
    if (candidate == Output::none)
        return false;
    produced = result = segment;
    return true;
}

void Connection::emitted(uint64_t now) {
    if (candidate == Output::none)
        return;
    Output kind = candidate;
    candidate = Output::none;
    if (kind == Output::response) {
        response_pending = false;
        return;
    }
    if (produced.flags & ack)
        ack_pending = false;
    if (kind == Output::acknowledgment)
        return;
    if (!handshake() && !delivery_active) {
        // Failed enqueue never reaches this ownership boundary. Retries cannot
        // restart an active period, including an unanswered zero-window probe.
        delivery_at = now;
        if (kind == Output::probe && !send_size && write_closed && !sent_fin)
            progress_at = now; // An empty FIN queued behind a closed window is now being probed.
        delivery_active = true;
    }
    uint32_t end = produced.sequence + sequence_length(produced);
    bool retransmitted = kind == Output::retransmit || (kind == Output::handshake && syn_emitted) ||
                         (kind == Output::probe && before(produced.sequence, send_next));
    if (before(send_next, end))
        send_next = end;
    if (kind == Output::handshake || (kind == Output::retransmit && handshake())) {
        syn_pending = false;
        syn_retransmitted |= syn_emitted;
        syn_emitted = true;
    }
    if (kind == Output::finish) {
        sent_fin = true;
        finish_sequence = produced.sequence;
        status = status == State::close_wait ? State::last_ack : State::fin_wait_1;
        if (!send_size)
            progress_at = now;
    }
    if (retransmitted)
        sample_pending = false;
    else if (!sample_pending && sequence_length(produced)) {
        sample_pending = true;
        sample_at = now;
        sample_end = end;
    }
    if (kind == Output::probe) {
        persist_interval = minimum(persist_interval * 2, uint32_t(60000));
        persist_at = after(now, persist_interval);
        return;
    }
    if (kind == Output::retransmit) {
        retransmit_pending = false;
        if (timeout_candidate) {
            if (!handshake())
                congestion.timeout(send_next - send_unacknowledged, repeated_timeout);
            repeated_timeout = true;
            timeout_end = end;
            timer.backoff();
            retransmit_at = after(now, timer.interval());
        }
    }
    if (!retransmit_active) {
        retransmit_at = after(now, timer.interval());
        retransmit_active = send_unacknowledged != send_next;
    }
    if (!retransmitted)
        last_send = now;
}
} // namespace ax::tcp
