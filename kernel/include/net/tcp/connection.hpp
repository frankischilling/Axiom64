// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/tcp/sender.hpp"
#include "net/tcp/wire.hpp"

namespace ax::tcp {
constexpr size_t stream_capacity = 32768;
enum class State {
    closed,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    closing,
    last_ack,
    time_wait
};

// A bounded TCP endpoint. The caller owns tuple lookup, packet validation, clock and storage.
// Input borrows a checksum-validated Segment; no input pointers survive the call.
// next() borrows send bytes until the immediately following emitted() or input/read/write call.
// Call emitted() only after copying the packet into an owned output queue. Failed enqueue
// leaves the candidate pending and does not consume sequence space or start a timer.
class Connection {
  public:
    State state() const {
        return status;
    }

    int error() const {
        return failure;
    }

    uint32_t next_receive() const {
        return receive_next;
    }

    uint32_t next_send() const {
        return send_next;
    }

    size_t available() const {
        return receive_size;
    }

    size_t queued() const {
        return send_size;
    }

    size_t writable() const;
    uint16_t window() const;

    bool eof() const {
        return received_fin || read_closed;
    }

    void active(uint32_t initial, uint64_t now, uint16_t maximum_segment = 1460);
    bool passive(uint32_t initial, const Segment& syn, uint64_t now,
                 uint16_t maximum_segment = 1460);
    void input(const Segment&, uint64_t now);
    bool next(uint64_t now, Segment&);
    void emitted(uint64_t now);
    size_t write(const void*, size_t, uint64_t now);
    size_t read(void*, size_t, bool peek = false, size_t offset = 0);
    void close_write();
    void close_read();
    void detach(uint64_t now);
    void abort(int error, bool send_reset = false);
    void limits(size_t receive_bytes, size_t send_bytes);

    void nodelay(bool enabled) {
        no_delay = enabled;
    }

    void user_timeout(uint32_t milliseconds) {
        timeout_ms = milliseconds;
    }

  private:
    enum class Output {
        none,
        response,
        handshake,
        data,
        finish,
        acknowledgment,
        retransmit,
        probe
    };
    State status = State::closed;
    Output candidate = Output::none;
    Segment produced{}, response{};
    Retransmission timer{};
    Congestion congestion{};
    uint8_t receive_bytes[stream_capacity]{}, receive_present[stream_capacity / 8]{};
    uint8_t send_bytes[stream_capacity]{};
    uint8_t packet_bytes[1460]{};
    size_t receive_head = 0, receive_size = 0, send_head = 0, send_size = 0;
    size_t receive_limit = stream_capacity, send_limit = stream_capacity;
    uint32_t initial_send = 0, initial_receive = 0, send_base = 0;
    uint32_t send_unacknowledged = 0, send_next = 0, receive_next = 0, finish_sequence = 0;
    uint32_t window_sequence = 0, window_ack = 0, pending_fin_sequence = 0;
    uint16_t peer_window = 0, maximum_peer_window = 0, mss = 536, local_mss = 1460;
    uint32_t timeout_ms = 0, persist_interval = 1000;
    uint64_t opened_at = 0, progress_at = 0, retransmit_at = 0, persist_at = 0;
    uint64_t sample_at = 0, expiration = 0, last_send = 0;
    uint32_t sample_end = 0, timeout_end = 0;
    int failure = 0;
    bool initialized = false, syn_pending = false, syn_emitted = false, syn_retransmitted = false;
    bool ack_pending = false, response_pending = false, retransmit_pending = false;
    bool retransmit_active = false, sample_pending = false, repeated_timeout = false;
    bool received_fin = false, pending_fin = false, sent_fin = false;
    bool write_closed = false, read_closed = false, detached = false;
    bool no_delay = false;
    bool timeout_candidate = false;
    void initialize(uint32_t, uint64_t, uint16_t);
    void negotiate(const Segment&);
    void synchronize(uint64_t);
    void acknowledge(const Segment&, uint64_t);
    void receive(const Segment&, uint64_t);
    void finish_received(uint64_t);
    void wait(uint64_t);
    void advance(uint64_t);
    void discard(size_t);
    void reset_reply(const Segment&);
    bool handshake() const;
    bool present(size_t) const;
    void mark(size_t, bool);
    bool oldest(Segment&);
    void payload(Segment&, size_t offset, size_t length);
};
} // namespace ax::tcp
