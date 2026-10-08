// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/dhcp/wire.hpp"

namespace ax::dhcp {
constexpr uint64_t never = UINT64_MAX;

struct Lease {
    uint32_t address = 0, server = 0;
    Parameters parameters;
    uint64_t granted_at = 0, renewal_at = never, rebinding_at = never, expires_at = never;
};

enum class Phase : uint8_t {
    stopped,
    waiting_link,
    waiting,
    selecting,
    requesting,
    rebooting,
    probing,
    installing,
    announcing,
    bound,
    renewing,
    rebinding,
    declining,
    releasing,
    backoff
};

enum class Input : uint8_t { tick, start, reply, conflict, completion, link_down, link_up, stop };

struct Event {
    Input input = Input::tick;
    const Reply* reply = nullptr;
    uint32_t token = 0, hint = 0;
    bool success = false;
};

enum class Operation : uint8_t { none, transmit, probe, announce, install, withdraw, forget };

struct Action {
    Operation operation = Operation::none;
    uint32_t token = 0, destination = 0;
    bool raw = true, forget_hint = false;
    Request request;
    Lease lease;
};

// Feed checked replies/conflicts, monotonic milliseconds, and fresh random samples.
// Complete each returned action with its token. Failed actions retain their owned
// bytes and retry after 100 ms; a newer transition invalidates stale completions.
class Client {
  public:
    explicit Client(const Identity& identity) : identity_(identity) {
    }

    Action advance(const Event&, uint64_t now, uint32_t random);

    Phase phase() const {
        return phase_;
    }

    uint32_t transaction() const {
        return transaction_;
    }

    uint64_t deadline() const;

    const Lease& lease() const {
        return lease_;
    }

    uint32_t conflict_address() const;

    bool configured() const {
        return configured_;
    }

  private:
    enum class Role : uint8_t { none, send, probe, announce, defend, install, withdraw, forget };
    Identity identity_;
    Phase phase_ = Phase::stopped;
    Lease lease_, candidate_;
    Action pending_;
    Role role_ = Role::none;
    uint64_t now_ = 0, due_ = never, retry_at_ = never, began_at_ = 0, request_at_ = 0;
    uint64_t defended_at_ = 0, release_until_ = never, announce_at_ = never;
    uint32_t transaction_ = 0, serial_ = 0, hint_ = 0, requested_ = 0, server_ = 0;
    unsigned attempts_ = 0, backoff_ = 4000, probes_ = 0, announcements_ = 0, conflicts_ = 0;
    bool configured_ = false, candidate_valid_ = false, request_sent_ = false;
    bool message_sent_ = false, remove_ = false, forget_ = false, defended_ = false;
    bool defend_ = false, announce_new_ = false, announcing_ = false, stopping_ = false;

    void cancel();

    void begin(uint32_t random, bool delayed);

    void transaction(uint32_t random);

    void abandon(uint32_t random, bool conflict);

    void complete(bool success, uint32_t random);

    void receive(const Reply&, uint32_t random);

    void timers(uint32_t random);

    void queue(Operation, Role);

    void transmit(Mode);
};
} // namespace ax::dhcp
