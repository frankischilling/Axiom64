// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/state.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace ax::dhcp;

static void check(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "DHCP_STATE_FAIL %s\n", message);
        exit(1);
    }
}

static Identity identity{{0x52, 0x54, 0, 0x12, 0x34, 0x10}, "axiom64"};
constexpr uint32_t address = 0x0a170128, server = 0x0a170101, other_server = 0x0a170102;

struct Harness {
    Client client{identity};
    Action action;
    uint64_t now = 10000, requested_at = 0;

    void input(Input input, uint32_t hint = 0, uint32_t random = 0) {
        Event event;
        event.input = input;
        event.hint = hint;
        action = client.advance(event, now, random);
    }

    void tick(uint64_t time, uint32_t random = 0) {
        now = time;
        action = client.advance({}, now, random);
    }

    void done(bool success = true, uint32_t random = 0) {
        check(action.operation != Operation::none, "completion requires an emitted action");
        Event event;
        event.input = Input::completion;
        event.token = action.token;
        event.success = success;
        action = client.advance(event, now, random);
    }

    Reply message(Type type, uint32_t duration = 100) {
        Reply reply;
        reply.type = type;
        reply.transaction = client.transaction();
        reply.address = address;
        reply.server = reply.source = server;
        reply.destination = 0xffffffff;
        auto& parameters = reply.parameters;
        parameters.has_lease = parameters.has_mask = true;
        parameters.lease = duration;
        parameters.mask = 0xffffff00;
        parameters.router = server;
        parameters.has_renewal = parameters.has_rebinding = true;
        parameters.renewal = duration / 2;
        parameters.rebinding = uint64_t(duration) * 7 / 8;
        parameters.dns_count = 1;
        parameters.dns[0] = 0x0a170135;
        strcpy(parameters.domain, "lab.example");
        return reply;
    }

    void receive(const Reply& reply, uint32_t random = 0) {
        Event event;
        event.input = Input::reply;
        event.reply = &reply;
        action = client.advance(event, now, random);
    }

    void expect(Operation operation, const char* reason) {
        check(action.operation == operation, reason);
    }

    void start(uint32_t hint = 0) {
        input(Input::start, hint);
        expect(Operation::none, "startup delay does not block through an operation");
        check(client.deadline() >= now + 1000 && client.deadline() <= now + 10000,
              "startup delay in the standard randomized interval");
        tick(client.deadline());
        expect(Operation::transmit, "initial broadcast emitted");
        check(action.raw && action.destination == 0xffffffff && !action.request.address &&
                  action.request.mode == (hint ? Mode::reboot : Mode::discover),
              "saved address is only a bootstrap request hint");
        done();
    }

    void request() {
        start();
        auto offer = message(Type::offer);
        offer.parameters.dns[0] = 0x0a170199;
        receive(offer);
        expect(Operation::transmit, "first valid offer selected");
        check(action.request.mode == Mode::selecting && action.request.requested == address &&
                  action.request.server == server && action.raw,
              "selection names only the chosen address and server");
        requested_at = now;
        done();
    }

    void probes() {
        uint64_t previous = 0;
        for (unsigned i = 0; i < 3; i++) {
            if (action.operation == Operation::none)
                tick(client.deadline());
            expect(Operation::probe, "exactly three probes precede installation");
            check(action.lease.address == address && !client.configured(),
                  "candidate address not installed while probing");
            if (i)
                check(now >= previous + 1000 && now <= previous + 2000,
                      "actual accepted probes are spaced one to two seconds apart");
            previous = now;
            done();
        }
        check(client.deadline() == previous + 2000, "listen for two seconds after last probe");
        tick(client.deadline());
        expect(Operation::install, "owned lease installation requested after silence");
        check(!client.configured(), "installation is not declared successful before completion");
    }

    void announce() {
        done();
        expect(Operation::announce, "first announcement after checked installation");
        uint64_t first = now;
        done();
        expect(Operation::none, "second announcement is asynchronous");
        tick(first + 2000);
        expect(Operation::announce, "second announcement after two seconds");
        done();
        check(client.configured() && client.phase() == Phase::bound,
              "bound state after two announcements");
    }

    void bind(uint32_t duration = 100) {
        request();
        now += 200;
        receive(message(Type::ack, duration));
        probes();
        announce();
    }

    void cleanup() {
        for (unsigned i = 0; i < 3 && (action.operation == Operation::withdraw ||
                                       action.operation == Operation::forget);
             i++)
            done();
    }
};

static void acquisition(void) {
    Harness harness;
    harness.start();
    auto offer = harness.message(Type::offer);
    offer.transaction++;
    harness.receive(offer);
    harness.expect(Operation::none, "unrelated transaction ignored");
    offer = harness.message(Type::offer);
    offer.destination = 0x0a170129;
    harness.receive(offer);
    harness.expect(Operation::none, "unrelated unicast destination ignored");
    offer = harness.message(Type::offer);
    offer.parameters.dns[0] = 0x0a170199;
    harness.receive(offer);
    harness.expect(Operation::transmit, "selected request retained before transport accepts it");
    auto request = harness.action;
    auto ack = harness.message(Type::ack);
    harness.receive(ack);
    check(harness.client.phase() == Phase::requesting && !harness.client.configured(),
          "ACK before an accepted request cannot install a lease");
    harness.tick(harness.now + 100);
    check(harness.action.token == request.token &&
              harness.action.request.transaction == request.request.transaction &&
              harness.action.request.requested == request.request.requested &&
              harness.action.request.server == request.request.server,
          "failed or uncompleted output retains its token and owned request");
    harness.done(false);
    harness.tick(harness.now + 100);
    check(harness.action.token == request.token, "transient send failure retains transaction");
    harness.requested_at = harness.now;
    harness.done();
    ack.server = other_server;
    harness.receive(ack);
    check(harness.client.phase() == Phase::requesting, "ACK from an unselected server ignored");
    ack = harness.message(Type::ack);
    harness.receive(ack);
    ack = {};
    ack.parameters.dns[0] = 0xa5a5a5a5;
    strcpy(ack.parameters.domain, "overwritten.example");
    harness.probes();
    check(harness.action.lease.granted_at == harness.requested_at &&
              harness.action.lease.parameters.dns[0] == 0x0a170135,
          "committed ACK replaces offer parameters and owns the overwritten receive snapshot");
    harness.announce();
    puts("DHCP_STATE_ACQUISITION_PASS");
}

static void retransmission(void) {
    Harness harness;
    harness.start(address);
    uint32_t transaction = harness.client.transaction();
    const uint64_t gaps[]{3000, 7000, 15000, 31000};
    for (unsigned i = 0; i < 4; i++) {
        uint64_t interval = harness.client.deadline() - harness.now;
        check(interval >= gaps[i] && interval <= gaps[i] + 2000,
              "request retransmission uses bounded randomized exponential backoff");
        harness.tick(harness.client.deadline());
        if (i != 3) {
            check(harness.action.request.mode == Mode::reboot &&
                      harness.client.transaction() == transaction,
                  "reboot retry keeps identity and does not install the saved address");
            harness.done();
        } else {
            harness.expect(Operation::forget, "unanswered saved hint invalidated");
            harness.done();
            check(harness.action.request.mode == Mode::discover &&
                      harness.client.transaction() != transaction && !harness.client.configured(),
                  "bounded reboot attempt falls back to a fresh discovery");
            harness.done();
        }
    }
    for (unsigned i = 0; i < 10; i++) {
        uint64_t interval = harness.client.deadline() - harness.now;
        check(interval >= 3000 && interval <= 65000, "discovery retry interval remains bounded");
        harness.tick(harness.client.deadline());
        check(harness.action.request.mode == Mode::discover, "absent server does not stop retries");
        harness.done();
    }
    harness.tick(harness.now + 70000000);
    check(harness.action.request.seconds == 65535, "BOOTP elapsed seconds saturate");
    puts("DHCP_STATE_RETRANSMISSION_PASS");
}

static void leases(void) {
    Harness harness;
    harness.bind();
    uint64_t renewal = harness.client.lease().renewal_at;
    uint64_t rebinding = harness.client.lease().rebinding_at;
    uint64_t expiry = harness.client.lease().expires_at;
    harness.tick(renewal);
    check(harness.action.request.mode == Mode::renew && !harness.action.raw &&
              harness.action.destination == server && harness.action.request.address == address &&
              !harness.action.request.requested && !harness.action.request.server,
          "T1 uses configured UDP unicast without options 50 or 54");
    uint64_t sent = harness.now;
    harness.done();
    auto changed = harness.message(Type::ack, 200);
    changed.parameters.router = 0;
    changed.parameters.dns_count = 0;
    changed.parameters.domain[0] = 0;
    changed.server = other_server;
    harness.receive(changed);
    check(harness.client.phase() == Phase::renewing, "renewal rejects another server");
    harness.tick(rebinding);
    check(harness.action.request.mode == Mode::rebind && !harness.action.raw &&
              harness.action.destination == 0xffffffff && harness.action.request.address == address,
          "T2 uses configured UDP broadcast without discarding the lease");
    harness.done();
    changed.transaction = harness.client.transaction();
    harness.receive(changed);
    harness.expect(Operation::install, "rebinding accepts a valid server's changed ACK");
    check(harness.action.lease.server == other_server && !harness.action.lease.parameters.router &&
              !harness.action.lease.parameters.dns_count && harness.action.lease.granted_at == sent,
          "changed ACK replaces configuration and uses the earliest accepted request anchor");
    harness.done();
    check(harness.client.phase() == Phase::bound &&
              harness.client.lease().expires_at == sent + 200000 &&
              harness.client.lease().expires_at > expiry,
          "checked renewal extends the lease without reprobe of an unchanged address");
    expiry = harness.client.lease().expires_at;
    harness.tick(harness.client.lease().renewal_at);
    harness.done();
    auto late = harness.message(Type::ack, 1000);
    late.server = other_server;
    harness.now = expiry;
    harness.receive(late);
    harness.expect(Operation::withdraw, "expiry precedes processing a late ACK");
    check(harness.action.forget_hint, "expired lease hint revoked");
    auto stale = harness.action;
    harness.done(false);
    harness.tick(harness.now + 100);
    check(harness.action.token == stale.token, "failed withdrawal retries the same owned cleanup");
    harness.cleanup();
    check(!harness.client.configured(), "expiry removes address before reacquisition");
    puts("DHCP_STATE_LEASES_PASS");
}

static void timers_and_parameters(void) {
    Harness invalid;
    invalid.request();
    auto reply = invalid.message(Type::ack);
    reply.parameters.has_lease = false;
    invalid.receive(reply);
    check(invalid.client.phase() == Phase::requesting, "missing lease duration rejected");
    reply = invalid.message(Type::ack, 0);
    invalid.receive(reply);
    check(invalid.client.phase() == Phase::requesting, "zero lease duration rejected");
    reply = invalid.message(Type::ack);
    reply.parameters.renewal = 95;
    reply.parameters.rebinding = 10;
    reply.parameters.has_mask = false;
    reply.parameters.classless = true;
    reply.parameters.routes[0] = {0xac14ffff, 0xffff0000, server};
    reply.parameters.routes[1] = reply.parameters.routes[0];
    reply.parameters.route_count = 2;
    invalid.receive(reply, 0x12345678);
    invalid.probes();
    auto lease = invalid.action.lease;
    check(lease.parameters.mask == 0xff000000 && !lease.parameters.router &&
              lease.parameters.route_count == 1 &&
              lease.parameters.routes[0].destination == 0xac140000,
          "classful fallback and classless precedence/deduplication use the committed ACK");
    check(lease.renewal_at > lease.granted_at + 45000 &&
              lease.renewal_at < lease.granted_at + 55000 &&
              lease.renewal_at < lease.rebinding_at && lease.rebinding_at < lease.expires_at,
          "invalid T1/T2 replaced by fuzzed strictly ordered defaults");
    invalid.announce();
    Harness infinite;
    infinite.request();
    reply = infinite.message(Type::ack, UINT32_MAX);
    reply.parameters.has_renewal = reply.parameters.has_rebinding = false;
    infinite.receive(reply);
    infinite.probes();
    infinite.announce();
    check(infinite.client.lease().expires_at == never && infinite.client.deadline() == never,
          "infinite lease has no accidental integer deadline");
    infinite.tick(infinite.now + 9000000000000);
    infinite.expect(Operation::none, "infinite lease persists across a large monotonic advance");
    Harness tiny;
    tiny.request();
    reply = tiny.message(Type::ack, 1);
    tiny.now += 1000;
    tiny.receive(reply);
    check(tiny.client.phase() == Phase::requesting, "already expired ACK cannot begin probing");
    reply = tiny.message(Type::ack, 2);
    tiny.receive(reply);
    tiny.tick(tiny.requested_at + 2000);
    tiny.expect(Operation::forget, "lease expiring during probes cannot be installed");
    Harness bad_host;
    bad_host.request();
    reply = bad_host.message(Type::ack);
    reply.address = 0x0a170100;
    bad_host.receive(reply);
    check(bad_host.client.phase() == Phase::requesting, "unrequested network address ignored");
    puts("DHCP_STATE_TIMERS_PARAMETERS_PASS");
}

static void nak_and_installation(void) {
    Harness harness;
    harness.bind();
    harness.tick(harness.client.lease().renewal_at);
    harness.done();
    auto nak = harness.message(Type::nak);
    nak.server = other_server;
    harness.receive(nak);
    harness.expect(Operation::none, "unselected NAK does not revoke a valid lease");
    nak.server = server;
    nak.destination = address;
    harness.receive(nak);
    harness.expect(Operation::none, "invalid unicast NAK ignored");
    nak.destination = 0xffffffff;
    harness.receive(nak);
    harness.expect(Operation::withdraw, "valid NAK immediately requests address withdrawal");
    harness.cleanup();
    check(!harness.client.configured(), "NAK revokes the old configuration");
    harness.tick(harness.client.deadline());
    check(harness.action.request.mode == Mode::discover, "NAK restarts full acquisition");
    Harness failure;
    failure.request();
    failure.receive(failure.message(Type::ack));
    failure.probes();
    failure.done(false);
    failure.expect(Operation::withdraw, "failed installation forces checked rollback");
    check(!failure.client.configured(), "failed installation never claims bound configuration");
    failure.cleanup();
    check(failure.client.phase() == Phase::backoff, "failed installation returns to acquisition");
    puts("DHCP_STATE_NAK_INSTALLATION_PASS");
}

static void conflicts(void) {
    Harness harness;
    harness.request();
    harness.receive(harness.message(Type::ack));
    if (harness.action.operation == Operation::none)
        harness.tick(harness.client.deadline());
    harness.expect(Operation::probe, "candidate probe pending before conflict");
    auto stale = harness.action;
    harness.input(Input::conflict);
    harness.cleanup();
    check(harness.action.request.mode == Mode::decline && harness.action.raw &&
              harness.action.request.requested == address && !harness.action.request.address &&
              harness.action.request.server == server && !harness.client.configured(),
          "candidate conflict sends source-zero DECLINE and never installs the address");
    Event old;
    old.input = Input::completion;
    old.token = stale.token;
    old.success = true;
    harness.client.advance(old, harness.now, 0);
    check(harness.client.phase() == Phase::declining,
          "stale probe completion cannot bind after conflict");
    harness.done();
    check(harness.client.deadline() >= harness.now + 10000, "DECLINE waits at least ten seconds");
    harness.tick(harness.client.deadline());
    harness.done();
    for (unsigned i = 1; i < 10; i++) {
        harness.receive(harness.message(Type::offer));
        harness.done();
        harness.receive(harness.message(Type::ack));
        harness.input(Input::conflict);
        harness.cleanup();
        check(harness.action.request.mode == Mode::decline,
              "repeated conflicting address declined");
        harness.done();
        uint64_t interval = harness.client.deadline() - harness.now;
        check(interval == (i == 9 ? 60000u : 10000u),
              "ten conflicts enable the standard one-minute rate limit");
        harness.tick(harness.client.deadline());
        harness.done();
    }
    Harness bound;
    bound.bind();
    bound.input(Input::conflict);
    bound.expect(Operation::announce, "first ongoing conflict gets one defensive announcement");
    bound.done();
    bound.now += 9999;
    bound.input(Input::conflict);
    bound.expect(Operation::withdraw, "second conflict inside ten seconds relinquishes address");
    bound.cleanup();
    check(bound.action.request.mode == Mode::decline && !bound.client.configured(),
          "relinquishment reports conflicting lease after withdrawal");
    puts("DHCP_STATE_CONFLICTS_PASS");
}

static void lifecycle(void) {
    Harness harness;
    harness.bind();
    harness.input(Input::link_down);
    harness.expect(Operation::withdraw, "carrier loss immediately withdraws owned settings");
    check(!harness.action.forget_hint, "carrier change preserves only a revalidation hint");
    harness.done();
    check(harness.client.phase() == Phase::waiting_link && !harness.client.configured(),
          "disconnected interface holds no configuration");
    harness.input(Input::link_up);
    harness.tick(harness.client.deadline());
    check(harness.action.request.mode == Mode::reboot &&
              harness.action.request.requested == address && !harness.action.request.server &&
              !harness.client.configured(),
          "link return revalidates remembered address before use");
    harness.done();
    harness.requested_at = harness.now;
    harness.receive(harness.message(Type::ack));
    harness.probes();
    harness.announce();
    harness.input(Input::stop);
    check(harness.action.request.mode == Mode::release && !harness.action.raw &&
              harness.action.destination == server && harness.action.request.address == address &&
              harness.action.request.server == server,
          "graceful stop sends UDP unicast RELEASE with the installed identity");
    harness.done(false);
    harness.expect(Operation::withdraw, "failed best-effort RELEASE cannot prevent teardown");
    harness.cleanup();
    check(harness.client.phase() == Phase::stopped && !harness.client.configured(),
          "stopped client releases configuration and saved hint");
    Harness delayed;
    delayed.bind();
    delayed.input(Input::stop);
    uint32_t old_token = delayed.action.token;
    delayed.tick(delayed.now + 200);
    delayed.expect(Operation::withdraw, "uncompleted RELEASE bounded to 200 milliseconds");
    check(delayed.action.token != old_token, "timed-out release token superseded by cleanup");
    delayed.cleanup();
    Harness clock;
    clock.start();
    uint64_t due = clock.client.deadline();
    clock.tick(clock.now - 9000);
    check(clock.client.deadline() == due, "backward clock input cannot extend deadlines");
    puts("DHCP_STATE_LIFECYCLE_PASS");
}

static void renewal_during_announcement(void) {
    Harness harness;
    harness.request();
    harness.receive(harness.message(Type::ack, 10));
    harness.probes();
    harness.done();
    harness.expect(Operation::announce, "short lease sends its first announcement before renewal");
    uint64_t first = harness.now;
    harness.done();
    check(harness.client.lease().renewal_at < first + 2000,
          "fixture renews between the two initial announcements");
    harness.tick(harness.client.lease().renewal_at);
    check(harness.action.request.mode == Mode::renew,
          "renewal proceeds during announcement interval");
    harness.done();
    harness.receive(harness.message(Type::ack));
    harness.expect(Operation::install, "renewal configuration accepted during announcements");
    harness.done();
    harness.tick(first + 2000);
    harness.expect(Operation::announce,
                   "renewed lease retains the outstanding second announcement");
    harness.done();
    check(harness.client.configured() && harness.client.phase() == Phase::bound,
          "renewal and both required announcements complete");
    Harness defense;
    defense.bind();
    uint64_t renewal = defense.client.lease().renewal_at;
    defense.tick(renewal - 1);
    defense.input(Input::conflict);
    defense.expect(Operation::announce, "defense immediately before renewal");
    defense.done();
    defense.tick(renewal);
    defense.done();
    defense.receive(defense.message(Type::ack));
    defense.done();
    defense.now++;
    defense.input(Input::conflict);
    defense.expect(Operation::withdraw,
                   "renewal cannot reset the ten-second conflict defense interval");
    Harness partial;
    partial.request();
    auto reply = partial.message(Type::ack);
    reply.parameters.renewal = 20;
    reply.parameters.has_rebinding = false;
    partial.receive(reply);
    partial.probes();
    check(partial.action.lease.renewal_at == partial.requested_at + 20000 &&
              partial.action.lease.rebinding_at > partial.action.lease.renewal_at,
          "valid explicit T1 survives an absent T2 option");
    puts("DHCP_STATE_OVERLAPPING_TIMERS_PASS");
}

static void delayed_install_and_stop(void) {
    Harness installation;
    installation.request();
    installation.receive(installation.message(Type::ack, 10));
    installation.probes();
    installation.now = installation.action.lease.expires_at;
    installation.done();
    installation.expect(
        Operation::withdraw,
        "installation completing at expiry still requests owned configuration cleanup");
    installation.cleanup();
    check(!installation.client.configured(), "late installation cannot leave a bound lease");
    Harness release;
    release.bind();
    release.input(Input::stop);
    release.done();
    release.expect(Operation::none, "accepted RELEASE polls during its bounded output drain");
    check(release.client.configured() && release.client.phase() == Phase::releasing,
          "ARP can complete before removing the release source address");
    release.tick(release.now + 200);
    release.expect(Operation::withdraw, "successful release drain ends in owned cleanup");
    release.cleanup();
    check(release.client.phase() == Phase::stopped, "accepted RELEASE ends in stopped state");
    Harness expiration;
    expiration.bind();
    expiration.now = expiration.client.lease().expires_at - 100;
    expiration.input(Input::stop);
    expiration.done();
    expiration.tick(expiration.now + 100);
    expiration.expect(Operation::withdraw, "lease expiry bounds the release drain");
    expiration.cleanup();
    check(expiration.client.phase() == Phase::stopped,
          "expiry during graceful stop cannot restart acquisition");
    Harness carrier;
    carrier.bind();
    carrier.input(Input::stop);
    carrier.done();
    carrier.input(Input::link_down);
    carrier.cleanup();
    carrier.input(Input::link_up);
    check(carrier.client.phase() == Phase::stopped && !carrier.client.configured(),
          "carrier return cannot restart a stopped client");
    puts("DHCP_STATE_DELAYED_COMPLETION_STOP_PASS");
}

int main() {
    acquisition();
    retransmission();
    leases();
    timers_and_parameters();
    nak_and_installation();
    conflicts();
    lifecycle();
    renewal_during_announcement();
    delayed_install_and_stop();
    puts("DHCP_STATE_TESTS_PASS");
    return 0;
}
