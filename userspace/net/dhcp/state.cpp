// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/state.hpp"
#include <string.h>

namespace ax::dhcp {
namespace {
uint64_t after(uint64_t now, uint64_t duration) {
    return duration > never - now ? never : now + duration;
}

bool unicast(uint32_t address) {
    unsigned first = address >> 24;
    return first && first != 127 && first < 224;
}

bool host(uint32_t address, uint32_t mask) {
    uint32_t bits = ~mask;
    return unicast(address) && !(bits & (bits + 1)) &&
           (bits < 2 || ((address & bits) && (address & bits) != bits));
}

uint64_t minimum(uint64_t left, uint64_t right) {
    return left < right ? left : right;
}

bool normalize(const Reply& reply, uint64_t sent, uint64_t now, uint32_t random, Lease& result) {
    auto parameters = reply.parameters;
    if (!parameters.has_lease || !parameters.lease || !unicast(reply.server) ||
        parameters.route_count > max_routes || parameters.dns_count > max_dns)
        return false;
    if (!parameters.has_mask) {
        unsigned first = reply.address >> 24;
        parameters.mask = first < 128 ? 0xff000000 : first < 192 ? 0xffff0000 : 0xffffff00;
        parameters.has_mask = true;
    }
    if (!host(reply.address, parameters.mask))
        return false;
    if (parameters.router && (!unicast(parameters.router) || parameters.router == reply.address))
        return false;
    size_t routes = 0;
    for (size_t i = 0; i < parameters.route_count; i++) {
        auto route = parameters.routes[i];
        uint32_t bits = ~route.mask;
        if ((bits & (bits + 1)) || (route.gateway && !unicast(route.gateway)))
            return false;
        route.destination &= route.mask;
        bool duplicate = false;
        for (size_t j = 0; j < routes; j++) {
            const auto& previous = parameters.routes[j];
            if (previous.destination != route.destination || previous.mask != route.mask)
                continue;
            if (previous.gateway != route.gateway)
                return false;
            duplicate = true;
        }
        if (!duplicate)
            parameters.routes[routes++] = route;
    }
    parameters.route_count = routes;
    if (parameters.classless)
        parameters.router = 0;
    for (size_t i = 0; i < parameters.dns_count; i++)
        if (!unicast(parameters.dns[i]) && (parameters.dns[i] >> 24) != 127)
            return false;
    Lease lease{};
    lease.address = reply.address;
    lease.server = reply.server;
    lease.parameters = parameters;
    lease.granted_at = sent;
    if (parameters.lease != UINT32_MAX) {
        uint64_t duration = uint64_t(parameters.lease) * 1000;
        // A supplied valid timer survives when the other option is absent.
        uint64_t default_renewal = duration / 2 - duration / 40 + random % (duration / 20 + 1);
        uint64_t default_rebinding =
            duration * 7 / 8 - duration / 80 + (random >> 16) % (duration / 40 + 1);
        uint64_t renewal =
            parameters.has_renewal ? uint64_t(parameters.renewal) * 1000 : default_renewal;
        uint64_t rebinding =
            parameters.has_rebinding ? uint64_t(parameters.rebinding) * 1000 : default_rebinding;
        if (!renewal || renewal >= rebinding || rebinding >= duration) {
            renewal = default_renewal;
            rebinding = default_rebinding;
        }
        lease.renewal_at = after(sent, renewal);
        lease.rebinding_at = after(sent, rebinding);
        lease.expires_at = after(sent, duration);
        if (lease.expires_at <= now)
            return false;
    } else if (parameters.has_renewal && parameters.has_rebinding && parameters.renewal &&
               parameters.renewal < parameters.rebinding && parameters.rebinding < UINT32_MAX) {
        lease.renewal_at = after(sent, uint64_t(parameters.renewal) * 1000);
        lease.rebinding_at = after(sent, uint64_t(parameters.rebinding) * 1000);
    }
    result = lease;
    return true;
}
} // namespace

void Client::cancel() {
    pending_ = {};
    role_ = Role::none;
    retry_at_ = never;
}

void Client::transaction(uint32_t random) {
    // Seed once; successive exchanges stay distinct even if a sample repeats.
    uint32_t next = transaction_ ? transaction_ + 1 : random ? random : 1;
    if (!next)
        next = 1;
    transaction_ = next;
    began_at_ = now_;
    request_sent_ = message_sent_ = false;
    attempts_ = 0;
    backoff_ = 4000;
}

void Client::begin(uint32_t random, bool delayed) {
    cancel();
    transaction(random);
    candidate_valid_ = false;
    requested_ = hint_;
    server_ = 0;
    phase_ = delayed ? Phase::waiting : hint_ ? Phase::rebooting : Phase::selecting;
    due_ = delayed ? after(now_, 1000 + random % 9001) : now_;
}

void Client::abandon(uint32_t random, bool conflict) {
    remove_ = remove_ || configured_ || role_ == Role::install;
    cancel();
    forget_ = true;
    hint_ = 0;
    defend_ = defended_ = announcing_ = false;
    if (stopping_) {
        candidate_valid_ = false;
        phase_ = Phase::stopped;
        due_ = never;
        return;
    }
    if (conflict) {
        if (conflicts_ < 10)
            conflicts_++;
        if (!candidate_valid_)
            candidate_ = lease_;
        candidate_valid_ = true;
        phase_ = Phase::declining;
        due_ = now_;
    } else {
        candidate_valid_ = false;
        phase_ = Phase::backoff;
        due_ = after(now_, 1000 + random % 9001);
    }
}

void Client::queue(Operation operation, Role role) {
    pending_ = {};
    pending_.operation = operation;
    pending_.token = ++serial_;
    if (!pending_.token)
        pending_.token = ++serial_;
    role_ = role;
    retry_at_ = now_;
}

void Client::transmit(Mode mode) {
    queue(Operation::transmit, Role::send);
    auto& request = pending_.request;
    request.identity = identity_;
    request.mode = mode;
    request.transaction = transaction_;
    uint64_t seconds = (now_ - began_at_) / 1000;
    request.seconds = mode == Mode::release || mode == Mode::decline ? 0
                      : seconds > 65535                              ? 65535
                                                                     : uint16_t(seconds);
    pending_.destination = 0xffffffff;
    if (mode == Mode::selecting || mode == Mode::reboot)
        request.requested = requested_;
    if (mode == Mode::selecting)
        request.server = server_;
    if (mode == Mode::renew || mode == Mode::rebind || mode == Mode::release) {
        pending_.raw = false;
        request.address = lease_.address;
        if (mode != Mode::rebind)
            pending_.destination = lease_.server;
    }
    if (mode == Mode::release)
        request.server = lease_.server;
    if (mode == Mode::decline) {
        request.server = candidate_.server;
        request.requested = candidate_.address;
    }
}

void Client::complete(bool success, uint32_t random) {
    if (!success) {
        if (role_ == Role::install) {
            remove_ = true;
            abandon(random, false);
        } else if (role_ == Role::send && pending_.request.mode == Mode::release) {
            cancel();
            phase_ = Phase::stopped;
            remove_ = configured_;
            forget_ = true;
            due_ = never;
        }
        return;
    }
    auto role = role_;
    auto mode = pending_.request.mode;
    cancel();
    switch (role) {
    case Role::send:
        if (mode == Mode::decline) {
            candidate_valid_ = false;
            phase_ = Phase::backoff;
            due_ = after(now_, conflicts_ >= 10 ? 60000 : 10000);
        } else if (mode == Mode::release) {
            // UDP acceptance can precede ARP completion. Keep the address for
            // the existing bounded release window while the transport polls.
            phase_ = Phase::releasing;
            due_ = never;
        } else {
            message_sent_ = true;
            if (mode != Mode::discover && !request_sent_) {
                request_sent_ = true;
                request_at_ = now_;
            }
            if (attempts_ < 255)
                attempts_++;
            if (mode == Mode::renew || mode == Mode::rebind) {
                uint64_t boundary = mode == Mode::renew ? lease_.rebinding_at : lease_.expires_at;
                uint64_t interval = boundary == never ? 60000 : (boundary - now_) / 2;
                if (interval < 60000)
                    interval = 60000;
                due_ = minimum(after(now_, interval), boundary);
            } else {
                due_ = after(now_, backoff_ - 1000 + random % 2001);
                if (backoff_ < 64000)
                    backoff_ *= 2;
            }
        }
        break;
    case Role::probe:
        probes_++;
        due_ = after(now_, probes_ == 3 ? 2000 : 1000 + random % 1001);
        break;
    case Role::announce:
        announcements_++;
        if (announcements_ == 2) {
            announcing_ = false;
            announce_at_ = never;
            if (phase_ == Phase::announcing)
                phase_ = Phase::bound;
        } else
            announce_at_ = after(now_, 2000);
        break;
    case Role::defend:
        defend_ = false;
        break;
    case Role::install:
        lease_ = candidate_;
        configured_ = true;
        candidate_valid_ = false;
        hint_ = lease_.address;
        request_sent_ = false;
        if (announce_new_) {
            defended_ = defend_ = false;
            announcements_ = 0;
            announcing_ = true;
            announce_at_ = now_;
        }
        phase_ = announcing_ ? Phase::announcing : Phase::bound;
        due_ = lease_.renewal_at;
        break;
    case Role::withdraw:
        remove_ = false;
        configured_ = false;
        lease_ = {};
        break;
    case Role::forget:
        forget_ = false;
        break;
    default:
        break;
    }
}

void Client::receive(const Reply& reply, uint32_t random) {
    if (reply.transaction != transaction_ || !message_sent_)
        return;
    if (phase_ == Phase::selecting) {
        Lease offer;
        if (reply.type != Type::offer ||
            (reply.destination != 0xffffffff && reply.destination != reply.address) ||
            !normalize(reply, now_, now_, random, offer))
            return;
        cancel();
        requested_ = offer.address;
        server_ = offer.server;
        phase_ = Phase::requesting;
        request_sent_ = message_sent_ = false;
        attempts_ = 0;
        backoff_ = 4000;
        due_ = now_;
        return;
    }
    bool extending = phase_ == Phase::renewing || phase_ == Phase::rebinding;
    if ((phase_ != Phase::requesting && phase_ != Phase::rebooting && !extending) ||
        !request_sent_ ||
        ((phase_ == Phase::requesting && reply.server != server_) ||
         (phase_ == Phase::renewing && reply.server != lease_.server)))
        return;
    if (reply.type == Type::nak) {
        if (reply.destination == 0xffffffff)
            abandon(random, false);
        return;
    }
    Lease lease;
    uint32_t expected = extending ? lease_.address : requested_;
    if (reply.type != Type::ack || reply.address != expected ||
        (reply.destination != 0xffffffff && reply.destination != expected) ||
        !normalize(reply, request_at_, now_, random, lease))
        return;
    cancel();
    candidate_ = lease;
    candidate_valid_ = true;
    announce_new_ = !extending;
    phase_ = extending ? Phase::installing : Phase::probing;
    probes_ = 0;
    due_ = extending ? now_ : after(now_, random % 1001);
}

void Client::timers(uint32_t random) {
    if ((configured_ && !remove_ && now_ >= lease_.expires_at && lease_.expires_at != never) ||
        (candidate_valid_ && phase_ != Phase::declining && candidate_.expires_at != never &&
         now_ >= candidate_.expires_at)) {
        abandon(random, false);
        return;
    }
    if (phase_ == Phase::releasing && now_ >= release_until_) {
        cancel();
        phase_ = Phase::stopped;
        remove_ = configured_;
        forget_ = true;
        due_ = never;
    }
    if (remove_ || forget_ || phase_ == Phase::stopped || phase_ == Phase::waiting_link)
        return;
    // A delayed main loop must still cross T2 before processing late replies.
    if (configured_ &&
        (phase_ == Phase::bound || phase_ == Phase::announcing || phase_ == Phase::renewing) &&
        now_ >= lease_.rebinding_at && lease_.rebinding_at != never) {
        bool renewing = phase_ == Phase::renewing;
        cancel();
        if (!renewing)
            transaction(random);
        phase_ = Phase::rebinding;
        due_ = now_;
    } else if (configured_ && (phase_ == Phase::bound || phase_ == Phase::announcing) &&
               now_ >= lease_.renewal_at && lease_.renewal_at != never) {
        cancel();
        transaction(random);
        phase_ = Phase::renewing;
        due_ = now_;
    }
    if (pending_.operation != Operation::none || now_ < due_)
        return;
    if (phase_ == Phase::waiting) {
        phase_ = hint_ ? Phase::rebooting : Phase::selecting;
        due_ = now_;
    } else if (phase_ == Phase::backoff)
        begin(random, false);
    else if ((phase_ == Phase::requesting || phase_ == Phase::rebooting) && attempts_ >= 4) {
        hint_ = 0;
        forget_ = true;
        begin(random, false);
    } else if (phase_ == Phase::probing && probes_ == 3) {
        phase_ = Phase::installing;
        due_ = now_;
    }
}

Action Client::advance(const Event& event, uint64_t now, uint32_t random) {
    if (now > now_)
        now_ = now;
    timers(random);
    if (event.input == Input::start && phase_ == Phase::stopped && !remove_ && !forget_) {
        stopping_ = false;
        hint_ = unicast(event.hint) ? event.hint : 0;
        begin(random, true);
    } else if (event.input == Input::link_down) {
        remove_ = remove_ || configured_ || role_ == Role::install;
        cancel();
        candidate_valid_ = false;
        announcing_ = defend_ = false;
        phase_ = stopping_ ? Phase::stopped : Phase::waiting_link;
        if (stopping_) {
            forget_ = true;
            hint_ = 0;
        }
        due_ = never;
    } else if (event.input == Input::link_up && phase_ == Phase::waiting_link)
        begin(random, true);
    else if (event.input == Input::stop && !stopping_) {
        stopping_ = true;
        remove_ = remove_ || role_ == Role::install;
        cancel();
        candidate_valid_ = false;
        announcing_ = defend_ = false;
        if (configured_ && !remove_ && !forget_) {
            phase_ = Phase::releasing;
            release_until_ = after(now_, 200);
            due_ = now_;
        } else {
            phase_ = Phase::stopped;
            remove_ = remove_ || configured_;
            forget_ = true;
            due_ = never;
        }
    } else if (event.input == Input::completion && pending_.operation != Operation::none &&
               event.token == pending_.token)
        complete(event.success, random);
    else if (event.input == Input::reply && event.reply)
        receive(*event.reply, random);
    else if (event.input == Input::conflict) {
        if (phase_ == Phase::probing || phase_ == Phase::installing)
            abandon(random, true);
        else if (configured_ && !remove_ && phase_ != Phase::releasing) {
            if (defended_ && now_ - defended_at_ < 10000)
                abandon(random, true);
            else {
                defended_ = true;
                defended_at_ = now_;
                defend_ = true;
                cancel();
            }
        }
    }
    timers(random);
    if (pending_.operation == Operation::none) {
        if (remove_) {
            queue(Operation::withdraw, Role::withdraw);
            pending_.lease = lease_;
            pending_.forget_hint = forget_;
        } else if (forget_)
            queue(Operation::forget, Role::forget);
        else if (defend_ && configured_) {
            queue(Operation::announce, Role::defend);
            pending_.lease = lease_;
        } else if (announcing_ && configured_ && now_ >= announce_at_) {
            queue(Operation::announce, Role::announce);
            pending_.lease = lease_;
        } else if (now_ >= due_) {
            switch (phase_) {
            case Phase::selecting:
                transmit(Mode::discover);
                break;
            case Phase::requesting:
                transmit(Mode::selecting);
                break;
            case Phase::rebooting:
                transmit(Mode::reboot);
                break;
            case Phase::renewing:
                transmit(Mode::renew);
                break;
            case Phase::rebinding:
                transmit(Mode::rebind);
                break;
            case Phase::declining:
                transmit(Mode::decline);
                break;
            case Phase::releasing:
                transmit(Mode::release);
                break;
            case Phase::probing:
                queue(Operation::probe, Role::probe);
                pending_.lease = candidate_;
                break;
            case Phase::installing:
                queue(Operation::install, Role::install);
                pending_.lease = candidate_;
                break;
            default:
                break;
            }
        }
    }
    if (pending_.operation != Operation::none && now_ >= retry_at_) {
        retry_at_ = after(now_, 100);
        return pending_;
    }
    return {};
}

uint64_t Client::deadline() const {
    uint64_t due = pending_.operation == Operation::none ? due_ : retry_at_;
    if (configured_ && !remove_) {
        due = minimum(due, lease_.expires_at);
        if (announcing_)
            due = minimum(due, announce_at_);
        if (phase_ == Phase::bound || phase_ == Phase::announcing)
            due = minimum(due, lease_.renewal_at);
        if (phase_ == Phase::renewing)
            due = minimum(due, lease_.rebinding_at);
    }
    if (candidate_valid_ && phase_ != Phase::declining)
        due = minimum(due, candidate_.expires_at);
    if (phase_ == Phase::releasing)
        due = minimum(due, release_until_);
    return due;
}

uint32_t Client::conflict_address() const {
    if (phase_ == Phase::probing || phase_ == Phase::installing)
        return candidate_.address;
    return configured_ && !remove_ ? lease_.address : 0;
}
} // namespace ax::dhcp
