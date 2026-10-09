// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/static.hpp"

namespace ax::net {
namespace {
uint64_t after(uint64_t now, uint64_t duration) {
    return duration > dhcp::never - now ? dhcp::never : now + duration;
}
} // namespace

StaticAddress::StaticAddress(const Profile& profile) : profile_(profile) {
    valid_ = profile.method == Method::fixed && valid_profile(profile);
}

void StaticAddress::cancel() {
    pending_ = {};
    role_ = Role::none;
    retry_at_ = dhcp::never;
}

void StaticAddress::begin(uint32_t random) {
    cancel();
    phase_ = StaticPhase::waiting;
    probes_ = announcements_ = 0;
    defended_ = defend_ = false;
    due_ = after(now_, random % 1001);
}

void StaticAddress::queue(dhcp::Operation operation, Role role) {
    pending_ = {};
    pending_.operation = operation;
    pending_.token = ++serial_;
    if (!pending_.token)
        pending_.token = ++serial_;
    pending_.lease.address = profile_.address;
    pending_.lease.parameters = profile_.parameters;
    role_ = role;
    retry_at_ = now_;
}

void StaticAddress::complete(bool success, uint32_t random) {
    if (!success) {
        if (role_ == Role::install) {
            remove_ = true;
            cancel();
            phase_ = StaticPhase::waiting;
            due_ = after(now_, 1000 + random % 9001);
            probes_ = announcements_ = 0;
        }
        return;
    }
    Role role = role_;
    cancel();
    switch (role) {
    case Role::probe:
        probes_++;
        due_ = after(now_, probes_ == 3 ? 2000 : 1000 + random % 1001);
        break;
    case Role::install:
        configured_ = true;
        phase_ = StaticPhase::announcing;
        due_ = now_;
        break;
    case Role::announce:
        announcements_++;
        phase_ = announcements_ == 2 ? StaticPhase::bound : StaticPhase::announcing;
        due_ = announcements_ == 2 ? dhcp::never : after(now_, 2000);
        break;
    case Role::defend:
        defend_ = false;
        break;
    case Role::withdraw:
        configured_ = remove_ = false;
        break;
    default:
        break;
    }
}

dhcp::Action StaticAddress::advance(const dhcp::Event& event, uint64_t now, uint32_t random) {
    if (now > now_)
        now_ = now;
    if (event.input == dhcp::Input::start && phase_ == StaticPhase::stopped && valid_ && !remove_) {
        stopping_ = false;
        begin(random);
    } else if (event.input == dhcp::Input::link_down || event.input == dhcp::Input::stop) {
        stopping_ |= event.input == dhcp::Input::stop;
        remove_ |= configured_ || role_ == Role::install;
        cancel();
        defend_ = false;
        phase_ = stopping_  ? StaticPhase::stopped
                 : blocked_ ? StaticPhase::conflicted
                            : StaticPhase::waiting_link;
        due_ = dhcp::never;
    } else if (event.input == dhcp::Input::link_up && phase_ == StaticPhase::waiting_link &&
               !blocked_ && !stopping_)
        begin(random);
    else if (event.input == dhcp::Input::completion &&
             pending_.operation != dhcp::Operation::none && event.token == pending_.token)
        complete(event.success, random);
    else if (event.input == dhcp::Input::conflict && conflict_address()) {
        if (!configured_ || (defended_ && now_ - defended_at_ < 10000)) {
            remove_ |= configured_ || role_ == Role::install;
            cancel();
            blocked_ = true;
            defend_ = false;
            phase_ = StaticPhase::conflicted;
            due_ = dhcp::never;
        } else {
            cancel();
            defended_ = defend_ = true;
            defended_at_ = now_;
        }
    }
    if (pending_.operation == dhcp::Operation::none) {
        if (remove_)
            queue(dhcp::Operation::withdraw, Role::withdraw);
        else if (defend_ && configured_)
            queue(dhcp::Operation::announce, Role::defend);
        else if (now_ >= due_) {
            if (phase_ == StaticPhase::waiting)
                phase_ = StaticPhase::probing;
            if (phase_ == StaticPhase::probing && probes_ == 3)
                phase_ = StaticPhase::installing;
            if (phase_ == StaticPhase::probing)
                queue(dhcp::Operation::probe, Role::probe);
            else if (phase_ == StaticPhase::installing)
                queue(dhcp::Operation::install, Role::install);
            else if (phase_ == StaticPhase::announcing)
                queue(dhcp::Operation::announce, Role::announce);
        }
    }
    if (pending_.operation != dhcp::Operation::none && now_ >= retry_at_) {
        retry_at_ = after(now_, 100);
        return pending_;
    }
    return {};
}

uint64_t StaticAddress::deadline() const {
    return pending_.operation == dhcp::Operation::none ? due_ : retry_at_;
}

uint32_t StaticAddress::conflict_address() const {
    return remove_ || blocked_ || stopping_ ? 0 : configured_ || probing() ? profile_.address : 0;
}

bool StaticAddress::probing() const {
    return phase_ == StaticPhase::waiting || phase_ == StaticPhase::probing ||
           phase_ == StaticPhase::installing;
}
} // namespace ax::net
