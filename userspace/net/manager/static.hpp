// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/config/profile.hpp"
#include "net/dhcp/state.hpp"

namespace ax::net {
enum class StaticPhase : uint8_t {
    stopped,
    waiting_link,
    waiting,
    probing,
    installing,
    announcing,
    bound,
    conflicted
};

// RFC 5227 ownership for a validated fixed profile. Uses the same checked action
// completion contract as DHCP, but never transmits DHCP or replaces the address.
// A conflict before installation or within ten seconds of a defense blocks the
// profile until the configuring process is restarted. Link changes do not clear it.
class StaticAddress {
  public:
    explicit StaticAddress(const Profile& profile = Profile{});
    dhcp::Action advance(const dhcp::Event&, uint64_t now, uint32_t random);
    uint64_t deadline() const;
    uint32_t conflict_address() const;
    bool probing() const;

    StaticPhase phase() const {
        return phase_;
    }

    bool configured() const {
        return configured_;
    }

  private:
    enum class Role : uint8_t { none, probe, install, announce, defend, withdraw };
    Profile profile_;
    StaticPhase phase_ = StaticPhase::stopped;
    dhcp::Action pending_;
    Role role_ = Role::none;
    uint64_t now_ = 0, due_ = dhcp::never, retry_at_ = dhcp::never, defended_at_ = 0;
    uint32_t serial_ = 0;
    unsigned probes_ = 0, announcements_ = 0;
    bool valid_ = false, configured_ = false, remove_ = false, blocked_ = false;
    bool defended_ = false, defend_ = false, stopping_ = false;
    void cancel();
    void begin(uint32_t random);
    void queue(dhcp::Operation, Role);
    void complete(bool success, uint32_t random);
};
} // namespace ax::net
