// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6.hpp"

namespace ax::ip6 {
constexpr unsigned configuration_all = 0, configuration_default = UINT32_MAX;

enum class ConfigurationKey : uint8_t {
    generation_mode,
    disabled,
    accept_ra,
    autoconf,
    dad_transmits,
    enhanced_dad,
    router_solicitations
};

// Linux netlink stores the generation mode; a changed sysctl mode also starts
// address generation. Neither operation withdraws existing valid addresses.
enum class ConfigurationWrite : uint8_t { sysctl, netlink };

int configuration_read(unsigned index, ConfigurationKey, int32_t&);
int configuration_write(unsigned index, ConfigurationKey, int32_t,
                        ConfigurationWrite = ConfigurationWrite::sysctl);
int configuration_secret(unsigned index, const Address&);

int configuration_secret_read(unsigned index, Address&);

bool configuration_disabled(unsigned index);

// Construct the identifier for a supplied /64 prefix without publishing it.
int configuration_identifier(unsigned index, Address&, unsigned& counter, bool& privacy);

// A stable owner's retry keeps its algorithm across later generation-mode changes.
int configuration_stable_identifier(unsigned index, Address&, unsigned& counter);

void configuration_registered(unsigned index);
void configuration_changed(unsigned index);
void configuration_address_removed(unsigned index, const Address&);
void configuration_address_regenerated(unsigned index, const Address&, const Address&);
void configuration_poll();
void configuration_reset();
} // namespace ax::ip6
