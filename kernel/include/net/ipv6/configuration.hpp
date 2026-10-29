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
    router_solicitations,
    max_addresses
};

// Linux netlink stores the generation mode; a changed sysctl mode also starts
// address generation. Neither operation withdraws existing valid addresses.
enum class ConfigurationWrite : uint8_t { sysctl, netlink };

int configuration_read(unsigned index, ConfigurationKey, int32_t&);
int configuration_write(unsigned index, ConfigurationKey, int32_t,
                        ConfigurationWrite = ConfigurationWrite::sysctl);
int configuration_secret(unsigned index, const Address&);

int configuration_secret_read(unsigned index, Address&);

// Zero means no IPv6 configuration object exists. Retained proc descriptions
// bind to one generation and cannot attach to a later interface initialization.
uint64_t configuration_generation(unsigned index);

bool configuration_disabled(unsigned index);

// DAD retains readiness across physical carrier loss after this IPv6 scope
// first became operational. Administrative shutdown and disablement clear it.
bool configuration_dad_ready(unsigned index);

// New SLAAC owners and stable DAD retries share the per-interface address limit.
// Manual addresses and initial link-local generation retain their own admission.
bool configuration_autoconf_allowed(unsigned index);

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
