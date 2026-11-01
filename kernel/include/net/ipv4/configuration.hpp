// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4.hpp"

namespace ax::ip4 {
constexpr unsigned configuration_all = 0, configuration_default = UINT32_MAX;
enum class ConfigurationKey : uint8_t { accept_source_route, forwarding };

int configuration_read(unsigned index, ConfigurationKey, int32_t&);
int configuration_write(unsigned index, ConfigurationKey, int32_t);

// A retained proc description belongs to one interface initialization.
uint64_t configuration_generation(unsigned index);
void configuration_registered(unsigned index);
void configuration_reset();

bool configuration_source_route(unsigned index);
bool configuration_forwarding(unsigned index);
} // namespace ax::ip4
