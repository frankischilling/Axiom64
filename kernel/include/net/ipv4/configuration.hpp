// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/configuration.hpp
 * @brief   IPv4 configuration policy interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the configuration scopes and policy values used by IPv4 processing.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include "net/ipv4.hpp"

namespace ax::ip4 {
constexpr unsigned configuration_all = 0, configuration_default = UINT32_MAX;
enum class ConfigurationKey : uint8_t { accept_source_route, forwarding, promote_secondaries };

int configuration_read(unsigned index, ConfigurationKey, int32_t&);
int configuration_write(unsigned index, ConfigurationKey, int32_t);

// A retained proc description belongs to one interface initialization.
uint64_t configuration_generation(unsigned index);
void configuration_registered(unsigned index);
void configuration_reset();

bool configuration_source_route(unsigned index);
bool configuration_forwarding(unsigned index);
bool configuration_promote_secondaries(unsigned index);
} // namespace ax::ip4
