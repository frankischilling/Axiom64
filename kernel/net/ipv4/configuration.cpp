// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv4/configuration.cpp
 * @brief   IPv4 interface configuration.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Maintains per-interface IPv4 settings and resolves effective values for the
 * network stack.
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
#include "net/ipv4/configuration.hpp"

namespace ax::ip4 {
namespace {
struct Values {
    int32_t accept_source_route = 1, forwarding = 0, promote_secondaries = 0;
};

struct Configuration {
    Values values;
    uint64_t generation = 0;
};

Configuration interfaces[max_net_devices + 1];
Values defaults, all{0, 0};
uint64_t next_generation = 1;

Configuration* select(unsigned index) {
    if (!index || index > ipv4_loopback || (index != ipv4_loopback && !net_info(index)))
        return nullptr;
    auto& state = interfaces[index - 1];
    if (!state.generation)
        state = {defaults, next_generation++};
    return &state;
}

Values* values(unsigned index) {
    if (index == configuration_all)
        return &all;
    if (index == configuration_default)
        return &defaults;
    auto state = select(index);
    return state ? &state->values : nullptr;
}

int32_t* field(Values& state, ConfigurationKey key) {
    switch (key) {
    case ConfigurationKey::accept_source_route:
        return &state.accept_source_route;
    case ConfigurationKey::forwarding:
        return &state.forwarding;
    case ConfigurationKey::promote_secondaries:
        return &state.promote_secondaries;
    }
    return nullptr;
}
} // namespace

int configuration_read(unsigned index, ConfigurationKey key, int32_t& value) {
    auto state = values(index);
    if (!state)
        return -19;
    auto selected = field(*state, key);
    if (!selected)
        return -22;
    value = *selected;
    return 0;
}

int configuration_write(unsigned index, ConfigurationKey key, int32_t value) {
    auto state = values(index);
    if (!state)
        return -19;
    auto selected = field(*state, key);
    if (!selected)
        return -22;
    bool changed = *selected != value;
    *selected = value;
    if (index == configuration_all && key == ConfigurationKey::forwarding && changed) {
        // ip_forward aliases all.forwarding. Only a changed global value propagates.
        defaults.forwarding = value;
        for (unsigned at = 1; at <= ipv4_loopback; at++)
            if (auto current = select(at))
                current->values.forwarding = value;
    }
    return 0;
}

uint64_t configuration_generation(unsigned index) {
    if (index == configuration_all || index == configuration_default)
        return 1;
    auto state = select(index);
    return state ? state->generation : 0;
}

void configuration_registered(unsigned index) {
    if (auto state = select(index))
        *state = {defaults, next_generation++};
}

void configuration_reset() {
    for (auto& state : interfaces)
        state = {};
    defaults = {};
    all = {0, 0};
}

bool configuration_source_route(unsigned index) {
    auto state = select(index);
    return state && all.accept_source_route && state->values.accept_source_route;
}

bool configuration_forwarding(unsigned index) {
    auto state = select(index);
    return state && state->values.forwarding;
}

bool configuration_promote_secondaries(unsigned index) {
    auto state = select(index);
    return state && (all.promote_secondaries || state->values.promote_secondaries);
}
} // namespace ax::ip4
