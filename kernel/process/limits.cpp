// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/limits.cpp
 * @brief   Process resource limits.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Stores and enforces the resource limits shared by a process and inherited by
 * its children.
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
#include "process/limits.hpp"

namespace ax {
ProcessLimits::ProcessLimits(uint64_t descriptor_capacity)
    : descriptor_capacity_(descriptor_capacity) {
    for (auto& value : values_)
        value = {resource_infinity, resource_infinity};
    values_[unsigned(Resource::open_files)] = {descriptor_capacity, descriptor_capacity};
    values_[unsigned(Resource::stack)].soft = 8 * 1024 * 1024;
    values_[unsigned(Resource::core)].soft = 0;
    values_[unsigned(Resource::message_queue)] = {819200, 819200};
    values_[unsigned(Resource::nice)] = {0, 0};
    values_[unsigned(Resource::realtime_priority)] = {0, 0};
}

int ProcessLimits::exchange(unsigned resource, const ResourceLimit* replacement,
                            ResourceLimit* previous, bool privileged) {
    if (resource >= unsigned(Resource::count))
        return -22;
    ResourceLimit proposed{};
    if (replacement) {
        proposed = *replacement;
        if (proposed.soft > proposed.hard)
            return -22;
        if ((resource == unsigned(Resource::open_files) && proposed.hard > descriptor_capacity_) ||
            (proposed.hard > values_[resource].hard && !privileged))
            return -1;
    }
    if (previous)
        *previous = values_[resource];
    if (replacement)
        values_[resource] = proposed;
    return 0;
}

uint64_t ProcessLimits::soft(Resource resource) const {
    return values_[unsigned(resource)].soft;
}

uint64_t ProcessLimits::hard(Resource resource) const {
    return values_[unsigned(resource)].hard;
}

int ProcessLimits::cpu_signal(uint64_t elapsed_ticks) {
    auto& limit = values_[unsigned(Resource::cpu)];
    uint64_t seconds = elapsed_ticks / 100;
    if (limit.hard != resource_infinity && seconds >= limit.hard)
        return 9;
    if (limit.soft != resource_infinity && seconds >= limit.soft) {
        limit.soft++;
        return 24;
    }
    return 0;
}
} // namespace ax
