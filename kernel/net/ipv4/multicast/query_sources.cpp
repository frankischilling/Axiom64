// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv4/multicast/query_sources.cpp
 * @brief   IGMP source queries.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Handles source lists in IGMP queries and tracks source-specific response
 * state.
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
#include "net/ipv4/query_sources.hpp"
#include "net/ipv4_wire.hpp"
#include "core/base.hpp"

namespace ax::ip4 {
namespace {
void sift(uint32_t* values, unsigned root, unsigned end) {
    while (root < end / 2) {
        unsigned child = root * 2 + 1;
        if (child + 1 < end && values[child] < values[child + 1])
            child++;
        if (values[root] >= values[child])
            break;
        uint32_t temporary = values[root];
        values[root] = values[child];
        values[child] = temporary;
        root = child;
    }
}

void sort(uint32_t* values, unsigned count) {
    for (unsigned root = count / 2; root; root--)
        sift(values, root - 1, count);
    for (unsigned end = count; end > 1; end--) {
        uint32_t temporary = values[0];
        values[0] = values[end - 1];
        values[end - 1] = temporary;
        sift(values, 0, end - 1);
    }
}
} // namespace

MulticastQuerySources::MulticastQuerySources(MulticastQuerySources&& other) {
    *this = static_cast<MulticastQuerySources&&>(other);
}

MulticastQuerySources& MulticastQuerySources::operator=(MulticastQuerySources&& other) {
    if (this == &other)
        return *this;
    clear();
    budget = other.budget;
    addresses = other.addresses;
    allocated = other.allocated;
    count = other.count;
    other.budget = nullptr;
    other.addresses = nullptr;
    other.allocated = other.count = 0;
    return *this;
}

MulticastQuerySources::~MulticastQuerySources() {
    clear();
}

void MulticastQuerySources::clear() {
    if (addresses) {
        release(addresses);
        budget->used -= allocated;
    }
    budget = nullptr;
    addresses = nullptr;
    allocated = count = 0;
}

bool MulticastQuerySources::contains(uint32_t address) const {
    unsigned begin = 0, end = count;
    while (begin < end) {
        unsigned middle = begin + (end - begin) / 2;
        if (addresses[middle] < address)
            begin = middle + 1;
        else
            end = middle;
    }
    return begin < count && addresses[begin] == address;
}

bool MulticastQuerySources::merge(const uint8_t* wire, unsigned incoming,
                                  MulticastQueryBudget& memory) {
    if (!incoming)
        return true;
    if (!wire || incoming > 65535 || incoming > UINT32_MAX - count)
        return false;
    bool changed = false;
    for (unsigned n = 0; n < incoming; n++)
        changed |= !contains(get32(wire + size_t(n) * 4));
    if (!changed)
        return true;
    size_t length = (size_t(count) + incoming) * sizeof(uint32_t);
    // Charge the peak while both old and replacement copies exist. Allocation
    // pressure cannot erase an accepted query or turn it into a whole-group one.
    if (memory.used > memory.limit || length > memory.limit - memory.used)
        return false;
    auto next = static_cast<uint32_t*>(alloc(length));
    if (!next)
        return false;
    for (unsigned n = 0; n < count; n++)
        next[n] = addresses[n];
    for (unsigned n = 0; n < incoming; n++)
        next[count + n] = get32(wire + size_t(n) * 4);
    unsigned total = count + incoming;
    sort(next, total);
    unsigned unique = 0;
    for (unsigned n = 0; n < total; n++)
        if (!unique || next[n] != next[unique - 1])
            next[unique++] = next[n];
    clear();
    memory.used += length;
    budget = &memory;
    addresses = next;
    allocated = length;
    count = unique;
    return true;
}
} // namespace ax::ip4
