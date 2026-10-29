// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/addresses.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::ip4 {
namespace {
bool same_prefix(const Ipv4Config& a, const Ipv4Config& b) {
    return a.mask == b.mask && (a.address & a.mask) == (b.address & b.mask);
}

bool valid(unsigned index, const char* label, const Ipv4Config& value) {
    if (!index || index > max_net_devices || !label || !*label)
        return false;
    unsigned length = 0;
    while (length < 16 && label[length])
        length++;
    return length < 16 && mask_valid(value.mask) &&
           (!value.address || (unicast(value.address) && (value.address >> 24) != 127));
}
} // namespace

const Ipv4Address* AddressBook::at(unsigned position) const {
    return position < count ? &entries[position] : nullptr;
}

const Ipv4Address* AddressBook::label(unsigned index, const char* name, uint32_t hint) const {
    const Ipv4Address* first = nullptr;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n];
        if (entry.index != index || strcmp(entry.label, name))
            continue;
        if (entry.config.address == hint)
            return &entry;
        if (!first)
            first = &entry;
    }
    return first;
}

const Ipv4Address* AddressBook::preferred(unsigned index, uint32_t destination) const {
    const Ipv4Address* first = nullptr;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n];
        if (entry.index != index || entry.secondary)
            continue;
        if (!first)
            first = &entry;
        if (destination &&
            (destination & entry.config.mask) == (entry.config.address & entry.config.mask))
            return &entry;
    }
    return first;
}

int AddressBook::add(unsigned index, const char* name, const Ipv4Config& value) {
    if (!valid(index, name, value) || !value.address)
        return -22;
    bool secondary = false;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n];
        if (entry.index != index || !same_prefix(entry.config, value))
            continue;
        if (entry.config.address == value.address)
            return -17;
        secondary = true;
    }
    if (count == ipv4_address_capacity)
        return -105;
    // Primary addresses precede secondaries without changing primary order.
    unsigned position = count;
    if (!secondary)
        for (unsigned n = 0; n < count; n++)
            if (entries[n].index == index && entries[n].secondary) {
                position = n;
                break;
            }
    for (unsigned n = count; n > position; n--)
        entries[n] = entries[n - 1];
    auto& entry = entries[position];
    entry = {};
    entry.index = index;
    entry.config = value;
    entry.secondary = secondary;
    memcpy(entry.label, name, strlen(name) + 1);
    count++;
    return 0;
}

void AddressBook::erase(unsigned position) {
    auto removed = entries[position];
    unsigned kept = 0;
    for (unsigned n = 0; n < count; n++) {
        if (n == position ||
            (!removed.secondary && entries[n].secondary && entries[n].index == removed.index &&
             same_prefix(entries[n].config, removed.config)))
            continue;
        entries[kept++] = entries[n];
    }
    while (count > kept)
        entries[--count] = {};
}

int AddressBook::set(unsigned index, const char* name, const Ipv4Config& value) {
    if (!valid(index, name, value))
        return -22;
    const auto current = label(index, name);
    if (current && current->config.address == value.address && current->config.mask == value.mask &&
        current->config.broadcast == value.broadcast)
        return 0;
    // Linux replacement retires the old prefix before checking insertion
    // collisions. Capture borrowed arguments before compaction invalidates them.
    const auto replacement = value;
    char saved_name[16]{};
    memcpy(saved_name, name, strlen(name) + 1);
    if (current)
        erase(unsigned(current - entries));
    return replacement.address ? add(index, saved_name, replacement) : 0;
}

int AddressBook::remove(unsigned index, uint32_t address, uint32_t mask) {
    for (unsigned n = 0; n < count; n++)
        if (entries[n].index == index && entries[n].config.address == address &&
            entries[n].config.mask == mask) {
            erase(n);
            return 0;
        }
    return -99;
}
} // namespace ax::ip4
