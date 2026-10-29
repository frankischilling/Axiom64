// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/routes.hpp"

namespace ax::ip4 {
namespace {
bool same_owner(const RouteTable::Entry& a, const RouteTable::Entry& b) {
    return a.value.index == b.value.index && a.value.gateway == b.value.gateway &&
           a.value.metric == b.value.metric && a.value.protocol == b.value.protocol &&
           a.value.scope == b.value.scope && a.preferred_source == b.preferred_source;
}
} // namespace

const RouteTable::Entry* RouteTable::at(unsigned position) const {
    for (const auto& slot : entries)
        if (slot.installed) {
            if (!position)
                return &slot.entry;
            position--;
        }
    return nullptr;
}

bool RouteTable::owns(uint64_t owner) const {
    for (const auto& slot : entries)
        if (slot.installed && slot.entry.owner == owner)
            return owner != 0;
    return false;
}

int RouteTable::insert(const Ipv4Route& value, bool exclusive) {
    for (const auto& slot : entries) {
        const auto& other = slot.entry.value;
        if (slot.installed && other.destination == value.destination && other.mask == value.mask &&
            other.metric == value.metric &&
            (exclusive || (other.index == value.index && other.gateway == value.gateway &&
                           other.protocol == value.protocol && other.scope == value.scope &&
                           !slot.entry.preferred_source)))
            return -17;
    }
    Slot* empty = nullptr;
    for (unsigned n = ipv4_address_capacity; n < capacity; n++)
        if (!entries[n].installed) {
            empty = &entries[n];
            break;
        }
    if (!empty)
        return -105;
    Entry entry{value};
    entry.value.preferred_source = 0;
    for (const auto& slot : entries)
        if (slot.installed && same_owner(entry, slot.entry)) {
            entry.owner = slot.entry.owner;
            break;
        }
    if (!entry.owner) {
        if (next_owner == UINT64_MAX)
            return -75;
        entry.owner = ++next_owner;
    }
    *empty = {entry, true};
    return 0;
}

int RouteTable::erase(const Ipv4Route& value, bool control, uint64_t& removed_owner) {
    for (auto& slot : entries) {
        const auto& other = slot.entry.value;
        if (slot.installed && (!value.index || other.index == value.index) &&
            other.destination == value.destination && other.mask == value.mask &&
            (!value.gateway || other.gateway == value.gateway) &&
            (!value.metric || other.metric == value.metric) &&
            (!control || ((!value.protocol || other.protocol == value.protocol) &&
                          (value.scope == 255 || other.scope == value.scope)))) {
            removed_owner = slot.entry.owner;
            if (slot.entry.automatic)
                slot.installed = false;
            else
                slot = {};
            return 0;
        }
    }
    return -3;
}

void RouteTable::withdraw(unsigned index) {
    for (auto& slot : entries)
        if (slot.entry.value.index == index)
            slot = {};
}

int RouteTable::synchronize(const AddressBook& addresses, uint16_t active_interfaces) {
    Slot next[ipv4_address_capacity]{};
    unsigned count = 0, fresh = 0;
    for (unsigned n = 0; auto address = addresses.at(n); n++) {
        if (address->secondary || !address->index || address->index > max_net_devices ||
            !(active_interfaces & (1u << (address->index - 1))))
            continue;
        const auto& config = address->config;
        auto& target = next[count++];
        target.entry = {{config.address & config.mask, config.mask, 0, address->index, 0, 2, 253},
                        0,
                        config.address,
                        true};
        target.installed = true;
        bool retained = false;
        for (unsigned at = 0; at < ipv4_address_capacity; at++) {
            const auto& old = entries[at];
            if (old.entry.value.index == address->index && old.entry.value.mask == config.mask &&
                old.entry.preferred_source == config.address) {
                target = old;
                retained = true;
                break;
            }
        }
        fresh += !retained;
    }
    // Refuse exhaustion before changing any installed route or lifetime ID.
    if (fresh > UINT64_MAX - next_owner)
        return -75;
    for (auto& slot : next) {
        if (!slot.installed || slot.entry.owner)
            continue;
        for (unsigned n = ipv4_address_capacity; n < capacity; n++)
            if (entries[n].installed && same_owner(slot.entry, entries[n].entry)) {
                slot.entry.owner = entries[n].entry.owner;
                break;
            }
        if (!slot.entry.owner)
            for (const auto& other : next)
                if (other.installed && other.entry.owner && same_owner(slot.entry, other.entry)) {
                    slot.entry.owner = other.entry.owner;
                    break;
                }
        if (!slot.entry.owner)
            slot.entry.owner = ++next_owner;
    }
    for (unsigned n = 0; n < ipv4_address_capacity; n++)
        entries[n] = next[n];
    return 0;
}
} // namespace ax::ip4
