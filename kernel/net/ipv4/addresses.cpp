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

uint64_t age(uint64_t now, uint64_t updated) {
    return now >= updated ? (now - updated) / 100 : 0;
}

uint32_t remaining(uint32_t lifetime, uint64_t elapsed) {
    return lifetime == UINT32_MAX ? UINT32_MAX : elapsed >= lifetime ? 0 : lifetime - elapsed;
}
} // namespace

const Ipv4Address* AddressBook::at(unsigned position) const {
    return position < count ? &entries[position].value : nullptr;
}

const Ipv4Address* AddressBook::label(unsigned index, const char* name, uint32_t hint) const {
    const Ipv4Address* first = nullptr;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n].value;
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
        const auto& entry = entries[n].value;
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

void AddressBook::renew(Slot& slot, Ipv4AddressLifetimes lifetime, uint64_t now) {
    slot.lifetime = lifetime;
    slot.updated = now;
    if (!slot.created)
        slot.created = now;
    slot.value.flags = (slot.value.flags & ~uint32_t(0xa0)) |
                       (lifetime.valid == UINT32_MAX ? 0x80 : 0) | (lifetime.preferred ? 0 : 0x20);
}

int AddressBook::add(unsigned index, const char* name, const Ipv4Config& value, uint64_t now,
                     Ipv4AddressLifetimes lifetime, bool replace) {
    if (!valid(index, name, value) || !value.address || !lifetime.valid ||
        lifetime.preferred > lifetime.valid)
        return -22;
    bool secondary = false;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n].value;
        if (entry.index != index || !same_prefix(entry.config, value))
            continue;
        if (entry.config.address == value.address) {
            if (!replace)
                return -17;
            // Linux refreshes the existing address's lifetime; replacement
            // labels and broadcast bytes do not replace its stored identity.
            renew(entries[n], lifetime, now);
            return 0;
        }
        secondary = true;
    }
    if (count == ipv4_address_capacity)
        return -105;
    const auto captured = value;
    char captured_name[16]{};
    memcpy(captured_name, name, strlen(name) + 1);
    // Primary addresses precede secondaries without changing primary order.
    unsigned position = count;
    if (!secondary)
        for (unsigned n = 0; n < count; n++)
            if (entries[n].value.index == index && entries[n].value.secondary) {
                position = n;
                break;
            }
    for (unsigned n = count; n > position; n--)
        entries[n] = entries[n - 1];
    auto& slot = entries[position];
    slot = {};
    auto& entry = slot.value;
    entry.index = index;
    entry.config = captured;
    entry.secondary = secondary;
    memcpy(entry.label, captured_name, strlen(captured_name) + 1);
    renew(slot, lifetime, now);
    count++;
    return 0;
}

void AddressBook::erase(unsigned position, bool promote) {
    auto removed = entries[position].value;
    unsigned promoted_position = count;
    Slot promoted;
    if (!removed.secondary && promote)
        for (unsigned n = 0; n < count; n++)
            if (entries[n].value.secondary && entries[n].value.index == removed.index &&
                same_prefix(entries[n].value.config, removed.config)) {
                promoted_position = n;
                promoted = entries[n];
                promoted.value.secondary = false;
                break;
            }
    unsigned kept = 0;
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n].value;
        if (n == position || n == promoted_position ||
            (!removed.secondary && !promote && entry.secondary && entry.index == removed.index &&
             same_prefix(entry.config, removed.config)))
            continue;
        entries[kept++] = entries[n];
    }
    if (promoted_position < count) {
        unsigned insert = kept;
        for (unsigned n = 0; n < kept; n++)
            if (entries[n].value.index == removed.index && entries[n].value.secondary) {
                insert = n;
                break;
            }
        for (unsigned n = kept; n > insert; n--)
            entries[n] = entries[n - 1];
        entries[insert] = promoted;
        kept++;
    }
    while (count > kept)
        entries[--count] = {};
}

int AddressBook::set(unsigned index, const char* name, const Ipv4Config& value, uint64_t now,
                     bool promote) {
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
        for (unsigned n = 0; n < count; n++)
            if (&entries[n].value == current) {
                erase(n, promote);
                break;
            }
    return replacement.address ? add(index, saved_name, replacement, now) : 0;
}

int AddressBook::remove(unsigned index, uint32_t address, uint32_t mask, bool promote) {
    for (unsigned n = 0; n < count; n++)
        if (entries[n].value.index == index && entries[n].value.config.address == address &&
            entries[n].value.config.mask == mask) {
            erase(n, promote);
            return 0;
        }
    return -99;
}

uint16_t AddressBook::expire(uint64_t now, uint16_t promote_interfaces) {
    uint16_t changed = 0;
    for (unsigned n = 0; n < count;) {
        auto& entry = entries[n];
        if (!(entry.value.flags & 0x80)) {
            uint64_t elapsed = age(now, entry.updated);
            uint16_t device = uint16_t(1u << (entry.value.index - 1));
            if (elapsed >= entry.lifetime.valid) {
                changed |= device;
                erase(n, promote_interfaces & device);
                continue;
            }
            if (elapsed >= entry.lifetime.preferred && !(entry.value.flags & 0x20)) {
                entry.value.flags |= 0x20;
                changed |= device;
            }
        }
        n++;
    }
    return changed;
}

Ipv4AddressCacheInfo AddressBook::cache(const Ipv4Address& value, uint64_t now) const {
    for (unsigned n = 0; n < count; n++) {
        const auto& entry = entries[n];
        if (entry.value.index != value.index ||
            entry.value.config.address != value.config.address ||
            entry.value.config.mask != value.config.mask)
            continue;
        uint64_t elapsed = age(now, entry.updated);
        return {entry.value.flags & 0x80 ? UINT32_MAX
                                         : remaining(entry.lifetime.preferred, elapsed),
                entry.value.flags & 0x80 ? UINT32_MAX : remaining(entry.lifetime.valid, elapsed),
                uint32_t(entry.created), uint32_t(entry.updated)};
    }
    return {0, 0, 0, 0};
}
} // namespace ax::ip4
