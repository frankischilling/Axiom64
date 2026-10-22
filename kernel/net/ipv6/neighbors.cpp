// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"

namespace ax::ip6 {
namespace {
enum class State { incomplete, reachable, stale, delay, probe, failed };

struct Neighbor {
    Address address, source;
    unsigned index = 0, attempts = 0;
    uint8_t mac[6]{};
    State state = State::incomplete;
    uint64_t due = 0, touched = 0;
};

Neighbor entries[64];

Neighbor* find(unsigned index, const Address& address) {
    for (auto& entry : entries)
        if (entry.index == index && entry.address == address)
            return &entry;
    return nullptr;
}

Neighbor* reserve(unsigned index, const Address& address) {
    if (auto entry = find(index, address))
        return entry;
    Neighbor* selected = nullptr;
    for (auto& entry : entries) {
        if (!entry.index) {
            selected = &entry;
            break;
        }
        if (entry.state != State::incomplete && entry.state != State::probe &&
            (!selected || entry.touched < selected->touched))
            selected = &entry;
    }
    if (!selected)
        return nullptr;
    *selected = {};
    selected->index = index;
    selected->address = address;
    selected->touched = ticks;
    return selected;
}

enum class ProbeSource { ready, missing, retired };

ProbeSource probe_source(Neighbor& entry) {
    if (ipv6_owned(entry.index, entry.source))
        return ProbeSource::ready;
    if (!ipv6_owned(0, entry.source)) {
        Ipv6Path path;
        if (ipv6_path({}, entry.address, entry.index, path))
            return ProbeSource::retired;
        if (ipv6_owned(entry.index, path.source)) {
            entry.source = path.source;
            return ProbeSource::ready;
        }
    }
    // A data source assigned to another interface cannot source this link's
    // solicitation. Linux falls back to a ready link-local address instead.
    for (unsigned n = 0; auto address = ipv6_address(n); n++) {
        if (address->index == entry.index && address->address.link_local() &&
            ipv6_owned(entry.index, address->address)) {
            entry.source = address->address;
            return ProbeSource::ready;
        }
    }
    return ProbeSource::missing;
}
} // namespace

Address all_nodes() {
    Address result;
    result.bytes[0] = 0xff;
    result.bytes[1] = 2;
    result.bytes[15] = 1;
    return result;
}

Address solicited_node(const Address& target) {
    auto result = all_nodes();
    result.bytes[11] = 1;
    result.bytes[12] = 0xff;
    for (unsigned n = 13; n < 16; n++)
        result.bytes[n] = target.bytes[n];
    return result;
}

void multicast_mac(const Address& address, uint8_t* mac) {
    mac[0] = mac[1] = 0x33;
    memcpy(mac + 2, address.bytes + 12, 4);
}

void neighbor_solicitation(unsigned index, const Address& address, const uint8_t* mac) {
    auto entry = reserve(index, address);
    if (!entry)
        return;
    if (entry->state == State::incomplete || memcmp(entry->mac, mac, 6)) {
        memcpy(entry->mac, mac, 6);
        entry->state = State::stale;
    }
    entry->touched = ticks;
}

void neighbor_advertisement(unsigned index, const Address& address, const uint8_t* mac,
                            bool solicited, bool override_mac) {
    auto entry = find(index, address);
    if (!entry)
        return;
    bool changed = mac && memcmp(entry->mac, mac, 6);
    if (entry->state == State::incomplete) {
        if (!mac)
            return;
        memcpy(entry->mac, mac, 6);
        entry->state = solicited ? State::reachable : State::stale;
    } else if (changed && !override_mac) {
        if (entry->state == State::reachable)
            entry->state = State::stale;
        return;
    } else {
        if (mac)
            memcpy(entry->mac, mac, 6);
        if (solicited)
            entry->state = State::reachable;
        else if (changed)
            entry->state = State::stale;
    }
    entry->due = ticks + 3000;
    entry->touched = ticks;
}

bool neighbor_resolve(unsigned index, const Address& source, const Address& address, uint8_t* mac) {
    auto entry = reserve(index, address);
    if (!entry)
        return false;
    entry->touched = ticks;
    entry->source = source;
    if (entry->state == State::incomplete || entry->state == State::failed)
        return false;
    if (entry->state == State::stale) {
        entry->state = State::delay;
        entry->due = ticks + 500;
    }
    memcpy(mac, entry->mac, 6);
    return true;
}

void neighbor_poll() {
    for (auto& entry : entries) {
        if (!entry.index)
            continue;
        if (!usable(entry.index)) {
            entry = {};
            continue;
        }
        if (entry.state == State::failed) {
            if (ticks >= entry.due)
                entry = {};
            continue;
        }
        if (entry.state == State::reachable && ticks >= entry.due)
            entry.state = State::stale;
        if (entry.state == State::delay && ticks >= entry.due) {
            entry.state = State::probe;
            entry.attempts = 0;
        }
        if (entry.state != State::incomplete && entry.state != State::probe)
            continue;
        auto source = probe_source(entry);
        if (source == ProbeSource::retired) {
            entry = {};
            continue;
        }
        if (ticks < entry.due)
            continue;
        if (entry.attempts == 3) {
            entry.state = State::failed;
            entry.due = ticks + 100;
            continue;
        }
        auto state = entry.state;
        if ((source == ProbeSource::missing ||
             !neighbor_probe(entry.index, entry.source, entry.address,
                             state == State::probe ? entry.mac : nullptr)) &&
            entry.state == state) {
            entry.attempts++;
            entry.due = ticks + 100;
        }
    }
}

void neighbor_reset() {
    for (auto& entry : entries)
        entry = {};
}
} // namespace ax::ip6
