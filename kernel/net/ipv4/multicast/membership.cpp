// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::ip4 {
namespace {
constexpr uint32_t all_hosts = 0xe0000001, all_routers = 0xe0000002, v3_routers = 0xe0000016;

uint64_t decode(uint8_t value) {
    return value < 128 ? value : uint64_t((value & 15) | 16) << (((value >> 4) & 7) + 3);
}

uint64_t sooner(uint64_t previous, uint64_t next) {
    return previous && previous < next ? previous : next;
}
} // namespace

void MulticastHost::seed(uint32_t value) {
    if (value)
        random_state = value;
}

uint64_t MulticastHost::delay(uint64_t maximum) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return maximum ? 1 + random_state % maximum : 1;
}

MulticastHost::Group* MulticastHost::find(unsigned index, uint32_t group) {
    for (auto& entry : groups)
        if (entry.index == index && entry.address == group)
            return &entry;
    return nullptr;
}

unsigned MulticastHost::version(unsigned index, uint64_t now) const {
    const auto& state = links[index];
    return state.v1_until > now ? 1 : state.v2_until > now ? 2 : 3;
}

void MulticastHost::changed(Group& entry, uint64_t now) {
    entry.response = 0;
    entry.source_count = 0;
    entry.remaining = links[entry.index].robustness;
    entry.change = now ? now : 1;
    if (!links[entry.index].up || entry.address == all_hosts ||
        (!entry.owners && (version(entry.index, now) == 1 ||
                           (version(entry.index, now) == 2 && !entry.last_reporter)))) {
        entry.remaining = 0;
        entry.change = 0;
        if (!entry.owners)
            entry = {};
    }
}

int MulticastHost::join(MulticastMembership& owner, unsigned index, uint32_t group, uint64_t now) {
    if (!multicast(group))
        return -22;
    if (!index || index >= interface_capacity)
        return -19;
    MulticastMembership::Entry* vacant = nullptr;
    for (auto& entry : owner.entries) {
        if (entry.index == index && entry.group == group)
            return -98;
        if (!entry.index && !vacant)
            vacant = &entry;
    }
    if (!vacant)
        return -105;
    auto entry = find(index, group);
    if (!entry)
        for (auto& candidate : groups)
            if (!candidate.index) {
                entry = &candidate;
                entry->index = index;
                entry->address = group;
                break;
            }
    if (!entry)
        return -105;
    *vacant = {group, index};
    if (!entry->owners++)
        changed(*entry, now);
    return 0;
}

int MulticastHost::leave(MulticastMembership& owner, unsigned index, uint32_t group, uint64_t now) {
    if (!multicast(group))
        return -22;
    for (auto& membership : owner.entries) {
        if (membership.group != group || (index && membership.index != index))
            continue;
        auto entry = find(membership.index, group);
        membership = {};
        if (entry && entry->owners && !--entry->owners)
            changed(*entry, now);
        return 0;
    }
    return -99;
}

void MulticastHost::close(MulticastMembership& owner, uint64_t now) {
    for (auto& entry : owner.entries)
        if (entry.index)
            leave(owner, entry.index, entry.group, now);
}

bool MulticastHost::member(unsigned index, uint32_t group) const {
    if (!index || index >= interface_capacity || !links[index].up)
        return false;
    if (group == all_hosts)
        return true;
    for (const auto& entry : groups)
        if (entry.index == index && entry.address == group && entry.owners)
            return true;
    return false;
}

bool MulticastHost::accepts(const MulticastMembership& owner, unsigned index,
                            uint32_t group) const {
    if (!member(index, group))
        return false;
    for (const auto& entry : owner.entries)
        if (entry.index == index && entry.group == group)
            return true;
    return owner.all;
}

void MulticastHost::link(unsigned index, bool up, uint64_t now) {
    if (!index || index >= interface_capacity || links[index].up == up)
        return;
    links[index] = {};
    links[index].up = up;
    for (auto& entry : groups) {
        if (entry.index != index)
            continue;
        if (up)
            changed(entry, now);
        else {
            entry.response = entry.change = 0;
            entry.remaining = entry.source_count = 0;
            entry.last_reporter = false;
            if (!entry.owners)
                entry = {};
        }
    }
}

void MulticastHost::receive(unsigned index, uint32_t destination, const uint8_t* bytes,
                            size_t length, bool router_alert, uint64_t now) {
    if (!index || index >= interface_capacity || !links[index].up || length < 8 ||
        checksum(bytes, length))
        return;
    uint32_t address = get32(bytes + 4);
    if (bytes[0] == 0x12 || bytes[0] == 0x16) {
        if (length != 8 || bytes[1] || address != destination || !multicast(address) ||
            version(index, now) == 3)
            return;
        if (auto entry = find(index, address)) {
            entry->response = 0;
            entry->last_reporter = false;
            if (entry->owners) {
                entry->change = 0;
                entry->remaining = 0;
            }
        }
        return;
    }
    if (bytes[0] != 0x11 || (address && !multicast(address)))
        return;
    auto& state = links[index];
    unsigned sources = 0;
    uint64_t maximum;
    if (length == 8) {
        if (!bytes[1]) {
            if (address)
                return;
            maximum = 1000;
            state.v1_until = now + state.robustness * state.query_interval + maximum;
        } else {
            maximum = uint64_t(bytes[1]) * 10;
            state.v2_until = now + state.robustness * state.query_interval + maximum;
        }
    } else {
        if (length < 12 || !router_alert)
            return;
        sources = get16(bytes + 10);
        if (length != 12 + size_t(sources) * 4 || (sources && !address))
            return;
        for (unsigned n = 0; n < sources; n++)
            if (!unicast(get32(bytes + 12 + n * 4)))
                return;
        maximum = decode(bytes[1]) * 10;
        state.robustness = (bytes[8] & 7) ? bytes[8] & 7 : 2;
        state.query_interval = decode(bytes[9]) ? decode(bytes[9]) * 100 : 12500;
    }
    state.response_interval = maximum;
    // Spread a general response over the advertised interval. A group query
    // coalesces with any earlier response and never delays that pending report.
    for (auto& entry : groups) {
        if (entry.index != index || !entry.owners || entry.address == all_hosts ||
            (address && address != entry.address))
            continue;
        bool whole = !sources || version(index, now) != 3;
        bool previous_whole = entry.response && !entry.source_count;
        if (whole || previous_whole)
            entry.source_count = 0;
        else {
            for (unsigned n = 0; n < sources; n++) {
                uint32_t source = get32(bytes + 12 + n * 4);
                bool present = false;
                for (unsigned old = 0; old < entry.source_count; old++)
                    present |= entry.sources[old] == source;
                if (present)
                    continue;
                if (entry.source_count == 64) {
                    // Bounded query state falls back to a complete EXCLUDE{}
                    // record, which preserves the host's actual ASM interest.
                    entry.source_count = 0;
                    break;
                }
                entry.sources[entry.source_count++] = source;
            }
        }
        entry.response = sooner(entry.response, now + delay(maximum));
    }
}

void MulticastHost::poll(uint64_t now, Emit emit, void* context) {
    for (auto& entry : groups) {
        if (!entry.index || !links[entry.index].up)
            continue;
        bool change = entry.change && entry.change <= now;
        bool response = entry.response && entry.response <= now && entry.owners;
        if (!change && !response)
            continue;
        uint8_t bytes[16 + 64 * 4]{};
        unsigned selected = version(entry.index, now);
        size_t length = 8;
        uint32_t destination = entry.address;
        if (selected == 3) {
            bytes[0] = 0x22;
            put16(bytes + 6, 1);
            bytes[8] = change ? (entry.owners ? 4 : 3) : entry.source_count ? 1 : 2;
            // Seven sources plus Router Alert and the report header fit the
            // minimum IPv4 MTU. Split INCLUDE lists instead of fragmenting IGMP.
            unsigned count = change ? 0 : entry.source_count > 7 ? 7 : entry.source_count;
            put16(bytes + 10, count);
            put32(bytes + 12, entry.address);
            for (unsigned n = 0; n < count; n++)
                put32(bytes + 16 + n * 4, entry.sources[n]);
            length = 16 + count * 4;
            destination = v3_routers;
        } else {
            if (!entry.owners && (selected == 1 || !entry.last_reporter)) {
                entry = {};
                continue;
            }
            bytes[0] = entry.owners ? (selected == 1 ? 0x12 : 0x16) : 0x17;
            if (!entry.owners)
                destination = all_routers;
            put32(bytes + 4, entry.address);
        }
        put16(bytes + 2, checksum(bytes, length));
        if (!emit(context, entry.index, destination, bytes, length))
            continue;
        entry.last_reporter = entry.owners != 0;
        if (change) {
            if (selected != 3 && !entry.owners)
                entry.remaining = 1;
            if (entry.remaining)
                entry.remaining--;
            entry.change = entry.remaining ? now + delay(selected == 3 ? 100 : 1000) : 0;
        }
        if (response && !change) {
            if (selected == 3 && entry.source_count > 7) {
                for (unsigned n = 7; n < entry.source_count; n++)
                    entry.sources[n - 7] = entry.sources[n];
                entry.source_count -= 7;
            } else {
                entry.response = 0;
                entry.source_count = 0;
            }
        }
        if (!entry.owners && !entry.remaining)
            entry = {};
    }
}
} // namespace ax::ip4
