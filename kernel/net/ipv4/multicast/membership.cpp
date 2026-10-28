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

struct ReportContext {
    MulticastHost::Emit emit;
    void* context;
    unsigned index;
    uint32_t group;
};

bool record(void* opaque, unsigned type, const uint32_t* sources, unsigned count) {
    auto& output = *static_cast<ReportContext*>(opaque);
    if (count > MulticastSourceReports::history_capacity)
        return false;
    uint8_t bytes[16 + MulticastSourceReports::history_capacity * 4]{};
    bytes[0] = 0x22;
    put16(bytes + 6, 1);
    bytes[8] = uint8_t(type);
    put16(bytes + 10, count);
    put32(bytes + 12, output.group);
    for (unsigned n = 0; n < count; n++)
        put32(bytes + 16 + n * 4, sources[n]);
    size_t length = 16 + count * 4;
    put16(bytes + 2, checksum(bytes, length));
    return output.emit(output.context, output.index, v3_routers, bytes, length);
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

void MulticastHost::synchronize(unsigned index, uint64_t now) {
    unsigned selected = version(index, now);
    if (links[index].selected == selected)
        return;
    links[index].selected = selected;
    // RFC 9776 section 7.2.1 cancels response and retransmission timers on
    // compatibility changes; source ownership remains unchanged.
    for (auto& entry : groups) {
        if (entry.index != index)
            continue;
        entry.response = entry.change = 0;
        entry.remaining = entry.source_count = entry.response_cursor = 0;
        entry.last_reporter = false;
        entry.reports.cancel();
        if (!entry.interest.owners())
            entry = {};
    }
}

void MulticastHost::changed(Group& entry, bool previously_present, uint64_t now) {
    entry.response_cursor = 0;
    bool present = entry.interest.owners() != 0;
    unsigned selected = version(entry.index, now);
    // Source edits do not change legacy group membership. Keep an already
    // pending join retransmission until accepted or explicitly suppressed.
    if (selected != 3 && present && previously_present && links[entry.index].up &&
        entry.address != all_hosts) {
        entry.reports.cancel();
        return;
    }
    entry.remaining = 0;
    entry.change = 0;
    if (!present) {
        entry.response = 0;
        entry.source_count = 0;
    }
    if (!links[entry.index].up || entry.address == all_hosts)
        entry.reports.cancel();
    else if (selected == 3) {
        if (entry.reports.pending())
            entry.change = now ? now : 1;
    } else {
        entry.reports.cancel();
        if (present != previously_present) {
            if (present)
                entry.remaining = links[entry.index].robustness;
            else if (selected == 2 && entry.last_reporter)
                entry.remaining = 1;
        }
        if (entry.remaining)
            entry.change = now ? now : 1;
    }
    if (!present && !entry.change)
        entry = {};
}

void MulticastHost::link(unsigned index, bool up, uint64_t now, uint32_t mtu) {
    if (!index || index >= interface_capacity)
        return;
    uint32_t usable_mtu = mtu >= 68 && mtu <= 65535 ? mtu : 68;
    links[index].mtu = usable_mtu;
    if (links[index].up == up)
        return;
    links[index] = {};
    links[index].up = up;
    links[index].mtu = usable_mtu;
    for (auto& entry : groups) {
        if (entry.index != index)
            continue;
        if (up) {
            entry.reports.restart(links[index].robustness);
            changed(entry, false, now);
        } else {
            entry.response = entry.change = 0;
            entry.remaining = entry.source_count = entry.response_cursor = 0;
            entry.last_reporter = false;
            entry.reports.cancel();
            if (!entry.interest.owners())
                entry = {};
        }
    }
}

void MulticastHost::receive(unsigned index, uint32_t destination, const uint8_t* bytes,
                            size_t length, bool router_alert, uint64_t now) {
    if (!index || index >= interface_capacity || !links[index].up || length < 8 ||
        checksum(bytes, length))
        return;
    synchronize(index, now);
    uint32_t address = get32(bytes + 4);
    if (bytes[0] == 0x12 || bytes[0] == 0x16) {
        if (length != 8 || bytes[1] || address != destination || !multicast(address) ||
            version(index, now) == 3)
            return;
        if (auto entry = find(index, address)) {
            entry->response = 0;
            entry->source_count = entry->response_cursor = 0;
            entry->last_reporter = false;
            if (entry->interest.owners()) {
                entry->change = 0;
                entry->remaining = 0;
                entry->reports.cancel();
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
            if (!address)
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
    synchronize(index, now);
    state.response_interval = maximum;
    // Spread a general response over the advertised interval. A group query
    // coalesces with any earlier response and never delays that pending report.
    for (auto& entry : groups) {
        if (entry.index != index || !entry.interest.owners() || entry.address == all_hosts ||
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
                    // Bounded query state falls back to a full record of the
                    // actual current filter, including its source list.
                    entry.source_count = 0;
                    break;
                }
                entry.sources[entry.source_count++] = source;
            }
        }
        entry.response_cursor = 0;
        entry.response = sooner(entry.response, now + delay(maximum));
    }
}

bool MulticastHost::respond(Group& entry, unsigned maximum, Emit emit, void* context) {
    uint32_t sources[MulticastSourceAggregate::capacity];
    unsigned count = 0;
    unsigned type = entry.interest.mode() ? 1 : 2;
    if (entry.source_count) {
        // RFC 9776 Table 5: INCLUDE intersects the query; EXCLUDE subtracts
        // its blocked sources. An empty source-specific response is omitted.
        type = 1;
        for (unsigned n = 0; n < entry.source_count; n++)
            if (entry.interest.accepts(entry.sources[n]))
                sources[count++] = entry.sources[n];
    } else
        count = entry.interest.sources(sources, MulticastSourceAggregate::capacity);
    if (type == 1 && !count)
        return true;
    ReportContext output{emit, context, entry.index, entry.address};
    for (;;) {
        unsigned remaining = count - entry.response_cursor;
        unsigned copied = remaining < maximum ? remaining : maximum;
        if (!record(&output, type, sources + entry.response_cursor, copied))
            return false;
        if (type == 2 || entry.response_cursor + copied == count)
            return true;
        entry.response_cursor += copied;
    }
}

void MulticastHost::poll(uint64_t now, Emit emit, void* context) {
    if (!emit)
        return;
    for (unsigned index = 1; index < interface_capacity; index++)
        synchronize(index, now);
    for (auto& entry : groups) {
        if (!entry.index || !links[entry.index].up)
            continue;
        bool change = entry.change && entry.change <= now;
        bool response = entry.response && entry.response <= now && entry.interest.owners();
        if (!change && !response)
            continue;
        unsigned selected = version(entry.index, now);
        if (selected == 3) {
            unsigned maximum = (links[entry.index].mtu - 40) / 4;
            if (maximum > MulticastSourceReports::history_capacity)
                maximum = MulticastSourceReports::history_capacity;
            if (change) {
                ReportContext output{emit, context, entry.index, entry.address};
                if (!entry.reports.transmit(maximum, record, &output))
                    continue;
                entry.change = entry.reports.pending() ? now + delay(100) : 0;
            } else {
                if (!respond(entry, maximum, emit, context))
                    continue;
                entry.response = 0;
                entry.source_count = entry.response_cursor = 0;
            }
        } else {
            if (!entry.interest.owners() && (selected == 1 || !entry.last_reporter)) {
                entry = {};
                continue;
            }
            uint8_t bytes[8]{};
            bytes[0] = entry.interest.owners() ? (selected == 1 ? 0x12 : 0x16) : 0x17;
            uint32_t destination = entry.interest.owners() ? entry.address : all_routers;
            put32(bytes + 4, entry.address);
            put16(bytes + 2, checksum(bytes, sizeof(bytes)));
            if (!emit(context, entry.index, destination, bytes, sizeof(bytes)))
                continue;
            if (change) {
                if (entry.remaining)
                    entry.remaining--;
                entry.change = entry.remaining ? now + delay(1000) : 0;
            }
            if (response) {
                entry.response = 0;
                entry.source_count = entry.response_cursor = 0;
            }
        }
        entry.last_reporter = entry.interest.owners() != 0;
        if (!entry.interest.owners() && !entry.change)
            entry = {};
    }
}
} // namespace ax::ip4
