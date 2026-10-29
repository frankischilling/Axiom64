// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_reports.hpp"

namespace ax::ip4 {
namespace {
bool contains(const uint32_t* addresses, unsigned count, uint32_t value) {
    for (unsigned n = 0; n < count; n++)
        if (addresses[n] == value)
            return true;
    return false;
}

bool valid_robustness(unsigned value) {
    return value && value <= 7;
}
} // namespace

void MulticastSourceReports::reset_round() {
    cursor = round_count = 0;
    active = false;
}

void MulticastSourceReports::compact() {
    unsigned retained = 0;
    for (unsigned n = 0; n < used; n++)
        if (sources[n].reserved || sources[n].remaining)
            sources[retained++] = sources[n];
    for (unsigned n = retained; n < used; n++)
        sources[n] = {};
    used = retained;
}

bool MulticastSourceReports::forwards(const Source& source) const {
    return include == source.listed;
}

int MulticastSourceReports::change(unsigned mode, const uint32_t* addresses, unsigned count,
                                   unsigned robustness) {
    return update(mode, addresses, count, addresses, count, robustness);
}

int MulticastSourceReports::change(const MulticastSourceAggregate& aggregate, unsigned robustness) {
    uint32_t addresses[current_capacity], retained[current_capacity];
    unsigned count = aggregate.sources(addresses, current_capacity);
    unsigned reserved = aggregate.retained_sources(retained, current_capacity);
    return update(aggregate.mode(), addresses, count, retained, reserved, robustness);
}

int MulticastSourceReports::update(unsigned mode, const uint32_t* addresses, unsigned count,
                                   const uint32_t* retained, unsigned retained_count,
                                   unsigned robustness) {
    if (mode > 1 || !valid_robustness(robustness) || (count && !addresses) ||
        (retained_count && !retained))
        return -22;
    if (count > current_capacity || retained_count > current_capacity)
        return -105;
    for (unsigned n = 1; n < count; n++)
        if (addresses[n - 1] >= addresses[n])
            return -22;
    for (unsigned n = 1; n < retained_count; n++)
        if (retained[n - 1] >= retained[n])
            return -22;
    for (unsigned n = 0; n < count; n++)
        if (!contains(retained, retained_count, addresses[n]))
            return -22;
    bool next_include = mode == 1;
    unsigned current = 0, reserved = 0;
    bool difference = include != next_include, reservation_changed = false;
    for (unsigned n = 0; n < used; n++) {
        if (sources[n].listed) {
            difference |= current >= count || sources[n].address != addresses[current];
            current++;
        }
        if (sources[n].reserved) {
            reservation_changed |=
                reserved >= retained_count || sources[n].address != retained[reserved];
            reserved++;
        }
    }
    difference |= current != count;
    reservation_changed |= reserved != retained_count;
    if (!difference && !reservation_changed)
        return 0;

    // Hidden contributor slots are part of admission. Final close then uses
    // only addresses already reserved by the previous aggregate transaction.
    unsigned needed = 0;
    for (unsigned n = 0; n < used; n++) {
        bool listed = contains(addresses, count, sources[n].address);
        bool changed = include == next_include && sources[n].listed != listed;
        needed += contains(retained, retained_count, sources[n].address) || sources[n].remaining ||
                  changed;
    }
    for (unsigned n = 0; n < retained_count; n++) {
        bool present = false;
        for (unsigned old = 0; old < used; old++)
            present |= sources[old].address == retained[n];
        needed += !present;
    }
    if (needed > history_capacity)
        return -105;

    bool same_mode = include == next_include;
    for (unsigned n = 0; n < used; n++) {
        bool listed = contains(addresses, count, sources[n].address);
        if (same_mode && sources[n].listed != listed)
            sources[n].remaining = uint8_t(robustness);
        sources[n].listed = listed;
        sources[n].reserved = contains(retained, retained_count, sources[n].address);
    }
    if (!same_mode)
        mode_remaining = uint8_t(robustness);
    include = next_include;
    compact();
    for (unsigned n = 0; n < retained_count; n++) {
        unsigned at = 0;
        while (at < used && sources[at].address < retained[n])
            at++;
        if (at < used && sources[at].address == retained[n])
            continue;
        for (unsigned next = used; next > at; next--)
            sources[next] = sources[next - 1];
        bool listed = contains(addresses, count, retained[n]);
        sources[at] = {retained[n], uint8_t(same_mode && listed ? robustness : 0), listed, true};
        used++;
    }
    if (difference)
        reset_round();
    return 0;
}

MulticastSourceReports::Source& MulticastSourceReports::find(uint32_t address) {
    // Every pending round address retains a nonzero counter until accepted.
    // Reservations may reorder the table, so a round stores stable addresses.
    unsigned at = 0;
    while (at + 1 < used && sources[at].address != address)
        at++;
    return sources[at];
}

void MulticastSourceReports::cancel() {
    mode_remaining = 0;
    for (unsigned n = 0; n < used; n++)
        sources[n].remaining = 0;
    compact();
    reset_round();
}

int MulticastSourceReports::restart(unsigned robustness) {
    if (!valid_robustness(robustness))
        return -22;
    cancel();
    if (include) {
        for (unsigned n = 0; n < used; n++)
            sources[n].remaining = uint8_t(robustness);
    } else
        mode_remaining = uint8_t(robustness);
    return 0;
}

bool MulticastSourceReports::pending() const {
    if (mode_remaining)
        return true;
    for (unsigned n = 0; n < used; n++)
        if (sources[n].remaining)
            return true;
    return false;
}

bool MulticastSourceReports::transmit(unsigned maximum, Emit emit, void* context) {
    if (!maximum || !emit)
        return false;
    if (maximum > history_capacity)
        maximum = history_capacity;
    if (!pending())
        return true;
    uint32_t addresses[history_capacity];
    if (mode_remaining) {
        unsigned count = 0;
        for (unsigned n = 0; n < used; n++)
            if (sources[n].listed)
                addresses[count++] = sources[n].address;
        for (;;) {
            unsigned remaining = count - cursor;
            unsigned copied = remaining < maximum ? remaining : maximum;
            if (!emit(context, include ? 3 : 4, addresses + cursor, copied))
                return false;
            if (include && cursor + copied < count) {
                cursor += copied;
                continue;
            }
            mode_remaining--;
            // Mode records satisfy one round of every source obligation,
            // including sources suppressed while the mode change is pending.
            for (unsigned n = 0; n < used; n++)
                if (sources[n].remaining)
                    sources[n].remaining--;
            compact();
            reset_round();
            return true;
        }
    }
    if (!active) {
        round_count = 0;
        for (unsigned selected = 0; selected < 2; selected++)
            for (unsigned n = 0; n < used; n++)
                if (sources[n].remaining && forwards(sources[n]) == (selected == 0))
                    round[round_count++] = sources[n].address;
        cursor = 0;
        active = true;
    }
    while (cursor < round_count) {
        bool allowed = forwards(find(round[cursor]));
        unsigned copied = 0;
        while (cursor + copied < round_count && copied < maximum &&
               forwards(find(round[cursor + copied])) == allowed) {
            addresses[copied] = find(round[cursor + copied]).address;
            copied++;
        }
        if (!emit(context, allowed ? 5 : 6, addresses, copied))
            return false;
        for (unsigned n = 0; n < copied; n++)
            find(round[cursor + n]).remaining--;
        cursor += copied;
    }
    compact();
    reset_round();
    return true;
}
} // namespace ax::ip4
