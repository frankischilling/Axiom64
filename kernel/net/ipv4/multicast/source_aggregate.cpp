// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_aggregate.hpp"

namespace ax::ip4 {
namespace {
bool valid(MulticastSourceView view) {
    return !view.present || (view.mode <= 1 && view.count <= MulticastSourceAggregate::capacity &&
                             (!view.count || view.addresses));
}
} // namespace

int MulticastSourceAggregate::apply(MulticastSourceView view, bool add) {
    if (!view.present)
        return 0;
    if (!add && (!owner_count || (!view.mode && !exclude_count) ||
                 (view.mode && owner_count == exclude_count)))
        return -22;
    for (unsigned n = 0; n < view.count; n++) {
        bool duplicate = false;
        for (unsigned prior = 0; prior < n; prior++)
            duplicate |= view.addresses[prior] == view.addresses[n];
        if (duplicate)
            continue;
        unsigned at = 0;
        while (at < used && entries[at].address < view.addresses[n])
            at++;
        if (at == used || entries[at].address != view.addresses[n]) {
            if (!add)
                return -22;
            if (used == capacity)
                return -105;
            for (unsigned next = used; next > at; next--)
                entries[next] = entries[next - 1];
            entries[at] = {view.addresses[n], 0, 0};
            used++;
        }
        auto& references = view.mode ? entries[at].included : entries[at].excluded;
        if (add) {
            if (references == UINT32_MAX)
                return -105;
            references++;
        } else {
            if (!references)
                return -22;
            references--;
            if (!entries[at].included && !entries[at].excluded) {
                for (unsigned next = at + 1; next < used; next++)
                    entries[next - 1] = entries[next];
                entries[--used] = {};
            }
        }
    }
    if (add) {
        if (owner_count == UINT32_MAX)
            return -105;
        owner_count++;
        exclude_count += !view.mode;
    } else {
        owner_count--;
        exclude_count -= !view.mode;
    }
    return 0;
}

int MulticastSourceAggregate::update(MulticastSourceView before, MulticastSourceView after) {
    if (!valid(before) || !valid(after))
        return -22;
    auto candidate = *this;
    if (int error = candidate.apply(before, false))
        return error;
    if (int error = candidate.apply(after, true))
        return error;
    *this = candidate;
    return 0;
}

bool MulticastSourceAggregate::effective(const Source& source) const {
    return exclude_count ? source.excluded == exclude_count && !source.included
                         : source.included != 0;
}

bool MulticastSourceAggregate::accepts(uint32_t source) const {
    if (!owner_count)
        return false;
    for (unsigned n = 0; n < used; n++)
        if (entries[n].address == source)
            return exclude_count ? !effective(entries[n]) : effective(entries[n]);
    return exclude_count != 0;
}

unsigned MulticastSourceAggregate::sources(uint32_t* output, unsigned available) const {
    unsigned count = 0;
    for (unsigned n = 0; n < used; n++)
        if (effective(entries[n])) {
            if (count < available)
                output[count] = entries[n].address;
            count++;
        }
    return count;
}

unsigned MulticastSourceAggregate::retained_sources(uint32_t* output, unsigned available) const {
    for (unsigned n = 0; n < used && n < available; n++)
        output[n] = entries[n].address;
    return used;
}
} // namespace ax::ip4
